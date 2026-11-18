"""Bytecode -> C++ for the supported subset (straight-line code).

Anything outside the subset is NEVER silently dropped: it becomes a
`// TODO(levipack-forge)` comment in the C++ and an entry in the report.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from . import classfile as C
from .solutions import advise, is_game_owner

LOG_LEVELS = {"trace": "debug", "debug": "debug", "info": "info", "warn": "warn", "error": "error"}
LOGGER_OWNERS = {"org/slf4j/Logger", "org/apache/logging/log4j/Logger"}
# Fabric lifecycle events that map onto the Levi mod lifecycle.
ENABLE_EVENTS = {"SERVER_STARTING", "SERVER_STARTED", "CLIENT_STARTED"}
DISABLE_EVENTS = {"SERVER_STOPPING", "SERVER_STOPPED", "CLIENT_STOPPING"}
LIFECYCLE_OWNER_HINTS = ("ServerLifecycleEvents", "ClientLifecycleEvents")


@dataclass
class Result:
    enable: list = field(default_factory=list)
    disable: list = field(default_factory=list)
    issues: list = field(default_factory=list)      # dicts: {where, what, kind, category, fix}
    resolved: list = field(default_factory=list)    # dicts: {where, what, how}  (handled automatically)
    converted: int = 0
    stubbed: int = 0


BRANCH_OPS = {153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
              166, 167, 168, 170, 171, 198, 199, 200, 201, 191, 169}
NOHANDLE = object()
FABRIC_LOADER = "net/fabricmc/loader/api/"


def cstr(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\": out.append("\\\\")
        elif ch == '"': out.append('\\"')
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif o < 32 or o == 127: out.append(f"\\x{o:02x}\"\"")
        else: out.append(ch)
    return '"' + "".join(out) + '"'


def fmt_value(v):
    k = v[0]
    if k == "str": return cstr(v[1])
    if k == "int": return str(v[1])
    if k == "long": return f"{v[1]}LL"
    if k == "float": return f"{v[1]!r}f"
    if k == "double": return repr(v[1])
    if k == "null": return "nullptr"
    return None


class Transpiler:
    def __init__(self, classes: dict[str, C.ClassFile], symbols=None, cfg_fields=None, meta=None,
                 overrides=None, mod_id=None, cmd_classes=None, commands=None):
        self.cmd_classes = cmd_classes or set()
        self.commands = commands or []
        self.classes = classes
        self.meta = meta or {}
        self.mod_id = mod_id or self.meta.get("id", "")
        self.ov = (overrides or {}).get("calls", {})
        self.used_overrides = set()
        self._touch_cache = {}
        self._ret = None
        self.symbols = symbols      # SymbolIndex or None
        self.cfg_fields = cfg_fields or {}   # (owner, name) -> cpp config member
        self.res = Result()

    # ------------------------------------------------------------------ API
    def entry(self, cls_name: str, method_name: str, section: str):
        cf = self.classes.get(cls_name)
        if not cf:
            self.res.issues.append({"where": cls_name, "what": "entrypoint class not found in jar"})
            return
        m = cf.find_method(method_name)
        if not m or m.code is None:
            self.res.issues.append({"where": f"{cls_name}.{method_name}", "what": "entrypoint method not found"})
            return
        lines = self._method(cf, m, depth=0)
        getattr(self.res, section).extend(lines)

    # ------------------------------------------------------------- internals
    def _resolved(self, where, what, how):
        item = {"where": where, "what": what, "how": how}
        if item not in self.res.resolved:
            self.res.resolved.append(item)

    def _todo(self, where, what, lines, kind="manual", owner=None):
        """kind: 'gap' = needs a native game hook, 'manual' = plain logic to port, 'syntax' = unsupported bytecode."""
        game = kind == "gap"
        cat, fix = advise(what, game=game) if kind != "syntax" else (
            "Bytecode outside subset",
            "Extend the transpiler (docs/EXTENDING.md) or implement the equivalent in generated native C++.")
        item = {"where": where, "what": what, "kind": kind, "category": cat, "fix": fix,
                "key": owner or ""}
        if item not in self.res.issues:
            self.res.issues.append(item)
            self.res.stubbed += 1
        tag = "GAP" if game else "TODO"
        lines.append(f"// {tag}(levipack-forge): {what}")
        if self.symbols is not None:
            for h in self.symbols.hints_for(what):
                lines.append(f"//   bedrock symbol candidate: {h}")

    def _method(self, cf, m, depth, args=None):
        where = f"{cf.name}.{m.name}{m.desc}"
        lines: list[str] = []
        if depth > 6:
            self._todo(where, "recursion limit while inlining lambdas", lines)
            return lines
        insns = C.decode(m.code)
        ret_val = None
        cut = next((k for k, i in enumerate(insns) if i.op in BRANCH_OPS), None)
        tail_todo = cut is not None
        if tail_todo:
            insns = insns[:cut]
        stack: list = []
        locals_: dict = {}
        if args:
            locals_.update(args)
        for ins in insns:
            op, a = ins.op, ins.arg
            if op == 0: continue
            elif op == 1: stack.append(("null",))
            elif 2 <= op <= 8: stack.append(("int", op - 3))
            elif op in (9, 10): stack.append(("long", op - 9))
            elif 11 <= op <= 13: stack.append(("float", float(op - 11)))
            elif op in (14, 15): stack.append(("double", float(op - 14)))
            elif op in (16, 17): stack.append(("int", a))
            elif op in (18, 19, 20):
                v = cf.const(a); stack.append(v if isinstance(v, tuple) else ("str", v))
            elif 26 <= op <= 45 or 21 <= op <= 25:
                if 21 <= op <= 25: idx = a
                else: idx = (op - 26) % 4
                stack.append(locals_.get(idx, ("this",) if idx == 0 else ("unknown",)))
            elif 54 <= op <= 58:
                locals_[a] = stack.pop()
            elif 59 <= op <= 78:
                locals_[(op - 59) % 4] = stack.pop()
            elif op == 87: stack.pop()
            elif op == 89: stack.append(stack[-1])
            elif op in (172, 173, 174, 175, 176):
                ret_val = stack.pop() if stack else None
                break
            elif op == 177: break
            elif op == 178:
                o, n, d = cf.ref(a)
                stack.append(("static", o, n, d))
            elif op == 179:
                o, n, d = cf.ref(a); v = stack.pop()
                if (o, n) in self.cfg_fields: continue   # handled as typed config default
                if v[0] == "logger":
                    continue
                if o in self.classes and fmt_value(v) is not None:
                    lines.append(f"// static {o.replace('/', '.')}.{n} = {fmt_value(v)} (compat flag, no native state)")
                    continue
                self._todo(where, f"putstatic {o}.{n} with non-constant value", lines)
            elif op == 180:
                stack.pop(); stack.append(("unknown",))
            elif op == 181:
                stack.pop(); stack.pop()
                self._todo(where, "putfield (instance state) not supported", lines)
            elif op == 187: stack.append(("new", cf.cls(a)))
            elif op == 192: pass
            elif op in (182, 183, 184, 185):
                o, n, d = cf.ref(a)
                params, ret = C.arg_slots(d)
                call_args = [stack.pop() for _ in params][::-1]
                recv = None if op == 184 else stack.pop()
                out = self._call(cf, where, op, o, n, d, recv, call_args, depth, lines)
                if ret != "V":
                    stack.append(out if out else ("unknown",))
            elif op == 186:
                bsm, n, d = cf.invokedynamic(a)
                params, ret = C.arg_slots(d)
                cap = [stack.pop() for _ in params][::-1]
                target = self._lambda_target(cf, bsm)
                stack.append(("lambda", target, cap))
            else:
                self._todo(where, f"opcode 0x{op:02x} (arithmetic/array/etc.) outside supported subset", lines, kind="syntax")
                self._ret = None
                return lines
        if tail_todo:
            self._todo(where, "code after the first branch/loop/try is outside the supported subset; "
                              "port the rest of this method by hand (the part above was converted)", lines, kind="syntax")
        else:
            self.res.converted += 1
        self._ret = None if tail_todo else ret_val
        return lines

    def _lambda_target(self, cf, bsm_index):
        mh, bargs = cf.bootstraps[bsm_index]
        for b in bargs:
            if cf.cp[b][0] == "mh":
                kind, (o, n, d) = cf.method_handle(b)
                return (o, n, d)
        return None

    # ------------------------------------------------------------ call routing
    def _call(self, cf, where, op, o, n, d, recv, args, depth, lines):
        # constructors / trivial plumbing
        if n == "<init>" and o in ("java/lang/Object",):
            return None
        if n == "getLogger" and ("LoggerFactory" in o or "LogManager" in o):
            return ("logger",)
        # autoboxing / unboxing is a no-op in C++
        if op == 184 and n == "valueOf" and o in ("java/lang/Integer", "java/lang/Boolean", "java/lang/Long",
                                                  "java/lang/Double", "java/lang/Float", "java/lang/Short", "java/lang/Byte") and args:
            return args[0]
        # logging
        if (o in LOGGER_OWNERS or (recv and recv[0] == "logger")) and n in LOG_LEVELS:
            return self._log(where, n, args, lines)
        if o == "java/io/PrintStream" and n in ("println", "print") and recv and recv[:3] == ("static", "java/lang/System", "out"):
            return self._log(where, "info", args[:1], lines)
        # Fabric lifecycle events
        if n == "register" and recv and recv[0] == "static" and any(h in recv[1] for h in LIFECYCLE_OWNER_HINTS):
            return self._lifecycle(where, recv, args, depth, lines)
        # 1) optional internal transpiler mappings
        r = self._override(where, o, n, d, recv, args, lines)
        if r is not NOHANDLE:
            return r
        # 2) Fabric Loader / metadata / Optional: answered from fabric.mod.json at convert time
        r = self._fabric(where, o, n, d, recv, args, depth, lines)
        if r is not NOHANDLE:
            return r
        # 3) APIs with no Bedrock equivalent that are safe to drop (and are reported as such)
        r = self._tokens(where, o, n, args)
        if r is not NOHANDLE:
            return r
        r = self._by_design(where, o, n, recv)
        if r is not NOHANDLE:
            return r
        # 3b) Brigadier command registration: the commands become launcher config fields
        if o in self.cmd_classes and n == "register":
            self._resolved(where, f"{o.replace('/', '.')}.{n}",
                           f"{len(self.commands)} client commands exposed as `cmd_*` launcher config fields "
                           "(values are stored; a native hook must apply them)")
            return None
        # 4) helper code that lives inside the jar and never touches the game: inline it
        r = self._inline(where, op, o, n, d, recv, args, depth, lines)
        if r is not NOHANDLE:
            return r
        # 5) everything else: stub + advice + symbol hints
        text = f"unsupported call {o.replace('/', '.')}.{n}{d}"
        game = is_game_owner(o) or (o in self.classes and bool(self._touches_game(o, n, d)))
        self._todo(where, text, lines, kind="gap" if game else "manual", owner=f"{o.replace('/', '.')}.{n}")
        return None

    def _lifecycle(self, where, recv, args, depth, lines):
        ev = recv[2]
        sect = "enable" if ev in ENABLE_EVENTS else "disable" if ev in DISABLE_EVENTS else None
        lam = args[0] if args else None
        if sect and lam and lam[0] == "lambda" and lam[1]:
            lo, ln_, ld = lam[1]
            tcf = self.classes.get(lo)
            tm = tcf.find_method(ln_, ld) if tcf else None
            if tm and tm.code is not None:
                body = self._method(tcf, tm, depth + 1)
                lines.append(f"// Fabric {recv[1].rsplit('/',1)[-1]}.{ev} -> LeviLauncher {sect}()")
                if sect == "enable":
                    lines.extend(body)
                else:
                    self.res.disable.extend(body)
                return None
        self._todo(where, f"{recv[1]}.{ev}.register(...) callback could not be resolved", lines, kind="gap")
        return None

    # -------------------------------------------------------------- overrides
    def _override(self, where, o, n, d, recv, args, lines):
        base = f"{o.replace('/', '.')}.{n}"
        key = base + d if base + d in self.ov else base
        spec = self.ov.get(key)
        if spec is None:
            return NOHANDLE
        self.used_overrides.add(key)
        reason = spec.get("reason", "internal mapping")
        if "cpp" in spec:
            code = spec["cpp"] if isinstance(spec["cpp"], list) else str(spec["cpp"]).split("\n")
            for i, a in enumerate(args):
                fv = fmt_value(a)
                code = [c.replace("{%d}" % i, fv if fv is not None else "/*runtime*/0") for c in code]
            lines.append(f"// override {key}: {reason}")
            lines.extend(code)
            self._resolved(where, base, f"C++ supplied in internal mapping ({reason})")
        elif spec.get("ignore"):
            lines.append(f"// ignored by internal mapping: {base} ({reason})")
            self._resolved(where, base, f"ignored on purpose ({reason})")
        else:
            self._resolved(where, base, f"return value fixed by internal mapping ({reason})")
        ret = spec.get("returns")
        if isinstance(ret, dict) and ret:
            k, v = next(iter(ret.items()))
            return {"bool": ("int", 1 if v else 0), "int": ("int", int(v)), "long": ("long", int(v)),
                    "double": ("double", float(v)), "str": ("str", str(v))}.get(k, None)
        return None

    # ----------------------------------------------- Fabric Loader / Optional
    def _fabric(self, where, o, n, d, recv, args, depth, lines):
        """Fabric Loader has no runtime on Bedrock, but every answer it gives about *this* mod is already
        known at convert time (fabric.mod.json). Fold those calls into constants."""
        me = self.mod_id
        pretty = f"{o.replace('/', '.')}.{n}"
        if o == FABRIC_LOADER + "FabricLoader":
            if n == "getInstance":
                return ("loader",)
            if n == "isModLoaded" and args and args[0][0] == "str":
                v = 1 if args[0][1] in (me, "minecraft") else 0
                self._resolved(where, pretty, f"folded to {'true' if v else 'false'}: "
                               f"'{args[0][1]}' {'is this mod' if v else 'cannot be loaded next to a native Bedrock mod'}")
                return ("int", v)
            if n == "getModContainer" and args and args[0][0] == "str":
                mid = args[0][1]
                self._resolved(where, pretty, f"answered from fabric.mod.json ('{mid}' "
                               f"{'is this mod' if mid == me else 'is absent'})")
                return ("opt", ("container", mid) if mid == me else None)
            if n == "isDevelopmentEnvironment":
                self._resolved(where, pretty, "folded to false (shipped build)")
                return ("int", 0)
            if n in ("getConfigDir", "getGameDir"):
                return ("cpp", "self.getConfigDir()")
            return NOHANDLE
        if o == "java/util/Optional" and recv and recv[0] == "opt":
            inner = recv[1]
            if n in ("orElseThrow", "get"):
                if inner is None:
                    self._todo(where, "Optional.get/orElseThrow on a value that is absent on Bedrock", lines, kind="manual")
                    return None
                self._resolved(where, pretty, "unwrapped at convert time")
                return inner
            if n == "isPresent":
                return ("int", 0 if inner is None else 1)
            if n == "isEmpty":
                return ("int", 1 if inner is None else 0)
            if n == "orElse" and args:
                return inner if inner is not None else args[0]
            if n == "ifPresent" and args:
                if inner is None:
                    self._resolved(where, pretty, "dropped: value is absent on Bedrock (callback never runs)")
                    return None
                lam = args[0]
                if lam[0] == "lambda" and lam[1]:
                    lo, ln_, ld = lam[1]
                    tcf = self.classes.get(lo); tm = tcf.find_method(ln_, ld) if tcf else None
                    if tm and tm.code is not None:
                        locs = self._bind(tm, list(lam[2]) + [inner])
                        lines.extend(self._method(tcf, tm, depth + 1, locs))
                        self._resolved(where, pretty, "callback inlined")
                        return None
            return NOHANDLE
        if o == FABRIC_LOADER + "ModContainer" and n == "getMetadata" and recv and recv[0] == "container":
            return ("meta", recv[1])
        if o == FABRIC_LOADER + "metadata/ModMetadata" and recv and recv[0] == "meta" and recv[1] == me:
            table = {"getId": me, "getName": self.meta.get("name"), "getDescription": self.meta.get("description")}
            if n in table and table[n] is not None:
                self._resolved(where, pretty, "answered from fabric.mod.json")
                return ("str", table[n])
            if n == "getVersion":
                return ("ver", me)
            return NOHANDLE
        if o == FABRIC_LOADER + "Version" and recv and recv[0] == "ver" and n in ("getFriendlyString", "toString"):
            self._resolved(where, pretty, "answered from fabric.mod.json")
            return ("str", self.meta.get("version", "0.0.0"))
        return NOHANDLE

    def _tokens(self, where, o, n, args):
        """Pure value helpers: a text component / resource id is just a string for our purposes."""
        pretty = f"{o.replace('/', '.')}.{n}"
        if o == "net/minecraft/network/chat/Component" and n == "literal" and args and args[0][0] == "str":
            self._resolved(where, pretty, "text component -> plain string")
            return args[0]
        if o in ("net/minecraft/resources/Identifier", "net/minecraft/resources/ResourceLocation") \
                and n == "fromNamespaceAndPath" and len(args) == 2 and args[0][0] == "str" and args[1][0] == "str":
            self._resolved(where, pretty, "resource id -> 'namespace:path' string")
            return ("str", f"{args[0][1]}:{args[1][1]}")
        return NOHANDLE

    def _by_design(self, where, o, n, recv):
        if o.endswith("resource/ResourceManagerHelper"):
            self._resolved(where, f"{o.replace('/', '.')}.{n}",
                           "no Bedrock equivalent: resources ship inside the pack, nothing reloads Java listeners")
            return ("rmh",) if n == "get" else None
        return NOHANDLE

    # ------------------------------------------------------ inlining in-jar code
    def _bind(self, tm, values):
        """Map call values onto local-variable slots of method `tm` (long/double take 2 slots)."""
        static = bool(tm.access & 0x0008)
        params, _ = C.arg_slots(tm.desc)
        locs, slot, vals = {}, 0, list(values)
        if not static and vals:
            locs[0] = vals.pop(0); slot = 1
        for p, v in zip(params, vals):
            locs[slot] = v
            slot += 2 if p in ("J", "D") else 1
        return locs

    def _touches_game(self, o, n, d, _seen=None):
        """Return the set of game/Fabric-API classes reachable from a jar method (transitively)."""
        key = (o, n, d)
        if key in self._touch_cache:
            return self._touch_cache[key]
        seen = _seen if _seen is not None else set()
        if key in seen:
            return set()
        seen.add(key)
        cf = self.classes.get(o)
        out = set()
        if cf:
            ms = [m for m in cf.methods if m.name == n and (not d or m.desc == d) and m.code]
            for m in ms:
                if "Lnet/minecraft/" in m.desc or "Lcom/mojang/" in m.desc:
                    out.add("method signature uses game types")
                for i in C.decode(m.code):
                    if i.op in (178, 179, 180, 181, 182, 183, 184, 185):
                        ro, rn, rd = cf.ref(i.arg)
                        if is_game_owner(ro):
                            out.add(ro.replace("/", "."))
                        elif ro in self.classes and i.op in (182, 183, 184, 185):
                            out |= self._touches_game(ro, rn, rd, seen)
                    elif i.op == 187 and is_game_owner(cf.cls(i.arg)):
                        out.add(cf.cls(i.arg).replace("/", "."))
                    elif i.op == 186:
                        bsm, _, _ = cf.invokedynamic(i.arg)
                        t = self._lambda_target(cf, bsm)
                        if t and t[0] in self.classes:
                            out |= self._touches_game(t[0], t[1], t[2], seen)
        if _seen is None:
            self._touch_cache[key] = out
        return out

    def _inline(self, where, op, o, n, d, recv, args, depth, lines):
        tcf = self.classes.get(o)
        if not tcf:
            return NOHANDLE
        # `new InJarClass(...)`: no per-object state is modelled; the object is only a token
        if n == "<init>":
            self._resolved(where, f"new {o.replace('/', '.')}", "object token only (no native state needed)")
            return None
        tm = tcf.find_method(n, d)
        if not tm or tm.code is None or depth > 5:
            return NOHANDLE
        if self._touches_game(o, n, d):
            return NOHANDLE                      # game-bound: reported as a GAP by the caller
        insns = C.decode(tm.code)
        if any(i.op in BRANCH_OPS for i in insns):
            return NOHANDLE                      # real logic: reported as manual
        params, ret = C.arg_slots(d)
        vals = ([recv] if op != 184 else []) + list(args)
        body = self._method(tcf, tm, depth + 1, self._bind(tm, vals))
        lines.extend(body)
        self._resolved(where, f"{o.replace('/', '.')}.{n}", "plain Java helper without game calls: inlined")
        return self._ret if ret != "V" else None

    def _log(self, where, level, args, lines):
        if not args:
            return None
        fmtv = args[0]
        if fmtv[0] != "str":
            self._todo(where, "logger call with non-constant message", lines)
            return None
        parts = [cstr(fmtv[1])]
        for v in args[1:]:
            f = fmt_value(v)
            if f is None and v[0] == "static" and (v[1], v[2]) in self.cfg_fields:
                f = f"mConfig.{self.cfg_fields[(v[1], v[2])]}"
            parts.append(f if f is not None else '"<runtime value>"')
        lines.append(f"self.getLogger().{LOG_LEVELS[level]}({', '.join(parts)});")
        return None
