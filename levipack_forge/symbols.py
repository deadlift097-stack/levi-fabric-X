"""Bedrock symbol index built from libminecraftpe.so (or a zip containing it).

The mangled-name regex works on stripped and even truncated binaries, so the
index is usable with partial uploads. Hints are heuristic: Java (Yarn/Mojang)
names do not always equal Bedrock's C++ names.
"""
from __future__ import annotations
import json, re, struct, zlib, pathlib

DATA = pathlib.Path(__file__).parent / "data"

_SYM = re.compile(rb"_ZN[0-9A-Za-z_]{6,400}")


def rescue_zip(path, member_suffix=".so"):
    """Yield (name, bytes, complete) for members of a possibly truncated zip."""
    d = pathlib.Path(path).read_bytes()
    i = 0
    while True:
        i = d.find(b"PK\x03\x04", i)
        if i < 0:
            return
        _, flag, comp, _, _, _, cs, us, nl, el = struct.unpack("<HHHHHIIIHH", d[i + 4:i + 30])
        name = d[i + 30:i + 30 + nl].decode("utf-8", "replace")
        start = i + 30 + nl + el
        if comp == 0:
            yield name, d[start:start + us], True
            i = start + us
            continue
        dec = zlib.decompressobj(-15)
        out = b""; pos = start; ok = True
        while pos < len(d) and not dec.eof:
            try:
                out += dec.decompress(d[pos:pos + (1 << 20)])
            except zlib.error:
                ok = False; break
            pos += 1 << 20
        yield name, out, ok and dec.eof
        i = start + max(cs, 1) if cs < len(d) else len(d)
        if not dec.eof:
            return


def build_index(path):
    p = pathlib.Path(path)
    blobs = []
    if p.suffix == ".zip":
        for name, data, _ in rescue_zip(p):
            if name.endswith(".so"):
                blobs.append((name, data))
    else:
        blobs.append((p.name, p.read_bytes()))
    syms = set()
    for name, data in blobs:
        if "minecraftpe" not in name and len(blobs) > 1:
            continue
        syms.update(m.group().decode() for m in _SYM.finditer(data))
    return sorted(syms)


class SymbolDB:
    """Build-keyed table of verified vtable slots (see tools/make_symbols_db.py and docs/ANDROID_HOOKING.md).

    status "static"   instruction evidence from the exact binary + `expect` words: the only status code may hook on
    status "reported" listed by the hooking guide without instruction evidence: hint only
    candidates       shape-alignment guesses: shown as hints, never hooked
    """

    def __init__(self, d):
        self.d = d
        self.sha256 = d.get("sha256", "")
        self.functions = d.get("functions", {})
        self.candidates = {c["name"]: c for c in d.get("candidates", [])}
        self.vtables = d.get("vtables", {})
        self.java_aliases = d.get("java_aliases", {})
        self.java_classes = d.get("java_classes", {})

    @classmethod
    def load(cls, path=None):
        """`path` = a *.symbols.json; None = the database bundled with levipack-forge (empty DB if none)."""
        if path is None:
            found = sorted(DATA.glob("*.symbols.json"))
            return cls(json.loads(found[0].read_text(encoding="utf-8"))) if found else cls({})
        return cls(json.loads(pathlib.Path(path).read_text(encoding="utf-8")))

    @property
    def tag(self):
        return self.sha256[:8] or "unknown-build"

    def vptr_rva(self, vtable, n=0):
        e = self.vtables.get(vtable) or []
        return int(e[n]["rva"], 16) if len(e) > n else None

    def overrides_for(self, name):
        """Subclass vtables that override this function's slot (recorded by `so_probe.py --subclasses`), de-duplicated by
        target. Empty when the build was not analysed for subclasses."""
        f = self.functions.get(name)
        if not f:
            return []
        seen, out = set(), []
        for sc in self.d.get("subclasses", {}).get(f["vtable"], []):
            o = (sc.get("overrides") or {}).get(str(f["index"]))
            if o and o["target_rva"] not in seen:
                seen.add(o["target_rva"])
                out.append({"class": sc["class"], "vptr_rva": sc["vptr_rva"], **o})
        return out

    def subclasses_analysed(self, vtable):
        return vtable in self.d.get("subclasses", {})

    def usable(self, name):
        f = self.functions.get(name)
        return bool(f and f.get("status") == "static" and f.get("expect") and f.get("kind") == "virtual"
                    and self.vptr_rva(f["vtable"]) is not None)

    def lookup_java(self, java_cls, method):
        """Names of Bedrock functions a Java call most plausibly corresponds to (hints, not proof)."""
        simple = java_cls.rsplit(".", 1)[-1].rsplit("$", 1)[0]
        hit = self.java_aliases.get(f"{simple}.{method}")
        if hit:
            return [hit]
        bcls = self.java_classes.get(simple)
        name = f"{bcls}::{method}" if bcls else ""
        return [name] if name in self.functions or name in self.candidates else []

    def describe(self, name):
        f = self.functions.get(name)
        if f:
            tail = "; ".join(x for x in (f.get("evidence"), f.get("source")) if x)
            return f"{name} = {f['vtable']} vtable slot {f['index']} [{f['status']}, build {self.tag}: {tail}]"
        c = self.candidates.get(name)
        if c:
            return (f"{name} ~ {c['vtable']} vtable slot {c['index']} [candidate/{c['confidence']}, build {self.tag}: "
                    f"shape alignment only - confirm with a test hook]")
        return name


class SymbolIndex:
    """Mangled-name list (from a .so/.zip/.txt) plus the build-keyed vtable DB."""

    def __init__(self, symbols, db=None):
        self.symbols = list(symbols)
        self.db = db if db is not None else SymbolDB.load()

    @classmethod
    def load(cls, path=None):
        if path is None:
            return cls([])
        p = pathlib.Path(path)
        if p.suffix == ".json":
            return cls([], SymbolDB.load(p))
        if p.suffix in (".zip", ".so"):
            return cls(build_index(p))
        return cls(l.strip() for l in p.read_text().splitlines() if l.strip())

    def search(self, *needles, limit=8):
        keys = [f"{len(n)}{n}" for n in needles if n]
        out = [s for s in self.symbols if all(k in s for k in keys)]
        return out[:limit]

    @staticmethod
    def _call(what: str):
        # "unsupported call net.minecraft.entity.player.PlayerEntity.jump()V"
        m = re.search(r"call ([\w.$]+)\.(\w+)\(", what)
        return (m.group(1), m.group(2)) if m else (None, None)

    def hints_for(self, what: str):
        owner, meth = self._call(what)
        if not owner:
            return []
        out = self.search(owner.rsplit(".", 1)[-1], meth, limit=3)
        out += [self.db.describe(n) for n in self.db.lookup_java(owner, meth)]
        return out

    def targets_for(self, what: str):
        """Bedrock functions with static evidence (safe to resolve + guard at runtime) for a Java call."""
        owner, meth = self._call(what)
        if not owner:
            return []
        return [n for n in self.db.lookup_java(owner, meth) if self.db.usable(n)]
