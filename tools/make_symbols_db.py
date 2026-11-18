#!/usr/bin/env python3
"""make_symbols_db.py - build levipack_forge/data/<name>.symbols.json for ONE libminecraftpe.so build.

Inputs (all produced by so_probe.py / read from the Amethyst headers, see symbols/source/):
  symbols.json          vtable RVAs + the hand-verified Item slots   (so_probe.py output, annotated)
  vtables_dump.txt      every slot with its first instructions        (so_probe.py --dump style)
  amethyst-learnings.txt  MSVC vtable indices + signatures (MC 1.21.0.3)

Output keeps three confidence levels apart so generated code can never trust a guess:
  functions   status "static"   : instruction evidence read from THIS binary + `expect` words (used for guards)
              status "reported" : claimed by the hooking guide without instruction evidence (never hooked)
  candidates  status "candidate": shape-alignment guess (tools/align_vtable.py), never hooked
Nothing here is live-tested. The first on-device test is still outstanding (see docs/ANDROID_HOOKING.md).

usage: python3 tools/make_symbols_db.py [--out levipack_forge/data/libminecraftpe.4de40e1d.symbols.json]
"""
from __future__ import annotations
import argparse, json, pathlib, re, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import align_vtable as AV                                   # noqa: E402

SRC = HERE.parent / "symbols" / "source"
GUIDE, FORGE = "android-hooking-guide", "forge-analysis"

# name -> (msvc, android, source, evidence, instructions that start the function)
STATIC = {
    "Item::getDescriptionId":  (4, 5, GUIDE, "add x0,x0,#0x90 ; ret (returns member @0x90)", ["add x0, x0, #0x90", "ret"]),
    "Item::getMaxUseDuration": (5, 6, GUIDE, "ldr w0,[x0,#0x114] ; ret", ["ldr w0, [x0, #0x114]", "ret"]),
    "Item::setMaxDamage":      (24, 27, GUIDE, "strh w1,[x0,#0x110] ; ret", ["strh w1, [x0, #0x110]", "ret"]),
    "Item::setMaxUseDuration": (25, 28, FORGE, "str w1,[x0,#0x114] ; ret (sibling of setMaxDamage, same field as getMaxUseDuration)",
                                ["str w1, [x0, #0x114]", "ret"]),
    "Item::canBeDepleted":     (30, 33, GUIDE, "reads short@0x110 > 0 and flag@0x112 bit 2",
                                ["ldrb w8, [x0, #0x112]", "ldrsh w9, [x0, #0x110]"]),
    "Item::getMaxDamage":      (34, 37, GUIDE, "ldrh w0,[x0,#0x110] ; ret", ["ldrh w0, [x0, #0x110]", "ret"]),
    "Item::getAttackDamage":   (35, 38, GUIDE, "mov w0,wzr ; ret (int, default 0); sits between getMaxDamage and the float-0 getter",
                                ["mov w0, wzr", "ret"]),
    "Item::getAttackDamageBonus": (36, 39, GUIDE, "movi d0,#0 ; ret (float, default 0)", ["movi d0, #0", "ret"]),
    "Item::isHandEquipped":    (37, 40, GUIDE, "ldrb [x0,#0x112] ; ubfx #1 ; ret", ["ldrb w8, [x0, #0x112]", "ubfx w0, w8, #1, #1", "ret"]),
    "Item::getDamageChance":   (57, 69, FORGE, "100/(n+1): mov w8,#0x64 ; add w9,w1,#1 ; sdiv w0,w8,w9",
                                ["mov w8, #0x64", "add w9, w1, #1", "sdiv w0, w8, w9"]),
    "Item::buildIdAux":        (70, 80, FORGE, "(itemId<<16)|aux: ldrh w8,[x0,#0x8a] ; sxth w9,w1 ; orr w0,w9,w8,lsl #16",
                                ["ldrh w8, [x0, #0x8a]", "sxth w9, w1", "orr w0, w9, w8, lsl #16"]),
}
# C++ view of each static function as a free function on AArch64 (this = first argument). `void*` stands for
# references/pointers to game types (Item&, const std::string&, const ItemStack*, const Actor&, ...).
CPP_SIG = {
    "Item::getDescriptionId": ("void *", []), "Item::getMaxUseDuration": ("int", ["void *"]),
    "Item::setMaxDamage": ("void *", ["int"]), "Item::setMaxUseDuration": ("void *", ["int"]),
    "Item::canBeDepleted": ("bool", []), "Item::getMaxDamage": ("short", []), "Item::getAttackDamage": ("int", []),
    "Item::getAttackDamageBonus": ("float", ["void *", "float"]), "Item::isHandEquipped": ("bool", []),
    "Item::getDamageChance": ("int", ["int"]), "Item::buildIdAux": ("int", ["short", "void *"]),
}
REPORTED = {   # the guide lists these as verified but gives no instruction evidence beyond "large function"
    "Item::initServer": (1, 2), "Item::setDescriptionId": (3, 4),
}
OFFSETS = {
    "Item::maxDamage": ("0x110", "int16", "strh/ldrh in setMaxDamage/getMaxDamage"),
    "Item::flags": ("0x112", "uint8", "bit1 = hand equipped, bit2 = damageable flag (canBeDepleted)"),
    "Item::maxUseDuration": ("0x114", "int32", "ldr/str in getMaxUseDuration/setMaxUseDuration"),
    "Item::id": ("0x8a", "int16", "ldrh in buildIdAux"),
    "Item::descriptionId": ("0x90", "std::string (libc++, 24 bytes)", "returned by getDescriptionId"),
}
# Java (Mojang/Yarn) call -> Bedrock function. Hints only; keep the list short and obviously right.
JAVA_ALIASES = {
    "Item.getMaxDamage": "Item::getMaxDamage", "ItemStack.getMaxDamage": "Item::getMaxDamage",
    "Item.getUseDuration": "Item::getMaxUseDuration", "Item.getMaxUseTime": "Item::getMaxUseDuration",
    "Item.isDamageable": "Item::canBeDepleted", "Item.getDescriptionId": "Item::getDescriptionId",
    "Item.getTranslationKey": "Item::getDescriptionId",
}
JAVA_CLASSES = {c: "Item" for c in ("Item", "ItemStack", "SwordItem", "TieredItem", "DiggerItem", "ToolItem", "ArmorItem")}


# ----- tiny ARM64 encoder: only the forms used above. Cross-checked with capstone in the tests.
def _r(t):                       # w8 / x0 / wzr / xzr / sp
    t = t.strip()
    if t in ("wzr", "xzr"):
        return 31
    return int(t[1:])


def encode(text: str) -> int:
    t = re.sub(r"\s+", " ", text.strip().lower())
    if t == "ret":
        return 0xD65F03C0
    if t == "mov w0, wzr":
        return 0x2A1F03E0
    if t in ("movi d0, #0", "movi d0, #0000000000000000"):
        return 0x2F00E400
    m = re.fullmatch(r"(ldr|str|ldrb|strb|ldrh|strh|ldrsh) ([wx]\d+), \[(x\d+), #(0x[0-9a-f]+|\d+)\]", t)
    if m:
        op, rt, rn, imm = m.group(1), _r(m.group(2)), _r(m.group(3)), int(m.group(4), 0)
        base, scale = {"strb": (0x39000000, 0), "ldrb": (0x39400000, 0), "strh": (0x79000000, 1), "ldrh": (0x79400000, 1),
                       "ldrsh": (0x79C00000, 1), "str": (0xB9000000, 2), "ldr": (0xB9400000, 2)}[op]
        if m.group(2)[0] == "x":
            raise ValueError("64-bit ldr/str not needed: " + text)
        assert imm % (1 << scale) == 0 and imm >> scale < 4096, text
        return base | ((imm >> scale) << 10) | (rn << 5) | rt
    m = re.fullmatch(r"add ([wx]\d+), ([wx]\d+), #(0x[0-9a-f]+|\d+)", t)
    if m:
        base = 0x91000000 if m.group(1)[0] == "x" else 0x11000000
        return base | (int(m.group(3), 0) << 10) | (_r(m.group(2)) << 5) | _r(m.group(1))
    m = re.fullmatch(r"mov (w\d+), #(0x[0-9a-f]+|\d+)", t)
    if m:
        return 0x52800000 | (int(m.group(2), 0) << 5) | _r(m.group(1))
    m = re.fullmatch(r"sdiv (w\d+), (w\d+), (w\d+)", t)
    if m:
        return 0x1AC00C00 | (_r(m.group(3)) << 16) | (_r(m.group(2)) << 5) | _r(m.group(1))
    m = re.fullmatch(r"sxth (w\d+), (w\d+)", t)
    if m:
        return 0x13003C00 | (_r(m.group(2)) << 5) | _r(m.group(1))
    m = re.fullmatch(r"ubfx (w\d+), (w\d+), #(\d+), #(\d+)", t)
    if m:
        lsb, width = int(m.group(3)), int(m.group(4))
        return 0x53000000 | (lsb << 16) | ((lsb + width - 1) << 10) | (_r(m.group(2)) << 5) | _r(m.group(1))
    m = re.fullmatch(r"orr (w\d+), (w\d+), (w\d+), lsl #(\d+)", t)
    if m:
        return 0x2A000000 | (_r(m.group(3)) << 16) | (int(m.group(4)) << 10) | (_r(m.group(2)) << 5) | _r(m.group(1))
    raise ValueError("encoder does not know: " + text)


def dump_words_text(dump, cls, idx):
    """First instructions of a slot as written in vtables_dump.txt (for the cross-check)."""
    return dump[idx][1]


def build(out):
    sym = json.loads((SRC / "symbols.json").read_text())
    am = AV.parse_amethyst(SRC / "amethyst-learnings.txt", "Item")
    dump = AV.parse_dump(SRC / "vtables_dump.txt", "Item")
    # 1. vtables (every class from symbols.json)
    vtables = {c: [{"rva": e["vptr_rva"], "slots": e["slots"]} for e in v] for c, v in sym["vtables"].items()}
    # 2. static / reported functions
    funcs = {}
    for name, (ms, an, src, ev, ins) in STATIC.items():
        txt = [x.strip() for x in dump[an][1]]
        first = ins[0].replace("#0000000000000000", "#0")
        if txt[0].replace("#0000000000000000", "#0") != first:
            raise SystemExit(f"{name}: dump slot {an} starts with '{txt[0]}', not '{ins[0]}' - evidence table is wrong")
        sig = am[ms]
        funcs[name] = {"kind": "virtual", "vtable": "Item", "index": an, "msvc_index": ms, "status": "static",
                       "source": src, "evidence": ev, "signature": sig,
                       "cpp_ret": CPP_SIG[name][0], "cpp_params": CPP_SIG[name][1], "expect": [f"0x{encode(i):08X}" for i in ins],
                       "expect_text": ins}
    for name, (ms, an) in REPORTED.items():
        funcs[name] = {"kind": "virtual", "vtable": "Item", "index": an, "msvc_index": ms, "status": "reported",
                       "source": GUIDE, "evidence": "guide lists it as verified; no instruction evidence recorded",
                       "signature": am[ms]}
    # 3. candidates from the shape alignment (without the anchors' own entries)
    pairs, ak, bk = AV.align(am, dump, AV.ANCHORS)
    cands = []
    for i in sorted(pairs):
        j = pairs[i]
        nm = "Item::" + re.search(r"(\w+)\(", am[i]).group(1)
        if nm in funcs:
            continue
        cands.append({"name": nm, "vtable": "Item", "index": j, "msvc_index": i, "shift": j - i, "status": "candidate",
                      "confidence": AV.confidence(i, j, pairs, AV.ANCHORS, ak, bk), "shape": f"{ak[i]}~{bk[j]}",
                      "signature": am[i]})
    shifts = {f["msvc_index"]: f["index"] - f["msvc_index"] for f in funcs.values()}
    shifts.update({c["msvc_index"]: c["shift"] for c in cands})
    runs = []
    for k in sorted(shifts):
        if runs and runs[-1]["shift"] == shifts[k]:
            runs[-1]["msvc_to"] = k
        else:
            runs.append({"msvc_from": k, "msvc_to": k, "shift": shifts[k]})
    db = {
        "schema": 1,
        "sha256": sym["sha256"],
        "mc_version_string": sym["mc_version_string"],
        "mc_version_confirmed": False,
        "abi": sym["abi"],
        "build_id": sym["build_id"],
        "image_base": 0,
        "notes": [
            "Item vtable slots do NOT shift by a constant vs Amethyst (MSVC 1.21.0.3): see shift_runs. The hooking guide's "
            "'+1..+3' only holds up to msvc slot ~37; at slot 57 the shift is +12. Never add a fixed offset to an Amethyst index.",
            "status 'static' = instruction evidence read from this exact binary. No entry is live-tested yet.",
            "Subclass vtables (SwordItem, ...) may override a slot: hooking the base Item slot only affects items that still inherit it.",
            "No build-id: identify the build by sha256 offline and by the `expect` words at runtime.",
        ],
        "shift_runs": runs,
        "vtables": vtables,
        "functions": funcs,
        "candidates": cands,
        "offsets": {k: {"offset": o, "type": t, "status": "static", "evidence": e} for k, (o, t, e) in OFFSETS.items()},
        "java_aliases": JAVA_ALIASES,
        "java_classes": JAVA_CLASSES,
    }
    out = pathlib.Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(db, indent=1) + "\n")
    return db


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE.parent / "levipack_forge/data/libminecraftpe.4de40e1d.symbols.json"))
    a = ap.parse_args(argv)
    db = build(a.out)
    c = {}
    for x in db["candidates"]:
        c[x["confidence"]] = c.get(x["confidence"], 0) + 1
    print(f"wrote {a.out}: {len(db['functions'])} functions "
          f"({sum(1 for f in db['functions'].values() if f['status']=='static')} static), "
          f"{len(db['candidates'])} candidates {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
