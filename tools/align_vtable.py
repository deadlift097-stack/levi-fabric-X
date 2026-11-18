#!/usr/bin/env python3
"""align_vtable.py - candidate MSVC(Amethyst) -> Itanium(Android) vtable slot alignment.

Reads
  * an Amethyst header listing   (the `--- Item (...)` appendix of amethyst-learnings.txt, lines `[035] int getAttackDamage() const`)
  * a vtable dump                (vtables_dump.txt: `[038] 0x1079f1e0  mov w0, wzr ; ret ; ...`)
and aligns the two sequences with a small dynamic program that compares the *shape* of each
function (return type vs. what the first instructions do).

THIS IS STATIC EVIDENCE ONLY. Output is a list of candidates with a confidence label:
  anchor   - pinned by hand-verified evidence (see ANCHORS)
  aligned  - shape-compatible and between two anchors
  weak     - shape-compatible but the alignment could have slid
Nothing here has been confirmed by a live hook. Never install a hook on a non-anchor slot
without a test hook that proves it (print / change a value).

usage: align_vtable.py amethyst-learnings.txt vtables_dump.txt --class Item [--json out.json] [--no-anchors]
"""
from __future__ import annotations
import argparse, json, re, sys

# (amethyst msvc index) -> (android itanium index), evidence. Item only.
ANCHORS = {
    5:  (6,  "ldr w0,[x0,#0x114]; ret (getMaxUseDuration)"),
    24: (27, "strh w1,[x0,#0x110]; ret (setMaxDamage)"),
    25: (28, "str w1,[x0,#0x114]; ret (setMaxUseDuration)"),
    30: (33, "reads short@0x110 > 0 and flag@0x112 bit2 (canBeDepleted)"),
    34: (37, "ldrh w0,[x0,#0x110]; ret (getMaxDamage)"),
    35: (38, "mov w0,wzr; ret (getAttackDamage, int 0)"),
    36: (39, "movi d0,#0; ret (getAttackDamageBonus, float 0)"),
    37: (40, "ldrb [x0,#0x112]; ubfx #1 (isHandEquipped)"),
    57: (69, "100/(n+1): mov w8,#0x64; add w9,w1,#1; sdiv (getDamageChance)"),
    70: (80, "(id<<16)|aux: ldrh [x0,#0x8a]; sxth; orr lsl #16 (buildIdAux)"),
}

AM_LINE = re.compile(r"^\s*\[(\d+)\]\s+(.*\S)\s*$")


def parse_amethyst(path, cls):
    out, on = {}, False
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("--- "):
            on = line.split()[1] == cls
            continue
        if on:
            m = AM_LINE.match(line)
            if m and m.group(2):
                out[int(m.group(1))] = m.group(2)
    return out


def ret_kind(sig):
    sig = sig.strip()
    if sig.startswith("~"):
        return "dtor"
    head = sig.split("(")[0]
    parts = head.rsplit(" ", 1)
    rt = parts[0].strip() if len(parts) == 2 else ""
    rt = rt.replace("const ", "").replace("virtual ", "").strip()
    if rt in ("void",):
        return "void"
    if rt == "bool":
        return "bool"
    if rt in ("int", "short", "uint8_t", "uint32_t", "uint16_t", "FacingID", "int32_t"):
        return "int"
    if rt in ("float",):
        return "float"
    if rt.endswith("*"):
        return "ptr"
    if rt.endswith("&"):
        return "ref"
    if rt.startswith("std::string") or rt.startswith("std::vector") or rt.startswith("std::unique_ptr") \
            or rt.startswith("std::optional") or rt.startswith("std::shared_ptr"):
        return "struct"
    return "any"          # enums / small structs: cannot tell


DUMP_LINE = re.compile(r"^\s*\[(\d+)\]\s+0x([0-9a-f]+)\s+(.*)$")


def parse_dump(path, cls):
    out, on = {}, False
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("=== "):
            head = line.split("vptr")[0]
            on = line.split()[1] == cls and ("[vtable #" not in head or "[vtable #0]" in head)
            continue
        if on:
            m = DUMP_LINE.match(line)
            if m:
                out[int(m.group(1))] = (int(m.group(2), 16), [x.strip() for x in m.group(3).split(" ; ")])
    return out


def and_kind(instrs):
    """Shape of the function that starts the instruction list (the dump shows 3 raw instructions)."""
    body = []
    for i in instrs:
        body.append(i)
        if i.split()[0] in ("ret", "br") or i.startswith("b "):
            break
    else:
        return "complex"
    t = body[0]; mn = t.split()[0]
    if mn == "ret":
        return "void_ret"
    if t.startswith("mov w0, wzr"):
        return "zero"
    if re.match(r"mov w0, #-?\w+", t):
        return "const"
    if t.startswith("mov x0, xzr"):
        return "nullptr"
    if t.startswith(("movi d0", "fmov s0")) or (t.startswith("mov w8") and any("scvtf" in b for b in body)):
        return "fconst"
    if re.match(r"ldr s0, \[x0", t):
        return "ldr_s"
    if re.match(r"ldr w0, \[x0", t) or re.match(r"ldrsh w0|ldrh w0|ldrsw", t):
        return "ldr32"
    if re.match(r"ldrb w0, \[x0", t):
        return "ldrb"
    if re.match(r"ldr x0, \[x0", t):
        return "ldr64"
    if re.match(r"add x0, x0, #", t):
        return "addref"
    if any("ubfx w0" in b for b in body):
        return "ubfx"
    if t.startswith(("stp xzr, xzr, [x8]", "strb wzr, [x8]")):
        return "sret0"
    if t.startswith("ldr x8, [x0]") and any(b.startswith("br ") for b in body):
        return "tail"
    if t.startswith(("mov x0, x8", "mov x1, xzr", "mov x9, x0")):
        return "movret"
    return "small"


COMPAT = {
    "void": {"void_ret": 0, "complex": 1, "tail": 1, "small": 2},
    "bool": {"zero": 0, "const": 0, "ldrb": 0, "ubfx": 0, "ldr32": 1, "complex": 1, "tail": 1, "small": 2},
    "int": {"zero": 0, "const": 0, "ldr32": 0, "ldrb": 1, "ubfx": 1, "complex": 1, "tail": 1, "small": 2},
    "float": {"fconst": 0, "ldr_s": 0, "complex": 1, "tail": 1, "small": 2},
    "ptr": {"nullptr": 0, "ldr64": 0, "addref": 0, "complex": 1, "tail": 1, "movret": 1, "small": 2},
    "ref": {"nullptr": 0, "ldr64": 0, "addref": 0, "complex": 1, "tail": 1, "movret": 1, "small": 2},
    "struct": {"sret0": 0, "complex": 0, "movret": 1, "addref": 1, "tail": 1, "small": 2},
    "any": {"zero": 1, "const": 1, "ldr32": 1, "sret0": 1, "complex": 1, "ldrb": 1, "fconst": 2, "small": 1, "tail": 1,
            "movret": 1, "ubfx": 1, "nullptr": 2, "ldr64": 2, "addref": 2, "ldr_s": 2, "void_ret": 3},
}
BAD = 7            # shape mismatch
GAP_ANDROID = 1.6  # an Android slot with no Amethyst partner (virtual added after 1.21.0.3)
GAP_AMETHYST = 9.0 # an Amethyst virtual with no Android slot
ANCHOR_BONUS = -60.0


def align(am, an, anchors):
    A = sorted(k for k in am if k > 0)             # Amethyst index 0 is the destructor (2 Android slots)
    B = sorted(k for k in an if k > 1)
    ak = {i: ret_kind(am[i]) for i in A}
    bk = {j: and_kind(an[j][1]) for j in B}
    n, m = len(A), len(B)
    INF = 1e18
    D = [[INF] * (m + 1) for _ in range(n + 1)]
    P = [[None] * (m + 1) for _ in range(n + 1)]
    D[0][0] = 0
    for i in range(n + 1):
        for j in range(m + 1):
            d = D[i][j]
            if d >= INF:
                continue
            if i < n and j < m:
                a, b = A[i], B[j]
                c = COMPAT.get(ak[a], COMPAT["any"]).get(bk[b], BAD)
                if anchors.get(a, (None,))[0] == b:
                    c += ANCHOR_BONUS
                elif a in anchors or any(v[0] == b for v in anchors.values()):
                    c += 1000                       # an anchored slot may only pair with its partner
                if d + c < D[i + 1][j + 1]:
                    D[i + 1][j + 1] = d + c; P[i + 1][j + 1] = (i, j, "m")
            if j < m and d + GAP_ANDROID < D[i][j + 1]:
                D[i][j + 1] = d + GAP_ANDROID; P[i][j + 1] = (i, j, "a")
            if i < n and d + GAP_AMETHYST < D[i + 1][j]:
                D[i + 1][j] = d + GAP_AMETHYST; P[i + 1][j] = (i, j, "d")
    i, j, pairs = n, m, {}
    while (i, j) != (0, 0):
        pi, pj, op = P[i][j]
        if op == "m":
            pairs[A[pi]] = B[pj]
        i, j = pi, pj
    return pairs, ak, bk


def confidence(a, b, pairs, anchors, ak, bk):
    if a in anchors and anchors[a][0] == b:
        return "anchor"
    lo = max((k for k in anchors if k < a), default=None)
    hi = min((k for k in anchors if k > a), default=None)
    ok = COMPAT.get(ak[a], COMPAT["any"]).get(bk[b], BAD) <= 1
    if not ok:
        return "weak"
    # between two anchors whose spacing equals the Android spacing: nothing could have been inserted/dropped
    if lo is not None and hi is not None and (anchors[hi][0] - anchors[lo][0]) == (hi - lo) and anchors[lo][0] < b < anchors[hi][0]:
        return "aligned"
    return "weak"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("amethyst"); ap.add_argument("dump")
    ap.add_argument("--class", dest="cls", default="Item")
    ap.add_argument("--json"); ap.add_argument("--no-anchors", action="store_true")
    a = ap.parse_args(argv)
    am, an = parse_amethyst(a.amethyst, a.cls), parse_dump(a.dump, a.cls)
    if not am or not an:
        print(f"no data for class {a.cls} (amethyst={len(am)} slots, dump={len(an)} slots)", file=sys.stderr); return 2
    anchors = {} if (a.no_anchors or a.cls != "Item") else ANCHORS
    pairs, ak, bk = align(am, an, anchors)
    rows = []
    for i in sorted(pairs):
        j = pairs[i]
        rows.append({"msvc": i, "android": j, "shift": j - i, "sig": am[i], "shape": f"{ak[i]}~{bk[j]}",
                     "confidence": confidence(i, j, pairs, anchors, ak, bk), "evidence": anchors.get(i, (0, ""))[1]})
    for r in rows:
        print(f"[{r['msvc']:03d}] -> [{r['android']:03d}] shift {r['shift']:+d}  {r['confidence']:8s} {r['shape']:18s} {r['sig'][:70]}")
    if a.json:
        json.dump(rows, open(a.json, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
