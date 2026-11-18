#!/usr/bin/env python3
"""
so_probe.py - inspects libminecraftpe.so (aarch64 ELF) for the levipack hook work.
Usage:
  python3 so_probe.py libminecraftpe.so                       # report + symbols.json skeleton
  python3 so_probe.py libminecraftpe.so --classes Item,Actor,Mob,Player,GameMode,BlockLegacy,ScreenController
  python3 so_probe.py libminecraftpe.so --sig 0x1234abc       # ARM64 masked signature for a function
  python3 so_probe.py libminecraftpe.so --dump vtables_dump.txt   # every slot + first instructions (feeds align_vtable.py)
  python3 so_probe.py libminecraftpe.so --verify levipack_forge/data/libminecraftpe.4de40e1d.symbols.json [--quiet]
                                                              # after a game update: do the static slots still match?
                                                              # --quiet prints only what is NOT ok
  python3 so_probe.py libminecraftpe.so --subclasses Item --db levipack_forge/data/libminecraftpe.4de40e1d.symbols.json --merge
                                                              # find every class derived from Item that overrides a
                                                              # static slot and record it in the DB (generated mods then
                                                              # hook those overrides too)
Needs: pip install pyelftools numpy   (capstone is optional: only --dump uses it, for readable instructions)
Writes: symbols.json (build_id, vtables, exported hits).

v0.4 changes: --dump and --verify added; --sig counts only 4-byte-aligned matches (ARM64 instructions are aligned,
unaligned regex hits were false positives); duplicate ADRP mask assignment removed; clear message when numpy is missing.
"""
import sys, re, json, struct, argparse, hashlib
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

def load(path):
    f = open(path, 'rb'); e = ELFFile(f); return f, e

def build_id(e):
    for s in e.iter_sections():
        if s.name == '.note.gnu.build-id':
            for n in s.iter_notes():
                if n['n_type'] == 'NT_GNU_BUILD_ID': return n['n_desc']
    return None

def v2off(e, va):
    for seg in e.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va < seg['p_vaddr'] + seg['p_filesz']:
            return va - seg['p_vaddr'] + seg['p_offset']
    return None

def mangle_name(c):
    parts = c.split('::')
    body = ''.join(str(len(x)) + x for x in parts)
    return body if len(parts) == 1 else 'N' + body + 'E'

def rodata_names(f, e, want=None):
    """Find Itanium typeinfo-name strings for the wanted classes by direct byte search -> {mangled: va}"""
    out = {}
    secs = [s for s in e.iter_sections() if s.name in ('.rodata', '.data.rel.ro')]
    for s in secs:
        data = s.data(); base = s['sh_addr']
        for c in (want or []):
            needle = b'\x00' + mangle_name(c).encode() + b'\x00'
            i = data.find(needle)
            while i != -1:
                out.setdefault(mangle_name(c), base + i + 1)
                i = data.find(needle, i + 1)
    return out

def demangle(t):
    res = []; s = t
    i = 1 if t.startswith('N') else 0
    while i < len(s) and s[i].isdigit():
        j = i
        while j < len(s) and s[j].isdigit(): j += 1
        n = int(s[i:j]); res.append(s[j:j+n]); i = j + n
    return '::'.join(res) if res else t

def reloc_map(e):
    """Vectorised: returns dict-like object with .get(va). RELATIVE + ABS64 vs symbol."""
    try:
        import numpy as np
    except ImportError:
        sys.exit("so_probe.py needs numpy: pip install numpy")
    dt = np.dtype([('off','<u8'),('info','<u8'),('add','<i8')])
    offs=[]; vals=[]
    dyn = e.get_section_by_name('.dynsym')
    symv = None
    for sec in e.iter_sections():
        if sec.name == '.rela.dyn':
            arr = np.frombuffer(sec.data(), dtype=dt)
            typ = arr['info'] & 0xffffffff; sym = arr['info'] >> 32
            m = (sym == 0) & ((typ == 1027) | (typ == 8))
            offs.append(arr['off'][m]); vals.append(arr['add'][m].astype('<u8'))
            m2 = (sym != 0) & ((typ == 257) | (typ == 1))
            if m2.any():
                if symv is None:
                    symv = np.frombuffer(dyn.data(), dtype=np.dtype([('n','<u4'),('i','u1'),('o','u1'),('sh','<u2'),('v','<u8'),('sz','<u8')]))['v']
                offs.append(arr['off'][m2]); vals.append((symv[sym[m2]] + arr['add'][m2].astype('<u8')))
    o = np.concatenate(offs) if offs else np.zeros(0,'<u8'); v = np.concatenate(vals) if vals else np.zeros(0,'<u8')
    order = np.argsort(o); o = o[order]; v = v[order]
    class RM:
        def get(self, va, default=None):
            i = np.searchsorted(o, va)
            return int(v[i]) if i < len(o) and o[i] == va else default
        def __contains__(self, va): return self.get(va) is not None
        def __getitem__(self, va): return self.get(va)
    rm = RM(); rm.o = o; rm.v = v
    return rm

def read_slots(f, e, rm, targets):
    """vectorised: for every 8-byte slot in data sections, resolved value in targets -> {value: [slot_va]}"""
    import numpy as np
    tg = np.array(sorted(targets), dtype='<u8'); hits = {}
    for s in e.iter_sections():
        if s.name in ('.data.rel.ro', '.data.rel.ro.local', '.data'):
            base = s['sh_addr']; data = s.data(); n = len(data) // 8
            arr = np.frombuffer(data[:n*8], dtype='<u8').copy()
            lo, hi = base, base + n * 8
            i0 = np.searchsorted(rm.o, lo); i1 = np.searchsorted(rm.o, hi)
            idx = ((rm.o[i0:i1] - base) // 8).astype(np.int64)
            arr[idx] = rm.v[i0:i1]
            pos = np.searchsorted(tg, arr); pos[pos >= len(tg)] = 0
            m = tg[pos] == arr
            for j in np.nonzero(m)[0]:
                hits.setdefault(int(arr[j]), []).append(base + int(j) * 8)
    return hits, rm

def find_vtables(f, e, want):
    names = rodata_names(f, e, want)
    sel = dict(names)
    rm = reloc_map(e)
    hits, _ = read_slots(f, e, rm, set(sel.values()))
    typeinfo = {}
    for t, nva in sel.items():
        for slot in hits.get(nva, []):
            typeinfo.setdefault(demangle(t), []).append(slot - 8)   # typeinfo = {vptr, name, ...}
    ti_set = {x for v in typeinfo.values() for x in v}
    hits2, _ = read_slots(f, e, rm, ti_set) if ti_set else ({}, rm)
    text = e.get_section_by_name('.text'); lo, hi = text['sh_addr'], text['sh_addr'] + text['sh_size']
    vt = {}
    for cls, tis in typeinfo.items():
        for ti in tis:
            for slot in hits2.get(ti, []):
                vptr = slot + 8                  # vptr points after offset_to_top + typeinfo
                first = vslot(f, e, rm, vptr, 0); ott = vslot(f, e, rm, slot - 8, 0)
                if first and lo <= first < hi and ott is not None and (ott < 0x10000 or ott > 0xFFFFFFFFFFF00000):
                    vt.setdefault(cls, []).append(vptr)
    return vt, rm, e

def vslot(f, e, rm, vptr, i):
    va = vptr + 8 * i
    if va in rm: return rm[va]
    o = v2off(e, va)
    if o is None: return None
    f.seek(o); return struct.unpack('<Q', f.read(8))[0]

def mask_sig(f, e, va, n=12):
    o = v2off(e, va); f.seek(o); words = struct.unpack('<%dI' % n, f.read(4 * n))
    toks = []; prev_adrp = False
    for w in words:
        m = 0
        if (w & 0x7C000000) == 0x14000000: m = 0x03FFFFFF              # B / BL
        elif (w & 0x9F000000) == 0x90000000: m = 0x60FFFFE0  # ADRP imm
        elif (w & 0x3B000000) == 0x18000000: m = 0x00FFFFE0            # LDR literal
        elif (w & 0x7E000000) == 0x34000000: m = 0x00FFFFE0            # CBZ/CBNZ
        elif (w & 0xFF000010) == 0x54000000: m = 0x00FFFFE0            # B.cond
        elif (w & 0x7E000000) == 0x36000000: m = 0x0007FFE0            # TBZ/TBNZ
        elif prev_adrp and ((w & 0x7F800000) == 0x11000000 or (w & 0x3B000000) == 0x39000000):
            m = 0x003FFC00                                              # ADD/LDR/STR imm12 after ADRP
        prev_adrp = (w & 0x9F000000) == 0x90000000
        b = struct.pack('<I', w); mb = struct.pack('<I', m)
        toks += ['??' if mb[k] else '%02X' % b[k] for k in range(4)]
    return ' '.join(toks)

def sig_unique(f, e, sig):
    """Number of 4-byte-aligned matches of the masked signature in .text (1 = usable)."""
    pat = re.compile(b''.join(b'.' if t == '??' else re.escape(bytes([int(t, 16)])) for t in sig.split()), re.S)
    c = 0
    for s in e.iter_sections():
        if s.name == '.text':
            data = s.data(); pos = 0
            while True:
                m = pat.search(data, pos)
                if not m:
                    break
                if (m.start() & 3) == 0:
                    c += 1
                pos = m.start() + 1
    return c


def text_range(e):
    t = e.get_section_by_name('.text'); return t['sh_addr'], t['sh_addr'] + t['sh_size']


def slot_count(f, e, rm, vptr, limit=1024):
    """Slots of a vtable: consecutive 8-byte entries that are relocated pointers or code addresses."""
    lo, hi = text_range(e); n = 0
    while n < limit:
        va = vptr + 8 * n
        v = vslot(f, e, rm, va, 0)
        if v is None or not (lo <= v < hi or (va in rm and v == 0)):
            break
        n += 1
    return n


def read_words(f, e, va, n):
    o = v2off(e, va)
    if o is None:
        return None
    f.seek(o); b = f.read(4 * n)
    return list(struct.unpack('<%dI' % (len(b) // 4), b)) if len(b) == 4 * n else None


def check_expect(words, expect):
    """True if the instruction words read from the binary equal the expected ones (pure, unit-tested)."""
    return words is not None and len(words) >= len(expect) and all(w == int(x, 16) for w, x in zip(words, expect))


def disasm_first(f, e, va, n=3):
    try:
        import capstone
    except ImportError:
        ws = read_words(f, e, va, n) or []
        return ' ; '.join('.word 0x%08x' % w for w in ws)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    ws = read_words(f, e, va, n) or []
    out = []
    for w in ws:
        ins = next(md.disasm(struct.pack('<I', w), va), None)
        out.append(('%s %s' % (ins.mnemonic, ins.op_str)).strip() if ins else '.word 0x%08x' % w)
        va += 4
    return ' ; '.join(out)


def dump_vtables(f, e, rm, vt, path, sha):
    """Write the vtables_dump.txt format that tools/align_vtable.py reads."""
    with open(path, 'w') as o:
        o.write('VTABLE DUMP - libminecraftpe.so  sha256 %s\n' % sha)
        o.write('Addresses are ELF virtual addresses = RVAs (image base 0). At runtime: load_base + RVA. Index counted from vptr.\n')
        o.write('Itanium ABI: slots 0 and 1 are the two destructors (D1/D0). Last column = first instructions of the slot.\n\n')
        for cls in sorted(vt):
            for k, vptr in enumerate(sorted(vt[cls])):
                n = slot_count(f, e, rm, vptr)
                tag = cls if len(vt[cls]) == 1 else '%s [vtable #%d]' % (cls, k)
                o.write('=== %s  vptr RVA 0x%x  slots %d\n' % (tag, vptr, n))
                for i in range(n):
                    fn = vslot(f, e, rm, vptr, i)
                    o.write('  [%03d] 0x%x  %s\n' % (i, fn, disasm_first(f, e, fn)))
                o.write('\n')


def cstring_at(f, e, va, maxlen=256):
    o = v2off(e, va)
    if o is None:
        return None
    f.seek(o); b = f.read(maxlen); i = b.find(b'\x00')
    return b[:i].decode('ascii', 'replace') if i > 0 else None


def typeinfo_addrs(f, e, rm, cls):
    """Typeinfo object address(es) of a class, found via its typeinfo-name string (needs RTTI)."""
    names = rodata_names(f, e, [cls])
    if not names:
        return []
    hits, _ = read_slots(f, e, rm, set(names.values()))
    return sorted(slot - 8 for v in hits.values() for slot in v)          # object = {vptr, name, ...}


def vptrs_of_typeinfo(f, e, rm, tis):
    """{typeinfo: [vptr]} - a vtable's slot -1 holds the typeinfo pointer (vptr = that address + 8)."""
    if not tis:
        return {}
    hits, _ = read_slots(f, e, rm, set(tis))
    lo, hi = text_range(e); out = {}
    for ti, slots in hits.items():
        for sl in slots:
            first = vslot(f, e, rm, sl + 8, 0)
            if first and lo <= first < hi:
                out.setdefault(ti, []).append(sl + 8)
    return out


def find_subclasses(f, e, rm, base_cls, max_depth=6):
    """Single-inheritance descendants of `base_cls`: [{'class','typeinfo','vptr','parent'}].

    A __si_class_type_info object is {vptr, name*, base_type_info*}; every object whose third word points at the
    base's typeinfo is a direct subclass. Multiple-inheritance classes (__vmi_class_type_info) are NOT found."""
    frontier = {ti: base_cls for ti in typeinfo_addrs(f, e, rm, base_cls)}
    found, seen = [], set(frontier)
    for _ in range(max_depth):
        if not frontier:
            break
        hits, _ = read_slots(f, e, rm, set(frontier))
        nxt = {}
        for parent_ti, slots in hits.items():
            for sl in slots:
                obj = sl - 16
                if obj in seen:
                    continue
                name_va = vslot(f, e, rm, obj + 8, 0)
                mangled = cstring_at(f, e, name_va) if name_va else None
                if not mangled or not re.match(r'^(N?\d+\w*E?|\d+\w+)$', mangled):
                    continue
                seen.add(obj); nxt[obj] = demangle(mangled)
                found.append({'class': demangle(mangled), 'typeinfo': obj, 'parent': frontier[parent_ti]})
        frontier = nxt
    vp = vptrs_of_typeinfo(f, e, rm, [x['typeinfo'] for x in found])
    out = []
    for x in found:
        for v in vp.get(x['typeinfo'], []):
            out.append({**x, 'vptr': v})
    return out


def slot_overrides(f, e, rm, base_vptr, sub_vptr, slots, nwords=3):
    """{slot: {target_rva, expect}} for the slots where the subclass vtable points elsewhere than the base vtable."""
    lo, hi = text_range(e); res = {}
    for s in slots:
        b, t = vslot(f, e, rm, base_vptr, s), vslot(f, e, rm, sub_vptr, s)
        if t and b != t and lo <= t < hi:
            w = read_words(f, e, t, nwords)
            if w:
                res[str(s)] = {'target_rva': hex(t), 'expect': ['0x%08X' % x for x in w]}
    return res


def subclass_report(f, e, rm, base_cls, base_vptr, slots):
    out = []
    for sc in find_subclasses(f, e, rm, base_cls):
        ov = slot_overrides(f, e, rm, base_vptr, sc['vptr'], slots)
        out.append({'class': sc['class'], 'parent': sc['parent'], 'vptr_rva': hex(sc['vptr']), 'overrides': ov})
    return sorted(out, key=lambda x: x['class'])


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b''):
            h.update(chunk)
    return h.hexdigest()


def verify_db(f, e, rm, db):
    """[(name, 'OK'|'MISMATCH'|'SKIP', detail)] for every static function of a symbols DB."""
    res = []
    for name, fn in sorted(db.get('functions', {}).items()):
        if fn.get('status') != 'static' or not fn.get('expect'):
            res.append((name, 'SKIP', 'status %s' % fn.get('status'))); continue
        vts = db.get('vtables', {}).get(fn['vtable']) or []
        if not vts:
            res.append((name, 'SKIP', 'vtable %s not in DB' % fn['vtable'])); continue
        vptr = int(vts[0]['rva'], 16)
        target = vslot(f, e, rm, vptr, fn['index'])
        words = read_words(f, e, target, len(fn['expect'])) if target else None
        if check_expect(words, fn['expect']):
            res.append((name, 'OK', 'slot %d -> 0x%x' % (fn['index'], target)))
        else:
            got = ' '.join('%08X' % w for w in words) if words else 'unreadable'
            res.append((name, 'MISMATCH', 'slot %d -> %s; expected %s, got %s' % (
                fn['index'], hex(target) if target else 'none', ' '.join(x[2:].upper() for x in fn['expect']), got)))
    return res


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('so')
    ap.add_argument('--classes', default='Item,Actor,Mob,Player,GameMode,BlockLegacy,ScreenController,Container,BlockActor,Dimension,Level,ClientInstance,Minecraft')
    ap.add_argument('--sig'); ap.add_argument('--dump', help='write every slot of the vtables to this file')
    ap.add_argument('--quiet', action='store_true', help='with --verify/--subclasses: print only problems')
    ap.add_argument('--subclasses', metavar='CLASS', help='list descendants of CLASS and the DB slots they override')
    ap.add_argument('--db', help='symbols DB (*.symbols.json) used by --subclasses for the slots to compare')
    ap.add_argument('--merge', action='store_true', help='with --subclasses: write the result into --db')
    ap.add_argument('--slots', help='with --subclasses and no --db: comma separated slot numbers')
    ap.add_argument('--verify', help='symbols DB (*.symbols.json): re-check its static slots against this .so')
    a = ap.parse_args()
    f, e = load(a.so)
    print('machine:', e['e_machine'], '| class:', e.elfclass)
    if a.sig:
        va = int(a.sig, 0); s = mask_sig(f, e, va)
        print('sig:', s); print('matches in .text:', sig_unique(f, e, s)); return
    if a.verify:
        db = json.load(open(a.verify))
        sha = file_sha256(a.so)
        same = sha == db.get('sha256')
        print('sha256:', sha, '(matches the DB)' if same else '(DIFFERENT build than the DB was made for: expect mismatches)')
        rm = reloc_map(e); bad = 0
        for name, st, detail in verify_db(f, e, rm, db):
            if not (a.quiet and st in ('OK', 'SKIP')):
                print(f'{st:9s} {name:34s} {detail}')
            bad += st == 'MISMATCH'
        print('result:', 'all static slots verified' if not bad and same else f'{bad} mismatch(es)' if bad else 'slots match but sha256 differs')
        return 1 if bad else 0
    if a.subclasses:
        db = json.load(open(a.db)) if a.db else {}
        cls = a.subclasses
        vts = (db.get('vtables') or {}).get(cls)
        if vts:
            base_vptr = int(vts[0]['rva'], 16)
        else:
            vt0, _, _ = find_vtables(f, e, {cls}); base_vptr = (vt0.get(cls) or [0])[0]
        if not base_vptr:
            print(f'no vtable for {cls} (RTTI missing?)'); return 2
        slots = sorted({fn['index'] for fn in db.get('functions', {}).values()
                        if fn.get('vtable') == cls and fn.get('status') == 'static'}) if db else \
            [int(x) for x in (a.slots or '').split(',') if x]
        if not slots:
            print('no slots to compare: pass --db or --slots'); return 2
        rm = reloc_map(e)
        rep = subclass_report(f, e, rm, cls, base_vptr, slots)
        n_ov = sum(1 for r in rep if r['overrides'])
        for r in rep:
            if r['overrides'] or not a.quiet:
                print(f"{r['class']:28s} parent {r['parent']:20s} vptr {r['vptr_rva']}  overrides slots {', '.join(r['overrides']) or '-'}")
        print(f'{len(rep)} descendant vtable(s) of {cls}, {n_ov} override at least one of slots {slots}')
        print('note: only single-inheritance descendants are found; multiple-inheritance classes are not')
        if a.merge:
            if not a.db:
                print('--merge needs --db'); return 2
            db.setdefault('subclasses', {})[cls] = [r for r in rep if r['overrides']]
            db['subclass_analysis'] = {'base': cls, 'slots': slots, 'sha256_checked': file_sha256(a.so)}
            json.dump(db, open(a.db, 'w'), indent=1); open(a.db, 'a').write('\n'); print('merged into', a.db)
        return 0
    bid = build_id(e); print('build-id:', bid)
    dyn = e.get_section_by_name('.dynsym')
    names = [s.name for s in dyn.iter_symbols()] if dyn else []
    mc = [n for n in names if n.startswith('_ZN') and ('4Item' in n or '5Actor' in n or '6Player' in n)]
    print('.dynsym entries:', len(names), '| game-looking Itanium names:', len(mc))
    print('.symtab present:', e.get_section_by_name('.symtab') is not None)
    want = set(a.classes.split(','))
    vt, rm, _ = find_vtables(f, e, want)
    out = {'build_id': bid, 'abi': 'arm64-v8a', 'vtables': {}, 'exports_sample': mc[:50]}
    for c in sorted(want):
        lst = vt.get(c, [])
        print(f'{c:18s} vtables: ' + (', '.join(hex(v) for v in lst) if lst else 'NOT FOUND (RTTI missing or nested name)'))
        if lst:
            out['vtables'][c] = {'rva': [hex(v) for v in lst],
                                 'slots0_8': [hex(vslot(f, e, rm, lst[0], i) or 0) for i in range(8)]}
    json.dump(out, open('symbols.json', 'w'), indent=2); print('wrote symbols.json')
    if a.dump:
        dump_vtables(f, e, rm, vt, a.dump, file_sha256(a.so)); print('wrote', a.dump)

if __name__ == '__main__':
    sys.exit(main() or 0)
