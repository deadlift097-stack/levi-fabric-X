"""Builds a tiny but structurally realistic aarch64 ELF so tools/so_probe.py can be tested without the 342 MB game library.

Layout (file offset == virtual address, one RWX PT_LOAD):
  .text         @0x1000  three functions
  .rodata       @0x2000  Itanium typeinfo name "4Item"
  .data.rel.ro  @0x3000  typeinfo object (name pointer) + vtable (offset-to-top, typeinfo, 3 slots)
  .rela.dyn     @0x3400  R_AARCH64_RELATIVE entries - the file content of every pointer is 0, exactly like a real
                         shared object, so the relocation path of so_probe is exercised
"""
import struct

F0 = [0x2A1F03E0, 0xD65F03C0]          # mov w0,wzr ; ret          (getAttackDamage shape)
F1 = [0xB9411400, 0xD65F03C0]          # ldr w0,[x0,#0x114] ; ret  (getMaxUseDuration shape)
F2 = [0xD65F03C0, 0xD65F03C0]          # ret ; ret
F3 = [0x52800C88, 0xD65F03C0]          # Sword::slot1 override
F4 = [0x52800D08, 0xD65F03C0]          # Blade::slot1 override
TEXT, RODATA, DATA, RELA = 0x1000, 0x2000, 0x3000, 0x3400
NAME_VA, TYPEINFO, VTABLE = RODATA + 1, DATA, DATA + 0x100
VPTR = VTABLE + 16
FUNCS = [TEXT, TEXT + 8, TEXT + 16]
SWORD_TI, SWORD_VT = DATA + 0x200, DATA + 0x300         # class Sword : Item   (typeinfo, vtable start)
BLADE_TI, BLADE_VT = DATA + 0x240, DATA + 0x380         # class Blade : Sword
SWORD_VPTR, BLADE_VPTR = SWORD_VT + 16, BLADE_VT + 16
F3_VA, F4_VA = TEXT + 24, TEXT + 32


def build():
    size = 0x4000
    img = bytearray(size)
    for i, f in enumerate((F0, F1, F2, F3, F4)):
        struct.pack_into('<2I', img, TEXT + 8 * i, *f)
    img[RODATA:RODATA + 22] = b'\x004Item\x005Sword\x005Blade\x00'
    SWORD_NAME, BLADE_NAME = RODATA + 7, RODATA + 14
    rel = [(DATA + 8, NAME_VA),                      # typeinfo.name -> "4Item"
           (VTABLE + 8, TYPEINFO)]                   # vtable[-1] -> typeinfo
    rel += [(VPTR + 8 * i, fn) for i, fn in enumerate(FUNCS)]
    rel += [(SWORD_TI + 8, SWORD_NAME), (SWORD_TI + 16, TYPEINFO), (SWORD_VT + 8, SWORD_TI),
            (SWORD_VPTR, FUNCS[0]), (SWORD_VPTR + 8, F3_VA), (SWORD_VPTR + 16, FUNCS[2])]
    rel += [(BLADE_TI + 8, BLADE_NAME), (BLADE_TI + 16, SWORD_TI), (BLADE_VT + 8, BLADE_TI),
            (BLADE_VPTR, FUNCS[0]), (BLADE_VPTR + 8, F4_VA), (BLADE_VPTR + 16, FUNCS[2])]
    for i, (off, add) in enumerate(rel):
        struct.pack_into('<QQq', img, RELA + 24 * i, off, 1027, add)
    rela_size = 24 * len(rel)

    shstr = b'\x00.text\x00.rodata\x00.data.rel.ro\x00.rela.dyn\x00.dynsym\x00.dynstr\x00.shstrtab\x00'
    def nm(n): return shstr.index(b'\x00' + n.encode() + b'\x00') + 1
    dynsym_off, dynstr_off, shstr_off = 0x3800, 0x3840, 0x3860
    img[dynstr_off:dynstr_off + 1] = b'\x00'
    img[shstr_off:shstr_off + len(shstr)] = shstr
    # section headers at 0x3a00 (null + 7)
    shoff = 0x3A00
    secs = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (nm('.text'), 1, 6, TEXT, TEXT, 40, 0, 0, 4, 0),
            (nm('.rodata'), 1, 2, RODATA, RODATA, 24, 0, 0, 1, 0),
            (nm('.data.rel.ro'), 1, 3, DATA, DATA, 0x400, 0, 0, 8, 0),
            (nm('.rela.dyn'), 4, 2, RELA, RELA, rela_size, 5, 0, 8, 24),
            (nm('.dynsym'), 11, 2, dynsym_off, dynsym_off, 24, 6, 1, 8, 24),
            (nm('.dynstr'), 3, 2, dynstr_off, dynstr_off, 1, 0, 0, 1, 0),
            (nm('.shstrtab'), 3, 0, shstr_off, shstr_off, len(shstr), 0, 0, 1, 0)]
    for i, (n, t, fl, addr, off, sz, link, info, al, es) in enumerate(secs):
        struct.pack_into('<IIQQQQIIQQ', img, shoff + 64 * i, n, t, fl, addr, off, sz, link, info, al, es)
    # program header at 0x40: one PT_LOAD over the whole image
    struct.pack_into('<IIQQQQQQ', img, 0x40, 1, 7, 0, 0, 0, size, size, 0x1000)
    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into('<16sHHIQQQIHHHHHH', img, 0, ident, 3, 183, 1, 0, 0x40, shoff, 0, 64, 56, 1, 64, len(secs), len(secs) - 1)
    return bytes(img)
