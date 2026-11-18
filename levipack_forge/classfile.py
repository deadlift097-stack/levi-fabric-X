"""Minimal, dependency-free JVM class file parser + bytecode iterator."""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

OPLEN = {}
for op in range(0, 256):
    OPLEN[op] = 1
for op in (16, 18, 21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169, 188):
    OPLEN[op] = 2
for op in (17, 19, 20, 132, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
           164, 165, 166, 167, 168, 178, 179, 180, 181, 182, 183, 184, 187, 189,
           192, 193, 198, 199):
    OPLEN[op] = 3
OPLEN[197] = 4
for op in (185, 186, 200, 201):
    OPLEN[op] = 5


@dataclass
class Insn:
    pc: int
    op: int
    arg: object = None   # decoded operand(s)


@dataclass
class Member:
    name: str
    desc: str
    access: int
    const_value: object = None
    code: bytes | None = None
    max_locals: int = 0


@dataclass
class ClassFile:
    name: str = ""
    super_name: str = ""
    interfaces: list = field(default_factory=list)
    access: int = 0
    cp: list = field(default_factory=list)
    fields: list = field(default_factory=list)
    methods: list = field(default_factory=list)
    bootstraps: list = field(default_factory=list)   # (method_handle_idx, [arg idx])

    # ---- constant pool helpers
    def utf8(self, i):
        return self.cp[i][1]

    def cls(self, i):
        return self.utf8(self.cp[i][1])

    def nat(self, i):
        _, n, d = self.cp[i]
        return self.utf8(n), self.utf8(d)

    def ref(self, i):
        """Field/Method/InterfaceMethod ref -> (owner, name, desc)."""
        _, c, nt = self.cp[i]
        n, d = self.nat(nt)
        return self.cls(c), n, d

    def const(self, i):
        e = self.cp[i]
        t = e[0]
        if t == "utf8":
            return e[1]
        if t == "string":
            return ("str", self.utf8(e[1]))
        if t in ("int", "float", "long", "double"):
            return (t, e[1])
        if t == "class":
            return ("class", self.utf8(e[1]))
        return (t, e[1:])

    def method_handle(self, i):
        _, kind, ref = self.cp[i]
        return kind, self.ref(ref)

    def invokedynamic(self, i):
        _, bsm, nt = self.cp[i]
        name, desc = self.nat(nt)
        return bsm, name, desc

    def find_method(self, name, desc=None):
        for m in self.methods:
            if m.name == name and (desc is None or m.desc == desc):
                return m
        return None


def parse(data: bytes) -> ClassFile:
    p = 0

    def u1():
        nonlocal p
        v = data[p]; p += 1; return v

    def u2():
        nonlocal p
        v = struct.unpack_from(">H", data, p)[0]; p += 2; return v

    def u4():
        nonlocal p
        v = struct.unpack_from(">I", data, p)[0]; p += 4; return v

    if u4() != 0xCAFEBABE:
        raise ValueError("not a class file")
    u2(); u2()
    n = u2()
    cp = [None] * n
    i = 1
    while i < n:
        t = u1()
        if t == 1:
            ln = u2(); s = data[p:p + ln].decode("utf-8", "replace"); p += ln
            cp[i] = ("utf8", s)
        elif t == 3:
            cp[i] = ("int", struct.unpack_from(">i", data, p)[0]); p += 4
        elif t == 4:
            cp[i] = ("float", struct.unpack_from(">f", data, p)[0]); p += 4
        elif t == 5:
            cp[i] = ("long", struct.unpack_from(">q", data, p)[0]); p += 8; i += 1
        elif t == 6:
            cp[i] = ("double", struct.unpack_from(">d", data, p)[0]); p += 8; i += 1
        elif t == 7:
            cp[i] = ("class", u2())
        elif t == 8:
            cp[i] = ("string", u2())
        elif t in (9, 10, 11):
            cp[i] = ("ref", u2(), u2())
        elif t == 12:
            cp[i] = ("nat", u2(), u2())
        elif t == 15:
            cp[i] = ("mh", u1(), u2())
        elif t == 16:
            cp[i] = ("mt", u2())
        elif t in (17, 18):
            cp[i] = ("indy", u2(), u2())
        elif t in (19, 20):
            cp[i] = ("mod", u2())
        else:
            raise ValueError(f"bad constant pool tag {t}")
        i += 1
    cf = ClassFile(cp=cp)
    cf.access = u2()
    cf.name = cf.cls(u2())
    s = u2()
    cf.super_name = cf.cls(s) if s else ""
    cf.interfaces = [cf.cls(u2()) for _ in range(u2())]

    def attrs(member=None):
        for _ in range(u2()):
            nonlocal p
            an = cf.utf8(u2()); ln = u4(); end = p + ln
            if an == "ConstantValue" and member is not None:
                member.const_value = cf.const(struct.unpack_from(">H", data, p)[0])
            elif an == "Code" and member is not None:
                member.max_locals = struct.unpack_from(">H", data, p + 2)[0]
                cl = struct.unpack_from(">I", data, p + 4)[0]
                member.code = data[p + 8:p + 8 + cl]
            elif an == "BootstrapMethods" and member is None:
                q = p
                cnt = struct.unpack_from(">H", data, q)[0]; q += 2
                for _ in range(cnt):
                    mh, na = struct.unpack_from(">HH", data, q); q += 4
                    args = list(struct.unpack_from(f">{na}H", data, q)); q += 2 * na
                    cf.bootstraps.append((mh, args))
            p = end

    for _ in range(u2()):
        m = Member("", "", 0)
        m.access = u2(); m.name = cf.utf8(u2()); m.desc = cf.utf8(u2())
        attrs(m); cf.fields.append(m)
    for _ in range(u2()):
        m = Member("", "", 0)
        m.access = u2(); m.name = cf.utf8(u2()); m.desc = cf.utf8(u2())
        attrs(m); cf.methods.append(m)
    attrs(None)
    return cf


def decode(code: bytes):
    """Yield Insn objects."""
    out = []
    pc = 0
    n = len(code)
    while pc < n:
        op = code[pc]
        if op == 170:  # tableswitch
            q = (pc + 4) & ~3
            lo, hi = struct.unpack_from(">ii", code, q + 4)
            ln = (q + 12 + 4 * (hi - lo + 1)) - pc
            out.append(Insn(pc, op, None)); pc += ln; continue
        if op == 171:  # lookupswitch
            q = (pc + 4) & ~3
            npairs = struct.unpack_from(">i", code, q + 4)[0]
            ln = (q + 8 + 8 * npairs) - pc
            out.append(Insn(pc, op, None)); pc += ln; continue
        if op == 196:  # wide
            ln = 6 if code[pc + 1] == 132 else 4
            out.append(Insn(pc, op, struct.unpack_from(">H", code, pc + 2)[0])); pc += ln; continue
        ln = OPLEN[op]
        arg = None
        if ln == 2:
            arg = code[pc + 1] if op not in (16,) else struct.unpack_from(">b", code, pc + 1)[0]
        elif ln == 3:
            if op in (17,):
                arg = struct.unpack_from(">h", code, pc + 1)[0]
            elif 153 <= op <= 168 or op in (198, 199):
                arg = struct.unpack_from(">h", code, pc + 1)[0]
            else:
                arg = struct.unpack_from(">H", code, pc + 1)[0]
        elif ln == 5:
            arg = struct.unpack_from(">H", code, pc + 1)[0]
        out.append(Insn(pc, op, arg)); pc += ln
    return out


def arg_slots(desc: str):
    """Parse a method descriptor -> (list of param type descriptors, return descriptor)."""
    assert desc[0] == "("
    i = 1; params = []
    while desc[i] != ")":
        j = i
        while desc[j] == "[":
            j += 1
        if desc[j] == "L":
            j = desc.index(";", j)
        params.append(desc[i:j + 1]); i = j + 1
    return params, desc[i + 1:]
