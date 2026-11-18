"""Discover Brigadier client commands in a jar and describe them as launcher config toggles.

Bedrock/Android has no Java command dispatcher. A command that flips a switch or sets a number can still be
useful as a typed config field (the launcher renders it). We read the command tree out of the bytecode:
`literal("x")` -> sub-command, `argument("n", floatArg())` -> number.
"""
from __future__ import annotations
import re
from . import classfile as C

ARG_KIND = {"floatArg": "double", "doubleArg": "double", "integer": "int", "longArg": "int",
            "bool": "bool", "word": "string", "string": "string", "greedyString": "string"}


def _snake(s):
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", s)
    return re.sub(r"[^0-9a-zA-Z]+", "_", s).strip("_").lower() or "value"


def uses_brigadier(cf: C.ClassFile) -> bool:
    return any(e and e[0] == "utf8" and ("com/brigadier" in e[1] or "com/mojang/brigadier" in e[1]
                                          or "client/command/v2" in e[1]) for e in cf.cp)


def find_commands(classes):
    """Return (commands, command_classes). commands: [{path, sub, args:[{name,kind}]}]."""
    out, cmd_classes = [], set()
    for cf in classes.values():
        if not uses_brigadier(cf):
            continue
        cmd_classes.add(cf.name)
        root, cur, last_kind = None, None, None
        seq = []
        for m in sorted((m for m in cf.methods if m.code), key=lambda m: m.name):
            last_str = None
            for i in C.decode(m.code):
                if i.op in (18, 19, 20):
                    v = cf.const(i.arg)
                    if isinstance(v, tuple) and v[0] == "str":
                        last_str = v[1]
                elif i.op in (184, 182, 185):
                    o, n, d = cf.ref(i.arg)
                    if n in ARG_KIND and "ArgumentType" in o:
                        last_kind = ARG_KIND[n]
                    elif n == "literal" and last_str is not None:
                        seq.append(("literal", last_str, None)); last_str = None
                    elif n == "argument" and last_str is not None:
                        seq.append(("arg", last_str, last_kind or "double")); last_str = None
        for kind, name, t in seq:
            if kind == "literal":
                if root is None:
                    root = name; cur = None
                else:
                    cur = {"path": f"{root} {name}", "sub": name, "args": [], "class": cf.name.replace("/", ".")}
                    out.append(cur)
            elif cur is not None:
                cur["args"].append({"name": name, "kind": t})
    uniq, seen = [], set()
    for c in out:                      # the same command is often registered by two classes (client + debug)
        if c["path"] not in seen:
            seen.add(c["path"]); uniq.append(c)
    return uniq, cmd_classes


def config_fields(commands):
    """Config members for the commands: bool toggle without arguments, typed numbers with arguments."""
    fields = []
    for c in commands:
        base = "cmd_" + _snake(c["sub"])
        if not c["args"]:
            fields.append({"member": base, "type": "bool", "default": "false",
                           "title": f"Command /{c['path']}", "desc": f"Replaces the Java command /{c['path']} (on/off)."})
        for a in c["args"]:
            t = {"double": ("double", "0.0"), "int": ("int", "0"), "bool": ("bool", "false"),
                 "string": ("std::string", '""')}[a["kind"]]
            fields.append({"member": f"{base}_{_snake(a['name'])}", "type": t[0], "default": t[1],
                           "title": f"/{c['path']} {a['name']}",
                           "desc": f"Replaces argument '{a['name']}' of the Java command /{c['path']}."})
    return fields
