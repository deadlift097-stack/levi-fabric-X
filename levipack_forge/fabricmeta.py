from __future__ import annotations
import json, re


def parse(text: str) -> dict:
    j = json.loads(text)
    authors = []
    for a in j.get("authors", []):
        authors.append(a if isinstance(a, str) else a.get("name", ""))
    ep = {}
    for kind, items in (j.get("entrypoints") or {}).items():
        norm = []
        for it in items:
            v = it if isinstance(it, str) else it.get("value", "")
            cls, _, meth = v.partition("::")
            norm.append((cls.replace(".", "/"), meth or None))
        ep[kind] = norm
    icon = j.get("icon")
    if isinstance(icon, dict):
        icon = icon[max(icon, key=lambda k: int(k))]
    mc = (j.get("depends") or {}).get("minecraft")
    return {
        "id": j.get("id", "mod"), "name": j.get("name") or j.get("id", "mod"),
        "version": str(j.get("version", "0.1.0")), "authors": [a for a in authors if a],
        "description": j.get("description", ""), "icon": icon,
        "entrypoints": ep, "minecraft": mc, "depends": j.get("depends") or {},
        "mixins": j.get("mixins") or [],
    }


def mc_to_levi(spec) -> str | None:
    """'~1.21' / '>=1.21 <1.22' / '1.21.x' -> '1.21.*' (best effort)."""
    if not spec:
        return None
    if isinstance(spec, list):
        spec = spec[0]
    m = re.search(r"(\d+)\.(\d+)", str(spec))
    return f"{m.group(1)}.{m.group(2)}.*" if m else None
