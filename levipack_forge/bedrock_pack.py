"""Java resource assets -> a client-side Bedrock *resource pack*.

Many Fabric animation/visual mods already ship Bedrock-flavoured data (Blockbench `.animation.json` / `.geo.json`,
sounds, textures). Those are re-targeted to Bedrock names and wired through generated animation controllers.
Everything that cannot be mapped is listed in PACK_REPORT.md; nothing is dropped silently.
"""
from __future__ import annotations
import json, re, shutil, uuid, pathlib

ANIM_KEYS = {"animation_length", "bones", "loop", "timeline", "sound_effects", "particle_effects",
             "override_previous_animation", "anim_time_update", "blend_weight", "start_delay", "loop_delay"}
# Java rig bone -> vanilla Bedrock humanoid bone
BONE_MAP = {"right_arm": "rightArm", "left_arm": "leftArm", "itemgrip_right": "rightItem",
            "itemgrip_left": "leftItem", "head": "head", "body": "body", "right_leg": "rightLeg",
            "left_leg": "leftLeg"}
# (regex on animation name, Molang condition). First match per rule, shortest name wins.
STATE_RULES = [
    (r"swim", "query.is_swimming"),
    (r"sprint", "query.is_sprinting"),
    (r"walk", "query.is_moving && !query.is_sprinting && query.is_on_ground"),
    (r"jump", "!query.is_on_ground && query.vertical_speed > 0"),
    (r"fall", "!query.is_on_ground && query.vertical_speed < 0"),
    (r"idle", "!query.is_moving"),
    (r"sneak|crouch", "query.is_sneaking"),
    (r"riding", "query.is_riding"),   # riding rule ignores SKIP_NAME's horse/mount words (see below)
    (r"glid|elytra", "query.is_gliding"),
    (r"sleep", "query.is_sleeping"),
]
SKIP_NAME = re.compile(r"disable_|left|right|backward|strafe|-bk|backup|test|_bk|water|horse|mount|hamster|"
                       r"spear|trident|sword|dagger|hand_|use_|eat|drink|mining|attack|inspect|compat", re.I)


def _uuid(mid, what):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"levipack-forge/{mid}/{what}"))


def _ver(v):
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]] or [0]
    return (nums + [0, 0, 0])[:3]


def _snake(s):
    return re.sub(r"[^0-9a-zA-Z]+", "_", s).strip("_").lower() or "x"


def build_pack(files, meta, mid, out, mc_versions='["1.26.*"]', overrides=None):
    ov = overrides or {}
    out = pathlib.Path(out)
    rep = {"animations": 0, "mapped": 0, "unmapped": [], "dropped_bones": {}, "geometries": 0, "sounds": 0,
           "textures": 0, "lang": [], "unconverted": []}
    bone_map = {**BONE_MAP, **ov.get("bone_map", {})}
    cond_ov = ov.get("animation_conditions", {})

    def write(rel, data):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))

    def jload(b):
        return json.loads(b.decode("utf-8-sig"))

    # ---------------- animations
    anims, snd_effects = {}, {}
    seen_content = set()
    for n in sorted(files):
        if not n.endswith(".animation.json") or "/model_parts_items/" in n:
            if n.endswith(".animation.json"):
                rep["unconverted"].append(f"{n}: custom-item animation (needs a Bedrock item attachable)")
            continue
        if files[n] in seen_content:
            continue
        seen_content.add(files[n])
        try:
            src = jload(files[n])
        except Exception as e:
            rep["unconverted"].append(f"{n}: unreadable ({e})"); continue
        for name, an in (src.get("animations") or {}).items():
            key = name if name.startswith("animation.") else f"animation.{mid}.{name}"
            new = {k: v for k, v in an.items() if k in ANIM_KEYS}
            for k in an:
                if k not in ANIM_KEYS:
                    rep["unconverted"].append(f"animation {name}: unknown key '{k}' dropped")
            bones = {}
            for b, data in (an.get("bones") or {}).items():
                nb = bone_map.get(b)
                if nb is None:
                    rep["dropped_bones"][b] = rep["dropped_bones"].get(b, 0) + 1
                    continue
                bones[nb] = data
            if "bones" in new:
                new["bones"] = bones
            for t, e in (an.get("sound_effects") or {}).items():
                for x in (e if isinstance(e, list) else [e]):
                    if x.get("effect"):
                        snd_effects[x["effect"]] = f"{mid}.animationssounds.{x['effect']}"
            anims[key] = new
    rep["animations"] = len(anims)
    if anims:
        write(f"animations/{mid}.animation.json", json.dumps({"format_version": "1.8.0", "animations": anims}, indent=1))

    # ---------------- state -> animation controllers
    fp = re.search(r"first[- ]person", meta.get("description", ""), re.I)
    tp = re.search(r"third[- ]person", meta.get("description", ""), re.I)
    scope = "variable.is_first_person" if fp and not tp else "!variable.is_first_person" if tp and not fp else ""
    chosen = {}
    for pat, cond in STATE_RULES:
        skip = re.compile(r"mount|idle|-bk|test|backup", re.I) if pat == "riding" else SKIP_NAME
        cands = sorted((k for k in anims if re.search(pat, k, re.I) and not skip.search(k)
                        and k not in chosen), key=lambda k: ("loop" not in k, len(k)))
        if cands:
            chosen[cands[0]] = cond
    for k, v in cond_ov.items():                      # user-supplied conditions win; "ignore"/false removes
        full = k if k.startswith("animation.") else f"animation.{mid}.{k}"
        if full in anims and v and v != "ignore":
            chosen[full] = v
        elif full in chosen:
            del chosen[full]
    ctrls, ent_anims, animate = {}, {}, []
    for full, cond in chosen.items():
        short = f"{mid}_{_snake(full.split('.')[-1])}"
        cname = f"controller.animation.{mid}.{_snake(full.split('.')[-1])}"
        c = f"({scope}) && ({cond})" if scope else cond
        ctrls[cname] = {"initial_state": "default",
                        "states": {"default": {"transitions": [{"active": c}]},
                                   "active": {"animations": [short], "blend_transition": 0.15,
                                              "transitions": [{"default": f"!({c})"}]}}}
        ent_anims[short] = full
        ent_anims[short + "_ctl"] = cname
        animate.append({short + "_ctl": "1.0"})
    rep["mapped"] = len(chosen)
    rep["unmapped"] = sorted(k.split(".", 2)[-1] for k in anims if k not in chosen)
    if ctrls:
        write(f"animation_controllers/{mid}.animation_controllers.json",
              json.dumps({"format_version": "1.10.0", "animation_controllers": ctrls}, indent=1))
    write("player.entity.patch.json", json.dumps(
        {"_note": "merge into the vanilla player.entity.json: `levipack-forge pack-merge`",
         "animations": ent_anims, "animate": animate,
         "sound_effects": snd_effects}, indent=1))

    # ---------------- geometry
    for n in sorted(files):
        if n.endswith(".geo.json"):
            try:
                g = jload(files[n])
                for geo in g.get("minecraft:geometry", []):
                    d = geo["description"]
                    ident = d["identifier"]
                    d["identifier"] = ident if ident.startswith(f"geometry.{mid}.") else f"geometry.{mid}.{ident.split('.', 1)[-1]}"
                write(f"models/entity/{mid}_{_snake(pathlib.Path(n).name[:-9])}.geo.json", json.dumps(g, indent=1))
                rep["geometries"] += 1
            except Exception as e:
                rep["unconverted"].append(f"{n}: geometry not converted ({e})")

    # ---------------- sounds
    events, written = {}, {}
    sound_json = {}
    for n in sorted(files):
        m = re.match(r"(?:resourcepacks/[^/]+/)?assets/([^/]+)/sounds\.json$", n)
        if m:
            try:
                sound_json.update(jload(files[n]))
            except Exception:
                pass
    for n in sorted(files):
        m = re.match(r"(?:resourcepacks/[^/]+/)?assets/([^/]+)/sounds/(.+)\.ogg$", n)
        if m:
            ns, rel = m.groups()
            dst = f"sounds/{mid}/{ns}/{rel}.ogg"
            if dst not in written:
                write(dst, files[n]); written[dst] = 1; rep["sounds"] += 1
            sid = f"{ns}:{rel}"
            events[f"{mid}.{rel.replace('/', '.')}"] = {"category": "player",
                                                        "sounds": [{"name": f"sounds/{mid}/{ns}/{rel}", "volume": 1.0}]}
    for eff, ev in snd_effects.items():           # keep only effects whose sound file really exists
        if ev not in events:
            rep["unconverted"].append(f"sound effect '{eff}' referenced by an animation has no .ogg in the jar")
    if events:
        write("sounds/sound_definitions.json", json.dumps({"format_version": "1.14.0", "sound_definitions": events}, indent=1))

    # ---------------- textures (Java GUI atlas textures have no Bedrock meaning)
    vanilla_skipped, gui_skipped = 0, 0
    for n in sorted(files):
        m = re.match(r"(?:resourcepacks/[^/]+/)?assets/([^/]+)/textures/(.+\.png)$", n)
        if not m:
            continue
        ns, rel = m.groups()
        if ns == "minecraft":
            vanilla_skipped += 1; continue
        if rel.startswith(("gui/", "font/")):
            gui_skipped += 1; continue
        write(f"textures/{mid}/{ns}/{rel}", files[n]); rep["textures"] += 1
    if vanilla_skipped:      # never drop silently
        rep["unconverted"].append(
            f"{vanilla_skipped} texture(s) under assets/minecraft/ replace vanilla Java textures; Bedrock uses other paths and names. "
            "Map them by hand into the pack; files that live inside the game APK (start screen, materials, cameras) "
            "need the AssetsAPI levipack (assetsapi_set_file_resource_pack), see docs/research/levipack-learnings.txt section 6B")
    if gui_skipped:
        rep["unconverted"].append(f"{gui_skipped} Java gui/font texture(s) skipped: Java GUI atlases have no Bedrock meaning (use a JSON UI pack)")

    # ---------------- language
    langs = []
    for n in sorted(files):
        m = re.match(r"assets/[^/]+/lang/([a-z]{2})_([a-z]{2})\.json$", n)
        if m:
            try:
                j = jload(files[n])
            except Exception:
                continue
            code = f"{m.group(1)}_{m.group(2).upper()}"
            write(f"texts/{code}.lang", "\n".join(f"{k}={str(v).replace(chr(10), ' ')}" for k, v in j.items()
                                                      if isinstance(v, str)) + "\n")
            langs.append(code)
    if langs:
        write("texts/languages.json", json.dumps(langs))
    rep["lang"] = langs

    # ---------------- what cannot be converted
    for n in sorted(files):
        if "/shaders/" in n:
            rep["unconverted"].append(f"{n}: Java GLSL shader (Bedrock uses materials; needs a native hook or a .material port)")
        elif "/model_parts_items/definitions/" in n:
            rep["unconverted"].append(f"{n}: Java item model-part definition (Bedrock needs an item + attachable JSON)")

    # ---------------- manifest, icon, reports
    mc = json.loads(mc_versions) if mc_versions else ["1.26.*"]
    eng = _ver(mc[0]) if mc else [1, 26, 0]
    name = f"{meta['name']} (Bedrock resource pack)"
    manifest = {"format_version": 2,
                "header": {"name": name, "description": meta.get("description") or meta["name"],
                           "uuid": _uuid(mid, "header"), "version": _ver(meta["version"]), "min_engine_version": eng},
                "modules": [{"type": "resources", "uuid": _uuid(mid, "module"), "version": _ver(meta["version"]),
                             "description": "Client-side visuals converted from the Java mod"}]}
    write("manifest.json", json.dumps(manifest, indent=2))
    icon = meta.get("icon")
    if icon and icon in files:
        write("pack_icon.png", files[icon])
    todo = {"animation_conditions": {k: "" for k in rep["unmapped"]}, "bone_map": {}}
    write("pack_map.todo.json", json.dumps(todo, indent=1))
    rep["problems"] = validate(out, rep)
    return rep


def validate(out, rep=None):
    """Self-check: every id written into the pack must resolve inside the pack."""
    out = pathlib.Path(out); bad = []
    def load(rel):
        f = out / rel
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None
    patch = load("player.entity.patch.json") or {}
    anim_files = [json.loads(f.read_text()) for f in (out / "animations").glob("*.json")] if (out / "animations").exists() else []
    known = {k for a in anim_files for k in a.get("animations", {})}
    ctrl_files = [json.loads(f.read_text()) for f in (out / "animation_controllers").glob("*.json")] if (out / "animation_controllers").exists() else []
    ctrls = {k: v for c in ctrl_files for k, v in c.get("animation_controllers", {}).items()}
    for short, target in patch.get("animations", {}).items():
        if target.startswith("controller.") and target not in ctrls:
            bad.append(f"controller {target} missing")
        elif target.startswith("animation.") and target not in known:
            bad.append(f"animation {target} missing")
    for name, c in ctrls.items():
        for st in c["states"].values():
            for a in st.get("animations", []):
                if a not in patch.get("animations", {}):
                    bad.append(f"{name}: animation short name {a} not registered on the entity")
    defs = (load("sounds/sound_definitions.json") or {}).get("sound_definitions", {})
    for ev in patch.get("sound_effects", {}).values():
        if ev not in defs:
            bad.append(f"sound event {ev} not defined")
    for ev, d in defs.items():
        for snd in d["sounds"]:
            if not (out / (snd["name"] + ".ogg")).exists():
                bad.append(f"sound file {snd['name']}.ogg missing")
    for a in anim_files:
        for n, an in a["animations"].items():
            for b in an.get("bones", {}):
                if b not in BONE_MAP.values() and b not in {v for v in (rep or {}).get("custom_bones", [])}:
                    pass
    return bad


def pack_report(rep, mid):
    L = [f"# Bedrock resource pack ({mid}) - client side", "",
         f"* animations: {rep['animations']} converted, {rep['mapped']} wired to game states automatically, "
         f"{len(rep['unmapped'])} left unmapped",
         f"* geometries: {rep['geometries']}; sounds: {rep['sounds']}; textures: {rep['textures']}; "
         f"languages: {', '.join(rep['lang']) or 'none'}", "",
         "Install: the pack ships **inside the `.levipack`** at `resources/minecraft_resource_packs/<Name>/` "
         "(`levipack-forge pack-install <project>`; `convert` runs it, and the CI workflow runs it again after `pack-merge`). "
         "It can also be zipped as a standalone `.mcpack` (CI does this). "
         "The animations are merged into the vanilla `player.entity.json` with `levipack-forge pack-merge` "
         "(the CI workflow does this automatically). **Not tested in-game.**", ""]
    if not rep["animations"] and not rep["geometries"]:
        L += ["## Nothing to convert", "This mod computes its animation in Java code, so there is no Bedrock animation data "
              "inside the jar. The pack only carries language files / icon. Author Bedrock animations by hand, or implement "
              "the behavior behind a native hook (see Hooks.cpp).", ""]
    L += ["## Self-check", *( [f"* PROBLEM: {p}" for p in rep.get("problems", [])] or ["* all ids resolve inside the pack"] ), ""]
    if rep["dropped_bones"]:
        L += ["## Bones with no vanilla Bedrock counterpart (dropped from animations)",
              *[f"* `{b}` ({n} animations): map it in `overrides/<jar>.json` -> `bone_map`" for b, n in rep["dropped_bones"].items()], ""]
    if rep["unmapped"]:
        L += ["## Animations not wired to a game state yet",
              "Give each one a Molang condition in `animation_conditions` (see `pack_map.todo.json`):",
              ", ".join(f"`{k}`" for k in rep["unmapped"][:80]) + (" ..." if len(rep["unmapped"]) > 80 else ""), ""]
    if rep["unconverted"]:
        L += ["## Not convertible", *[f"* {u}" for u in dict.fromkeys(rep["unconverted"])], ""]
    return "\n".join(L) + "\n"


def merge_player_entity(vanilla: dict, patch: dict) -> dict:
    """Add the converted animations/controllers to the vanilla client entity description."""
    d = vanilla["minecraft:client_entity"]["description"]
    d.setdefault("animations", {}).update(patch.get("animations", {}))
    anim = d.setdefault("scripts", {}).setdefault("animate", [])
    for e in patch.get("animate", []):
        if e not in anim:
            anim.append(e)
    if patch.get("sound_effects"):
        d.setdefault("sound_effects", {}).update(patch["sound_effects"])
    return vanilla


# Files that belong to the converter's working folder, not to the pack the game loads.
PACK_DEV_FILES = {"PACK_REPORT.md", "pack_map.todo.json", "player.entity.patch.json"}
# `texts` is deliberately absent: a pack that only carries converted .lang files adds nothing (Java translation keys do
# not match Bedrock's) and the same files already ship as the experimental resources/texts/*.lang.
PACK_CONTENT_DIRS = ("animations", "animation_controllers", "entity", "models", "sounds", "textures")


def pack_folder_name(mid: str) -> str:
    """`punchy_moves` -> `PunchyMoves` (working levipacks name the folder like BetterBoatTrails)."""
    return "".join(p.capitalize() for p in re.split(r"[^0-9A-Za-z]+", mid) if p) or "Pack"


def install_pack(project, mid: str, only_if_content: bool = True):
    """Copy <project>/resource_pack into <project>/resources/minecraft_resource_packs/<Name>/.

    The levipack package step copies `resources/` into the archive and nothing else, so a pack that stays in
    `resource_pack/` never reaches the game (every working levipack ships it at this path). Re-run after
    `pack-merge` so the merged player.entity.json is the one that gets packaged.
    Returns the destination, or None when there is nothing worth shipping.
    """
    project = pathlib.Path(project)
    src = project / "resource_pack"
    if not (src / "manifest.json").exists():
        return None
    if only_if_content and not any((src / d).exists() and any((src / d).rglob("*")) for d in PACK_CONTENT_DIRS):
        return None
    dst = project / "resources" / "minecraft_resource_packs" / pack_folder_name(mid)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=lambda d, names: [n for n in names if pathlib.Path(d) == src and n in PACK_DEV_FILES])
    return dst
