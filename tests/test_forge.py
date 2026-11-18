import json, os, pathlib, subprocess, shutil, sys, zipfile, tempfile
import pytest
from levipack_forge import classfile, fabricmeta, generator, symbols
from levipack_forge.transpile import cstr

FIX = pathlib.Path(__file__).parent / "fixtures" / "hello.jar"


def test_cstr_escapes():
    assert cstr('a"b\\n') == '"a\\"b\\\\n"'


def test_fabric_meta():
    m = fabricmeta.parse(json.dumps({"id": "x", "entrypoints": {"main": ["a.B", "a.C::go"]},
                                     "authors": [{"name": "N"}, "M"]}))
    assert m["entrypoints"]["main"] == [("a/B", None), ("a/C", "go")]
    assert m["authors"] == ["N", "M"]


@pytest.mark.skipif(not FIX.exists(), reason="fixture jar missing")
def test_parse_and_convert(tmp_path):
    with zipfile.ZipFile(FIX) as z:
        cf = classfile.parse(z.read("com/example/hello/HelloMod.class"))
    assert cf.name == "com/example/hello/HelloMod"
    r = generator.convert(FIX, tmp_path / "out")
    cpp = (tmp_path / "out/src/mod/MyMod.cpp").read_text()
    assert 'self.getLogger().info("Hello Fabric world!");' in cpp
    assert "mConfig.greeting" in cpp
    assert 'self.getLogger().warn("Bye");' in cpp        # lifecycle STOPPING -> disable()
    assert "TODO(levipack-forge)" in cpp                # loop was not silently dropped
    assert r["config_fields"] == 8   # 3 in HelloMod + 5 finite statics in Nasty
    cm = (tmp_path / "out/CMakeLists.txt").read_text()
    assert 'set(MOD_ID "hello_mod" CACHE' in cm


def test_symbol_search():
    idx = symbols.SymbolIndex(["_ZN6Player4jumpEv", "_ZN5Actor4hurtEv"])
    assert idx.search("Player", "jump") == ["_ZN6Player4jumpEv"]
    assert idx.hints_for("unsupported call net.minecraft.Player.jump()V") == ["_ZN6Player4jumpEv"]


def test_rescue_truncated_zip(tmp_path):
    big = os.urandom(1000) + b"_ZN6Player4jumpEv\x00" + b"A" * 200000
    full = tmp_path / "f.zip"
    with zipfile.ZipFile(full, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("libminecraftpe.so", big)
    cut = tmp_path / "cut.zip"
    cut.write_bytes(full.read_bytes()[:-200])           # chop central directory
    assert "_ZN6Player4jumpEv" in symbols.build_index(cut)


@pytest.mark.skipif(not FIX.exists(), reason="fixture jar missing")
def test_config_defaults_are_valid_cpp(tmp_path):
    generator.convert(FIX, tmp_path / "out")
    h = (tmp_path / "out/src/mod/Config.h").read_text()
    assert "= nan" not in h and "= inf" not in h          # NaN/Infinity statics are skipped
    assert "delete_ = 1" in h and "register_ = true" in h  # C++ keywords are renamed
    assert "(-9223372036854775807LL - 1)" in h


# ---------------------------------------------------------------- manual-work solver
from levipack_forge.transpile import Transpiler


def test_report_has_sections_and_todo_files(tmp_path):
    generator.convert(FIX, tmp_path / "out")
    rep = (tmp_path / "out/CONVERSION_REPORT.md").read_text()
    assert "### Auto-resolved" in rep and "How to solve the open items" in rep
    assert (tmp_path / "out/MANUAL_WORK.md").exists()
    assert not (tmp_path / "out/overrides.todo.json").exists()
    assert "Native implementation checklist" in (tmp_path / "out/MANUAL_WORK.md").read_text()
    project = json.loads((tmp_path / "out/levipack.project.json").read_text())
    assert project["resource_pack_required"] is False and project["mod_menu"]["type"] == "launcher_config"


def _mod_jar_calling(tmp_path, snippet_calls):
    """Real jars are the best fixtures; here we only check the override plumbing on the sample jar."""
    return FIX


@pytest.mark.skipif(not FIX.exists(), reason="fixture jar missing")
def test_conversion_does_not_require_overrides(tmp_path):
    generator.convert(FIX, tmp_path / "out")
    assert not (tmp_path / "out/overrides.todo.json").exists()
    assert not (tmp_path / "out/overrides").exists()


def test_fabric_loader_calls_fold_to_constants():
    from levipack_forge import classfile as C
    t = Transpiler({}, meta={"id": "m", "name": "M", "version": "9.9"}, mod_id="m")
    lines = []
    # isModLoaded("m") is true, isModLoaded("jei") is false: no stub, no TODO
    assert t._fabric("w", "net/fabricmc/loader/api/FabricLoader", "isModLoaded", "(Ljava/lang/String;)Z",
                     ("loader",), [("str", "m")], 0, lines) == ("int", 1)
    assert t._fabric("w", "net/fabricmc/loader/api/FabricLoader", "isModLoaded", "(Ljava/lang/String;)Z",
                     ("loader",), [("str", "jei")], 0, lines) == ("int", 0)
    opt = t._fabric("w", "net/fabricmc/loader/api/FabricLoader", "getModContainer", "(Ljava/lang/String;)Ljava/util/Optional;",
                    ("loader",), [("str", "m")], 0, lines)
    cont = t._fabric("w", "java/util/Optional", "orElseThrow", "()Ljava/lang/Object;", opt, [], 0, lines)
    meta = t._fabric("w", "net/fabricmc/loader/api/ModContainer", "getMetadata", "()X", cont, [], 0, lines)
    ver = t._fabric("w", "net/fabricmc/loader/api/metadata/ModMetadata", "getVersion", "()X", meta, [], 0, lines)
    s = t._fabric("w", "net/fabricmc/loader/api/Version", "getFriendlyString", "()X", ver, [], 0, lines)
    assert s == ("str", "9.9") and not t.res.issues


def test_override_returns_and_ignore():
    t = Transpiler({}, overrides={"calls": {"a.B.c": {"returns": {"bool": True}}, "a.B.d": {"ignore": True, "reason": "x"}}})
    lines = []
    assert t._call(None, "w", 184, "a/B", "c", "()Z", None, [], 0, lines) == ("int", 1)
    t._call(None, "w", 184, "a/B", "d", "()V", None, [], 0, lines)
    assert any("ignored by internal mapping" in l for l in lines) and not t.res.issues


# ------------------------------------------------ v0.3: hooks, commands, bedrock resource pack
from levipack_forge import bedrock_pack, commands as cmdmod

PUNCHY = pathlib.Path(__file__).parent.parent / "mods" / "punchy-3.2b-fabric-26.3.jar"


def test_state_rules_pick_one_animation_per_state(tmp_path):
    files = {"a/x.animation.json": json.dumps({"format_version": "1.8.0", "animations": {
        "walk_on_water_loop": {"animation_length": 1, "bones": {"right_arm": {"rotation": {"0": [0, 0, 0]}}}},
        "my_sprint": {"animation_length": 1, "bones": {"camera": {"rotation": {"0": [0, 0, 0]}}, "left_arm": {}}},
        "disable_idle": {"animation_length": 1}}}).encode()}
    meta = {"name": "T", "version": "1.2b", "description": "First-person animations", "icon": None}
    rep = bedrock_pack.build_pack(files, meta, "t", tmp_path)
    patch = json.loads((tmp_path / "player.entity.patch.json").read_text())
    assert "t_my_sprint" in patch["animations"] and "t_walk_on_water_loop" not in patch["animations"]
    assert rep["dropped_bones"] == {"camera": 1}          # reported, not silent
    assert rep["problems"] == []
    ctl = json.loads((tmp_path / "animation_controllers/t.animation_controllers.json").read_text())
    cond = ctl["animation_controllers"]["controller.animation.t.my_sprint"]["states"]["default"]["transitions"][0]["active"]
    assert "variable.is_first_person" in cond and "query.is_sprinting" in cond
    man = json.loads((tmp_path / "manifest.json").read_text())
    assert man["header"]["version"] == [1, 2, 0] and man["modules"][0]["type"] == "resources"


def test_animation_conditions_override(tmp_path):
    files = {"a.animation.json": json.dumps({"animations": {"hop": {"animation_length": 1}}}).encode()}
    meta = {"name": "T", "version": "1", "description": "", "icon": None}
    bedrock_pack.build_pack(files, meta, "t", tmp_path, overrides={"animation_conditions": {"hop": "query.is_jumping"}})
    ctl = json.loads((tmp_path / "animation_controllers/t.animation_controllers.json").read_text())
    assert "query.is_jumping" in json.dumps(ctl)


def test_merge_player_entity():
    van = {"minecraft:client_entity": {"description": {"animations": {"a": "animation.a"}, "scripts": {"animate": ["a"]}}}}
    out = bedrock_pack.merge_player_entity(van, {"animations": {"t_x": "animation.t.x"}, "animate": [{"t_x": "1.0"}],
                                                 "sound_effects": {"s": "t.s"}})
    d = out["minecraft:client_entity"]["description"]
    assert d["animations"]["t_x"] == "animation.t.x" and {"t_x": "1.0"} in d["scripts"]["animate"] and d["sound_effects"]["s"] == "t.s"


@pytest.mark.skipif(not PUNCHY.exists(), reason="punchy jar missing")
def test_punchy_commands_and_mod_menu(tmp_path):
    classes, files = generator.load_jar(PUNCHY)
    cmds, _ = cmdmod.find_commands(classes)
    assert [c["sub"] for c in cmds] == ["debugposition", "pos", "rot", "scale"]
    r = generator.convert(PUNCHY, tmp_path / "o")
    assert r["config_fields"] <= generator.MAX_CONFIG_FIELDS          # command fields reserved their slots
    assert 'bool cmd_debugposition' in (tmp_path / "o/src/mod/Config.h").read_text()
    cm = (tmp_path / "o/CMakeLists.txt").read_text()
    assert "src/mod/Hooks.cpp" in cm
    assert "hooks::installAll(self);" in (tmp_path / "o/src/mod/MyMod.cpp").read_text()
    assert r["mod_menu"] is True and r["resource_pack_required"] is False
    assert not (tmp_path / "o/resource_pack").exists()

@pytest.mark.skipif(not FIX.exists(), reason="fixture jar missing")
def test_mixin_classes_are_reported_as_native_hook_tasks(tmp_path):
    jar = tmp_path / "with-mixin.jar"
    with zipfile.ZipFile(FIX) as src, zipfile.ZipFile(jar, "w") as dst:
        for item in src.infolist():
            if item.filename != "fabric.mod.json":
                dst.writestr(item, src.read(item.filename))
        meta = json.loads(src.read("fabric.mod.json"))
        meta["mixins"] = ["hello.mixins.json"]
        dst.writestr("fabric.mod.json", json.dumps(meta))
        dst.writestr("hello.mixins.json", json.dumps({"package": "com.example.mixin", "mixins": ["PlayerMixin"]}))
    out = tmp_path / "out"
    generator.convert(jar, out)
    report = (out / "CONVERSION_REPORT.md").read_text()
    assert "Mixin injection" in report
    assert "com/example/mixin/PlayerMixin" in report
    assert "Java asset inventory" in report
