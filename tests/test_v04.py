"""v0.4: symbol DB, runtime resolver, pack packaging, so_probe / align tooling."""
import json, pathlib, shutil, subprocess, sys, zipfile
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]

from levipack_forge import bedrock_pack, generator, hooks
from levipack_forge.symbols import SymbolDB, SymbolIndex
import align_vtable as AV
import make_symbols_db as MK

DB_PATH = next((ROOT / "levipack_forge/data").glob("*.symbols.json"))
DB = json.loads(DB_PATH.read_text())
DUMP = ROOT / "symbols/source/vtables_dump.txt"
AMETHYST = ROOT / "symbols/source/amethyst-learnings.txt"
HELLO = ROOT / "tests/fixtures/hello.jar"
PUNCHY = ROOT / "mods/punchy-3.2b-fabric-26.3.jar"
HAS_GXX = shutil.which("g++") is not None


# ------------------------------------------------------------------ symbol DB
def test_db_is_keyed_by_build_and_static_entries_have_guards():
    assert len(DB["sha256"]) == 64 and DB["abi"] == "arm64-v8a" and DB["mc_version_confirmed"] is False
    static = {n: f for n, f in DB["functions"].items() if f["status"] == "static"}
    assert {"Item::getAttackDamage", "Item::getMaxDamage", "Item::isHandEquipped"} <= set(static)
    item_slots = DB["vtables"]["Item"][0]["slots"]
    for n, f in static.items():
        assert f["expect"] and f["index"] < item_slots, n
        assert f["index"] > f["msvc_index"], n           # Itanium has two destructor slots: never a negative shift


def test_static_entries_agree_with_the_dump_text():
    dump = AV.parse_dump(DUMP, "Item")
    for n, f in DB["functions"].items():
        if f["status"] != "static":
            continue
        first = dump[f["index"]][1][0].replace("#0000000000000000", "#0")
        assert first == f["expect_text"][0].replace("#0000000000000000", "#0"), n


def test_encoder_known_words():
    assert MK.encode("ret") == 0xD65F03C0
    assert MK.encode("mov w0, wzr") == 0x2A1F03E0
    assert MK.encode("ldr w0, [x0, #0x114]") == 0xB9411400
    assert MK.encode("strh w1, [x0, #0x110]") == 0x79022001


def test_encoder_matches_capstone():
    cs = pytest.importorskip("capstone")
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    norm = lambda s: s.replace("#0000000000000000", "#0").replace(" ", "")
    for n, f in DB["functions"].items():
        for w, t in zip(f.get("expect", []), f.get("expect_text", [])):
            i = next(md.disasm(int(w, 16).to_bytes(4, "little"), 0))
            assert norm(f"{i.mnemonic} {i.op_str}") == norm(t), (n, w)


def test_alignment_rediscovers_the_guides_verified_slots_unaided():
    """The shape DP, given NO anchors, lands on every slot the hooking guide verified by hand."""
    am, an = AV.parse_amethyst(AMETHYST, "Item"), AV.parse_dump(DUMP, "Item")
    pairs, _, _ = AV.align(am, an, {})
    for msvc, android in {5: 6, 24: 27, 25: 28, 30: 33, 34: 37, 35: 38, 36: 39, 37: 40}.items():
        assert pairs[msvc] == android, msvc
    assert pairs[118] == 132                              # last Amethyst virtual -> last Android slot


def test_slot_shift_is_not_constant():
    """The guide says unchecked slots shift by +1..+3. The binary says otherwise past slot ~40."""
    shifts = {r["msvc_from"]: r["shift"] for r in DB["shift_runs"]}
    assert max(r["shift"] for r in DB["shift_runs"]) >= 12
    f = DB["functions"]["Item::getDamageChance"]          # 100/(n+1) - unmistakable
    assert f["index"] - f["msvc_index"] == 12
    assert any(r["msvc_from"] <= 57 <= r["msvc_to"] and r["shift"] == 12 for r in DB["shift_runs"]), shifts


def test_candidates_are_never_usable_for_hooks():
    db = SymbolDB.load(DB_PATH)
    cand = next(iter(db.candidates))
    assert not db.usable(cand)
    assert not db.usable("Item::initServer")              # reported by the guide, no instruction evidence
    assert db.usable("Item::getAttackDamage")


def test_java_lookup_and_hints():
    idx = SymbolIndex.load(None)
    call = "unsupported call net.minecraft.world.item.Item.getMaxDamage()I"
    assert idx.targets_for(call) == ["Item::getMaxDamage"]
    assert "slot 37" in idx.hints_for(call)[0]
    assert idx.targets_for("unsupported call a.Player.jump()V") == []
    assert SymbolIndex.load(DB_PATH).targets_for(call) == ["Item::getMaxDamage"]   # a .json is accepted by --symbols


# ------------------------------------------------------------------ generated C++
def _render(tmp, ns="demo"):
    issues = [{"what": "unsupported call net.minecraft.world.item.Item.getMaxDamage()I", "category": "Items", "fix": "x"},
              {"what": "unsupported call a.b.Player.jump()V", "category": "Entities", "fix": "y"}]
    hh, hc = hooks.render(ns, issues, [], SymbolIndex.load(None))
    rh, rc = hooks.render_resolve(ns)
    d = tmp / "mod"; d.mkdir(parents=True)
    for n, t in (("Hooks.h", hh), ("Hooks.cpp", hc), ("Resolve.h", rh), ("Resolve.cpp", rc)):
        (d / n).write_text(t)
    return hc


def test_hooks_cpp_lists_only_needed_targets(tmp_path):
    hc = _render(tmp_path)
    rva = int(DB["vtables"]["Item"][0]["rva"], 16)
    assert f'{{"Item::getMaxDamage", "4Item", {rva}ull, 37, {{0x79422000u, 0xD65F03C0u}}' in hc
    assert "namespace hk_Item_getMaxDamage" in hc and "hk_Item_getAttackDamage" not in hc   # only what this mod needs
    assert "return orig(self);" in hc                                                        # default = pass-through


@pytest.mark.skipif(not HAS_GXX, reason="g++ not available")
def test_generated_cpp_is_valid_cpp20(tmp_path):
    _render(tmp_path)
    stub = ROOT / "tests/fixtures/stub"
    for src in ("Resolve.cpp", "Hooks.cpp"):
        r = subprocess.run(["g++", "-std=c++20", "-Wall", "-Wextra", "-fsyntax-only", f"-I{tmp_path}", f"-I{stub}",
                            str(tmp_path / "mod" / src)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


@pytest.mark.skipif(not HAS_GXX, reason="g++ not available")
def test_resolver_runtime_behaviour(tmp_path):
    _render(tmp_path)
    exe = tmp_path / "t"
    r = subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", f"-I{tmp_path}", str(ROOT / "tests/cpp/resolve_test.cpp"),
                        str(tmp_path / "mod/Resolve.cpp"), "-o", str(exe)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = subprocess.run([str(exe)], capture_output=True, text=True)
    assert out.returncode == 0 and "resolve tests ok" in out.stdout, out.stderr


def test_convert_emits_resolver_and_cmake_sources(tmp_path):
    generator.convert(HELLO, tmp_path / "o")
    cm = (tmp_path / "o/CMakeLists.txt").read_text()
    assert "src/mod/Resolve.cpp" in cm and "src/mod/Hooks.cpp" in cm
    assert (tmp_path / "o/src/mod/Resolve.h").exists()
    assert json.loads((tmp_path / "o/levipack.project.json").read_text())["symbol_db_build"] == DB["sha256"][:8]


# ------------------------------------------------------------------ resource-pack-free output
@pytest.mark.skipif(not PUNCHY.exists(), reason="bundled jar missing")
def test_generated_project_does_not_require_resource_pack(tmp_path):
    out = tmp_path / "o"
    result = generator.convert(PUNCHY, out)
    project = json.loads((out / "levipack.project.json").read_text())
    assert result["resource_pack_required"] is False
    assert project["resource_pack_required"] is False
    assert not (out / "resource_pack").exists()
    assert not (out / "resources/minecraft_resource_packs").exists()
    assert (out / "src/mod/Config.h").exists()
    assert "launcher-editable settings menu" in (out / "CONVERSION_REPORT.md").read_text()


def test_generated_project_keeps_only_optional_language_resources(tmp_path):
    generator.convert(HELLO, tmp_path / "o")
    assert not (tmp_path / "o/resources/minecraft_resource_packs").exists()


# ------------------------------------------------------------------ so_probe on a synthetic aarch64 ELF
@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    pytest.importorskip("elftools"); pytest.importorskip("numpy")
    import so_probe, elfsynth
    p = tmp_path_factory.mktemp("elf") / "libfake.so"
    p.write_bytes(elfsynth.build())
    f, e = so_probe.load(str(p))
    return so_probe, elfsynth, f, e, p


def test_probe_finds_vtable_through_rtti_and_relocations(probe):
    so, es, f, e, _ = probe
    vt, rm, _ = so.find_vtables(f, e, {"Item", "Actor"})
    assert vt == {"Item": [es.VPTR]}                       # Actor has no RTTI in the fake -> not invented
    assert [so.vslot(f, e, rm, es.VPTR, i) for i in range(3)] == es.FUNCS
    assert so.slot_count(f, e, rm, es.VPTR) == 3


def test_probe_dump_is_readable_by_the_aligner(probe, tmp_path):
    so, es, f, e, p = probe
    vt, rm, _ = so.find_vtables(f, e, {"Item"})
    out = tmp_path / "dump.txt"
    so.dump_vtables(f, e, rm, vt, out, "00" * 32)
    d = AV.parse_dump(out, "Item")
    assert sorted(d) == [0, 1, 2] and d[1][0] == es.FUNCS[1]
    assert d[0][1][0] == "mov w0, wzr"


def test_probe_verify_reports_ok_and_mismatch(probe):
    so, es, f, e, _ = probe
    _, rm, _ = so.find_vtables(f, e, {"Item"})
    db = {"vtables": {"Item": [{"rva": hex(es.VPTR)}]}, "functions": {
        "Item::a": {"status": "static", "vtable": "Item", "index": 0, "expect": ["0x2A1F03E0", "0xD65F03C0"]},
        "Item::b": {"status": "static", "vtable": "Item", "index": 1, "expect": ["0x2A1F03E0"]},      # wrong on purpose
        "Item::c": {"status": "candidate", "vtable": "Item", "index": 2}}}
    res = {n: s for n, s, _ in so.verify_db(f, e, rm, db)}
    assert res == {"Item::a": "OK", "Item::b": "MISMATCH", "Item::c": "SKIP"}


def test_probe_cli_verify_exit_code(probe, tmp_path):
    so, es, f, e, p = probe
    ok = {"sha256": so.file_sha256(str(p)), "vtables": {"Item": [{"rva": hex(es.VPTR)}]}, "functions": {
        "Item::a": {"status": "static", "vtable": "Item", "index": 0, "expect": ["0x2A1F03E0"]}}}
    (tmp_path / "ok.json").write_text(json.dumps(ok))
    r = subprocess.run([sys.executable, str(ROOT / "tools/so_probe.py"), str(p), "--verify", str(tmp_path / "ok.json")],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 0 and "all static slots verified" in r.stdout, r.stdout + r.stderr
    ok["functions"]["Item::a"]["expect"] = ["0xDEADBEEF"]
    (tmp_path / "bad.json").write_text(json.dumps(ok))
    r = subprocess.run([sys.executable, str(ROOT / "tools/so_probe.py"), str(p), "--verify", str(tmp_path / "bad.json")],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 1 and "MISMATCH" in r.stdout


def test_probe_signature_masks_pc_relative_bits_and_checks_alignment(probe):
    so, es, f, e, _ = probe
    import struct
    # bl +0x100 ; adrp x8, #0x1000 ; add x8,x8,#0x10 ; ret   (the middle two are an ADRP/ADD pair)
    buf = struct.pack("<4I", 0x94000040, 0x90000008, 0x91004108, 0xD65F03C0)
    data = bytearray(probe[4].read_bytes()); data[es.TEXT:es.TEXT + 16] = buf      # patch .text of a copy
    tmp = probe[4].with_name("libsig.so"); tmp.write_bytes(bytes(data))
    f2, e2 = so.load(str(tmp))
    sig = so.mask_sig(f2, e2, es.TEXT, n=4)
    toks = sig.split()
    # wildcards are per byte, so a word whose immediate straddles a byte is fully wild
    assert toks[:4] == ["??"] * 4                                    # BL imm26
    assert toks[4:8] == ["??"] * 4                                   # ADRP immlo/immhi
    assert toks[8:12] == ["08", "??", "??", "91"]                    # ADD imm12 (after ADRP) masked, rest kept
    assert toks[12:] == ["C0", "03", "5F", "D6"]                     # RET exact
    assert so.sig_unique(f2, e2, sig) == 1
    assert so.check_expect([1, 2, 3], ["0x1", "0x2"]) and not so.check_expect([1], ["0x1", "0x2"])


# ------------------------------------------------------------------ real SDK, live-test project, subclass probe
def test_generated_hooks_compile_against_the_real_preloader_sdk():
    """Fetches preloader-android 0.2.2 + fmt 11.2.0 (network); skipped when offline or without g++."""
    if not HAS_GXX or not shutil.which("git"):
        pytest.skip("g++/git missing")
    import check_sdk_compile
    rc = check_sdk_compile.main(["--cache", str(pathlib.Path(__import__("tempfile").gettempdir()) / "levipack-sdk")])
    if rc == 2:
        pytest.skip("SDK could not be fetched (offline)")
    assert rc == 0


def test_live_test_project(tmp_path):
    from levipack_forge import cli
    out = tmp_path / "lt"
    assert cli.main(["live-test", "-o", str(out), "--bonus", "5"]) == 0
    hc = (out / "src/mod/Hooks.cpp").read_text()
    assert "const int r = base + 5;" in hc and "namespace hk_Item_getAttackDamage" in hc
    assert '"Item::getAttackDamage", "4Item"' in hc and "::origs), true}," in hc   # body supplied -> ported
    notes = (out / "LIVE_TEST.md").read_text()
    assert "levilamroid.log" in notes and "no subclass data yet" in notes          # honest about the missing subclass data
    assert "src/mod/Resolve.cpp" in (out / "CMakeLists.txt").read_text()
    assert not list(tmp_path.glob(".*overrides.json"))                              # temp overrides cleaned up


def test_hook_override_for_unverified_function_fails_loudly():
    with pytest.raises(ValueError, match="no statically verified slot"):
        hooks.render("demo", [], [], SymbolIndex.load(None), {"Item::isGlint": {"cpp": "return true;"}})


def test_probe_finds_subclasses_and_records_overrides(probe, tmp_path):
    so, es, f, e, p = probe
    _, rm, _ = so.find_vtables(f, e, {"Item"})
    rep = so.subclass_report(f, e, rm, "Item", es.VPTR, [0, 1, 2])
    by = {r["class"]: r for r in rep}
    assert set(by) == {"Sword", "Blade"}                                   # direct subclass and grandchild
    assert by["Blade"]["parent"] == "Sword"
    assert list(by["Sword"]["overrides"]) == ["1"]                         # only slot 1 differs from Item's vtable
    ov = by["Sword"]["overrides"]["1"]
    assert ov["target_rva"] == hex(es.F3_VA) and ov["expect"][0] == "0x52800C88"


def test_probe_cli_subclasses_merge_feeds_the_generator(probe, tmp_path):
    so, es, f, e, p = probe
    db = {"sha256": "cd" * 32, "vtables": {"Item": [{"rva": hex(es.VPTR), "slots": 3}]},
          "functions": {"Item::getAttackDamage": {"kind": "virtual", "vtable": "Item", "index": 1, "status": "static",
                                                  "expect": ["0xB9411400", "0xD65F03C0"], "cpp_ret": "int", "cpp_params": []}}}
    dbp = tmp_path / "db.json"; dbp.write_text(json.dumps(db))
    r = subprocess.run([sys.executable, str(ROOT / "tools/so_probe.py"), str(p), "--subclasses", "Item", "--db", str(dbp), "--merge"],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 0 and "merged into" in r.stdout, r.stdout + r.stderr
    merged = SymbolDB.load(dbp)
    assert merged.subclasses_analysed("Item")
    assert {o["class"] for o in merged.overrides_for("Item::getAttackDamage")} == {"Sword", "Blade"}
    _, hc = hooks.render("demo", [], [], SymbolIndex([], merged), {"Item::getAttackDamage": {}})
    assert hc.count("ull, {0x5280") == 2                                    # both override guards reach the generated table


def test_probe_verify_quiet_hides_ok_lines(probe, tmp_path):
    so, es, f, e, p = probe
    db = {"sha256": so.file_sha256(str(p)), "vtables": {"Item": [{"rva": hex(es.VPTR)}]}, "functions": {
        "Item::a": {"status": "static", "vtable": "Item", "index": 0, "expect": ["0x2A1F03E0"]}}}
    (tmp_path / "d.json").write_text(json.dumps(db))
    r = subprocess.run([sys.executable, str(ROOT / "tools/so_probe.py"), str(p), "--verify", str(tmp_path / "d.json"), "--quiet"],
                       capture_output=True, text=True, cwd=tmp_path)
    assert "Item::a" not in r.stdout and "all static slots verified" in r.stdout
