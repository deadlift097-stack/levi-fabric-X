"""Generated Hooks.cpp executed against a fake libminecraftpe.so + mocked preloader (host g++)."""
import pathlib, shutil, subprocess, pytest
from levipack_forge import hooks
from levipack_forge.symbols import SymbolDB, SymbolIndex

ROOT = pathlib.Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("g++") is None, reason="g++ not available")


def fake_db():
    w = ["0x2A1F03E0", "0xD65F03C0"]
    return SymbolDB({"sha256": "ab" * 32, "vtables": {"Item": [{"rva": "0x1000", "slots": 20}]},
                     "functions": {"Item::getAttackDamage": {
                         "kind": "virtual", "vtable": "Item", "index": 5, "status": "static", "expect": w,
                         "cpp_ret": "int", "cpp_params": []}},
                     "subclasses": {"Item": [
                         {"class": "Sword", "vptr_rva": "0x2000", "overrides": {"5": {"target_rva": "0x4100", "expect": ["0x11111111", "0x22222222"]}}},
                         {"class": "Axe", "vptr_rva": "0x2100", "overrides": {"5": {"target_rva": "0x4100", "expect": ["0x11111111", "0x22222222"]}}},
                         {"class": "Plain", "vptr_rva": "0x2200", "overrides": {}}]}})


def test_subclass_overrides_are_deduplicated():
    assert [o["class"] for o in fake_db().overrides_for("Item::getAttackDamage")] == ["Sword"]


def test_runtime(tmp_path):
    sym = SymbolIndex([], fake_db())
    hh, hc = hooks.render("demo", [], [], sym, {"Item::getAttackDamage": {"cpp": "return orig(self) + 3;"}})
    rh, rc = hooks.render_resolve("demo")
    d = tmp_path / "mod"; d.mkdir()
    for n, t in (("Hooks.h", hh), ("Hooks.cpp", hc), ("Resolve.h", rh), ("Resolve.cpp", rc)):
        (d / n).write_text(t)
    exe = tmp_path / "t"
    r = subprocess.run(["g++", "-std=c++20", "-Wall", "-Wextra", f"-I{tmp_path}", f"-I{ROOT/'tests/fixtures/stub'}",
                        str(ROOT / "tests/cpp/hooks_runtime_test.cpp"), str(d / "Hooks.cpp"), str(d / "Resolve.cpp"),
                        "-o", str(exe)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = subprocess.run([str(exe)], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0 and "hooks runtime ok" in out.stdout, out.stderr + out.stdout


def test_unknown_hook_override_is_rejected():
    with pytest.raises(ValueError, match="no statically verified slot"):
        hooks.render("demo", [], [], SymbolIndex.load(None), {"Item::isGlint": {"cpp": "return true;"}})
