"""`levipack-forge live-test`: a minimal levipack that proves the whole hook chain on a real device.

It hooks Item::getAttackDamage (and, when the symbol DB knows them, every subclass override of that slot), adds
`bonus` to the result and logs the first calls. If the log shows the lines and the damage changes, then: build check,
module base, vtable slot mapping, prologue guard, the preloader hook and the detour dispatch are all proven.
"""
from __future__ import annotations
import json, pathlib, tempfile, zipfile
from .generator import convert
from .symbols import SymbolDB, SymbolIndex
from . import hooks as hookmod

BODY = """static std::atomic<int> calls{0};
    const int base = orig(self);
    const int r = base + @BONUS@;
    if (calls.fetch_add(1) < 40)
        modLog().info("[live-test] Item::getAttackDamage hook #{} self={} {} -> {}", K, self, base, r);
    return r;"""

NOTES = """# Live test: Item::getAttackDamage +@BONUS@

Goal: prove on a real device that the hook chain works for build `@BUILD@`
(libminecraftpe.so sha256 `@SHA@`, game string `@VER@` - unconfirmed).

## Build and install
1. Push this folder to GitHub and run the *build* workflow (or `./scripts/package.ps1 -Abi arm64-v8a`).
2. Import the `.levipack` in LeviLauncher, start Minecraft with that game version.

## What to look for in `levilamroid.log`
(`/sdcard/Android/media/org.levimc.launcher/minecraft/com.mojang.minecraftpe/levilamroid.log`)

| line | means |
|---|---|
| `[hook] Item::getAttackDamage: N of N address(es) hooked (K subclass override(s))` | module found, slot passed the instruction guard, SDK cross-check agreed (or was unavailable), hooks installed |
| `does not match game build` | wrong game build: re-run `tools/so_probe.py --verify` on YOUR libminecraftpe.so and send the output |
| `preloader resolves 0x.., levipack-forge 0x..; refusing` | RTTI resolver and the DB disagree: send this line |
| `[live-test] Item::getAttackDamage hook #0 ... 0 -> @BONUS@` | the detour runs: attack with any non-sword item (or open an inventory tooltip) |

## Interpreting results
* `hook #0` = the base Item function. Items that inherit it (most non-weapons) show it.
* `hook #1..` = subclass overrides (swords/tools). @SUBTXT@
* Hit a mob with a stick/hand and with a sword. Report: which hook numbers fired, and the damage you saw.
* If the install line appears but no `[live-test]` line ever does, the slot is right but nothing calls it for your
  action - try a sword, then report back.

## Remove the effect
Delete the mod from the launcher.
"""


def generate(out, bonus=3, mc_versions=None, symbols=None):
    db = SymbolDB.load(symbols)
    if not db.usable("Item::getAttackDamage"):
        raise SystemExit("symbol DB has no statically verified Item::getAttackDamage")
    out = pathlib.Path(out)
    with tempfile.TemporaryDirectory() as tmp:
        jar = pathlib.Path(tmp) / "levipack_live_test.jar"
        meta = {"schemaVersion": 1, "id": "levipack_live_test", "name": "Levipack Live Test",
                "version": "0.1.0", "description": f"Adds {bonus} to Item::getAttackDamage and logs it.",
                "authors": ["levipack-forge"], "entrypoints": {}}
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("fabric.mod.json", json.dumps(meta))
        r = convert(jar, out, mc_versions, symbols, "levipack_live_test")
        # This dedicated diagnostic project intentionally injects its test detour directly;
        # ordinary mod conversion has no overrides-file dependency.
        sym = SymbolIndex.load(symbols)
        hh, hc = hookmod.render("levipack_live_test", [], [], sym,
                                {"Item::getAttackDamage": {"cpp": BODY.replace("@BONUS@", str(bonus))}})
        (out / "src/mod/Hooks.h").write_text(hh)
        (out / "src/mod/Hooks.cpp").write_text(hc)
    sub = db.overrides_for("Item::getAttackDamage")
    subtxt = (f"The DB lists {len(sub)} distinct subclass override(s) for this slot, so they are hooked too." if sub else
              "**This DB has no subclass data yet**, so swords/tools that override the slot are NOT hooked. "
              "Run `python tools/so_probe.py libminecraftpe.so --subclasses Item --db <db.json> --merge` and regenerate.")
    (out / "LIVE_TEST.md").write_text(NOTES.replace("@BONUS@", str(bonus)).replace("@BUILD@", db.tag)
                                      .replace("@SHA@", db.sha256).replace("@VER@", db.d.get("mc_version_string", "?"))
                                      .replace("@SUBTXT@", subtxt))
    r["subclass_overrides_in_db"] = len(sub)
    return r
