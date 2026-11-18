# Levi Fabric Forge

Convert Fabric Java mod JARs into LeviLauncher Android native-mod projects and `.levipack` packages.

This project deliberately does **not** require a Bedrock resource pack, an `examples/` directory, or an `overrides/` directory. Each generated mod includes its own launcher-editable settings menu backed by the LeviLauncher typed config (`config.json` + `config.schema.json`). The converter imports supported static settings and command options into that menu.

## Quick start

```bash
pip install -e .
levipack-forge convert mods/my-mod.jar -o generated --mc-versions '["1.26.*"]'
cat generated/CONVERSION_REPORT.md
cd generated
./scripts/package.ps1 -Abi all
```

Or add a Fabric JAR to `mods/` and run **Convert Fabric mod -> .levipack** from GitHub Actions. The workflow creates the native project, builds it with the Android NDK, and publishes the `.levipack` plus conversion report.

## What the converter does

- Reads `fabric.mod.json`, main/client/server entrypoints, metadata, icons, dependencies and declared mixin configs.
- Translates the supported straight-line Java bytecode subset into native C++.
- Converts supported logger calls and Fabric lifecycle callbacks.
- Imports supported static Java settings and detected command options into the per-mod launcher settings menu.
- Generates a native hook registry and runtime resolver. When `--symbols` is supplied, TODO entries include candidate Bedrock symbols.
- Inventories Java assets and data files and reports them; it does not pretend that Java assets, models or data packs are already Bedrock-compatible.

## Important compatibility boundary

Bedrock has no Java classes, Fabric runtime, Java Minecraft API, or Java Mixin runtime. A converter cannot safely translate those APIs into working game behavior by renaming classes. Game-facing behavior must be reimplemented against the exact Bedrock build with verified native targets and `<pl/memory/Hook.hpp>`. Generated hooks are safe scaffolding, not proof that a feature works. Never enable a guessed hook on a live client.

`CONVERSION_REPORT.md` records converted code, native-hook gaps, mixin classes and asset inventory. `MANUAL_WORK.md` is the implementation checklist. Test the generated project with the Android NDK and on the target LeviLauncher / Minecraft version before distribution.

## Repository layout

- `levipack_forge/` — parser, bytecode transpiler, hook generation, symbol index and CLI.
- `levipack_forge/template/` — native LeviLauncher project template copied into each conversion.
- `mods/` — input Fabric JARs.
- `symbols/` and `levipack_forge/data/` — build-specific symbol research and verified symbol database.
- `reference/` — pristine LeviLauncher native template reference.
- `tests/` — parser, conversion, hook and packaging tests.
- `docs/` — Android hooking and extension notes.

## Commands

```bash
levipack-forge convert mod.jar -o generated --symbols symbols.txt
levipack-forge symbols index libminecraftpe.so -o symbols.txt
levipack-forge symbols search symbols.txt Player jump
levipack-forge live-test -o live-test
```
