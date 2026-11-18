# Changelog

## Unreleased — resource-pack-free native conversion
- Removed the mandatory Bedrock resource-pack generation/install stage from conversion and CI packaging.
- Removed the repository `examples/` and `overrides/` directories and the CLI override-file workflow.
- Every generated mod advertises a launcher-editable settings menu through its typed config and schema.
- Added mixin config/class inventory and Java asset/data inventory to conversion reports.
- Added an explicit asset-porting note: visual/data assets are not in-game without a Bedrock asset delivery mechanism.


## 0.5.0
* New: real hook detours. Targets with static evidence get a generated detour (pass-through, or `hooks` override body), installed with `pl::memory::hook` (signature taken from preloader-android 0.2.2), cross-checked against `pl::memory::resolveVtableFunction`, one trampoline per hooked address, `unhook` on disable.
* New: subclass overrides. `so_probe.py --subclasses CLASS --db DB --merge` records which descendants override a DB slot; generated code hooks every distinct override.
* New: `levipack-forge live-test` + `live-test.yml` workflow: on-device proof project with a log checklist (`LIVE_TEST.md`).
* New: `so_probe.py --verify --quiet`; `tools/check_sdk_compile.py` (compiles generated hooks against the real SDK headers; run in CI).
* Tests: 44 (host runtime test with a fake mmapped libminecraftpe.so and a mocked preloader).
* Not done: anything on the real 342 MB binary or a device.

## 0.4.0
* Fix: resource pack is now packaged into the .levipack (`resources/minecraft_resource_packs/<Name>/`); new `pack-install` command; workflow runs it after `pack-merge`.
* New: build-keyed symbol DB (11 static Item virtuals with instruction guards), `Resolve.h/.cpp` runtime resolver.
* New: `tools/` (`so_probe.py` with `--dump`/`--verify`, `align_vtable.py`, `make_symbols_db.py`).
* Finding: Amethyst -> Android Item slot shift is not +1..+3 (see docs/ANDROID_HOOKING.md).
* Report: vanilla/GUI textures that cannot be converted are listed instead of skipped silently.
