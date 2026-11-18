# Android hooking: what is known, what is guessed

Source material: `docs/research/` (the three analysis notes) and `symbols/source/` (the dump and probe output for one
`libminecraftpe.so`). Everything below is **static analysis of one binary** (sha256 `4de40e1d...`, string
`1.26.62.01_RC0`, unconfirmed). **Nothing has been tested live on a device yet.**

## Status levels (`levipack_forge/data/*.symbols.json`)

| status | meaning | used by generated code |
|---|---|---|
| `static` | instruction evidence read from this binary, plus `expect` words | resolved + prologue-checked at start-up |
| `reported` | the hooking guide calls it verified, no instruction evidence recorded | hint only |
| `candidate` | shape alignment (`tools/align_vtable.py`) | hint only |

Currently 11 `static` Item virtuals: `getDescriptionId 5`, `getMaxUseDuration 6`, `setMaxDamage 27`,
`setMaxUseDuration 28`, `canBeDepleted 33`, `getMaxDamage 37`, `getAttackDamage 38`, `getAttackDamageBonus 39`,
`isHandEquipped 40`, `getDamageChance 69`, `buildIdAux 80` (Android slot numbers, counted from the vptr).
Item fields: `maxDamage` short @0x110, flags byte @0x112, `maxUseDuration` int @0x114, item id short @0x8a.

## Correction to the hooking guide: the slot shift is not +1..+3

The guide says Amethyst (MSVC) indices shift by +1..+3 for slots it did not check. The dump disagrees:
`getDamageChance` (`mov w8,#0x64; add w9,w1,#1; sdiv`) is Amethyst 57 but Android 69 (**+12**), and `buildIdAux`
(`ldrh [x0,#0x8a]; sxth; orr lsl #16`) is 70 -> 80 (+10). The shift grows from +1 to about +15 by the end of the table
(`shift_runs` in the DB). Hooking an unchecked slot with "index + 3" would patch the wrong function.

`tools/align_vtable.py` aligns the Amethyst list against the dump by function shape. Given no hints at all it
reproduces every slot the guide verified (a regression test pins this), but shape alone is ambiguous for runs of
`mov w0,wzr; ret` getters, so its output is only ever a candidate.

## Runtime behaviour of a generated mod

`Resolve.cpp` (plain C++, no SDK): find `libminecraftpe.so` in `/proc/self/maps` (lowest mapping must have file offset 0),
read `base + vptrRva + 8*slot`, require slot and target to lie inside the module, and require the first instruction
words to equal `expect`. Any failure -> `0` -> feature skipped with a log line.

`Hooks.cpp` then (per verified target, signatures taken from the real preloader-android 0.2.2 headers):
1. cross-checks the address with the SDK's own `pl::memory::resolveVtableFunction("4Item", slot, "libminecraftpe.so")`
   (same slot numbering) and **refuses to hook if the two disagree**;
2. collects the base function plus every subclass override recorded in the DB (distinct addresses only, max 16);
3. installs one detour per address with `pl::memory::hook`. A detour template is instantiated per address, so each
   detour calls the trampoline of the function that was really entered (a subclass override is a different function);
4. `uninstallAll` calls `pl::memory::unhook` for each.

The default detour is a pass-through. Implement the desired native behavior in the generated hook body and keep the change in the native project source. Re-run conversion after backing up that implementation, or extend the transpiler/template to emit the implementation automatically. No separate overrides directory or JSON file is part of the workflow.

## Subclass overrides (swords, tools)

Hooking the base `Item` slot does not affect classes that override it. `so_probe.py` finds every single-inheritance
descendant through RTTI (`__si_class_type_info` base pointers) and records which static slots they override, with the
first three instruction words of each override as its guard:

```bash
python tools/so_probe.py libminecraftpe.so --subclasses Item \
    --db levipack_forge/data/libminecraftpe.4de40e1d.symbols.json --merge
```
The shipped DB does **not** contain this data yet (it needs your binary), so until you run it, swords/tools are not hooked
and the live-test notes say so. Limits: multiple-inheritance descendants (`__vmi_class_type_info`) are not found.

## After a game update

```bash
python tools/so_probe.py libminecraftpe.so --verify levipack_forge/data/libminecraftpe.4de40e1d.symbols.json --quiet
python tools/so_probe.py libminecraftpe.so --dump vtables_dump.txt          # new build: regenerate
python tools/align_vtable.py symbols/source/amethyst-learnings.txt vtables_dump.txt --class Item
python tools/make_symbols_db.py                                              # rebuild the DB from symbols/source
```
`--verify` exits 1 on any slot mismatch; `--quiet` prints only problems. For a new build you must re-read the evidence
table in `tools/make_symbols_db.py` (`STATIC`) by hand: the script refuses to build if a slot no longer starts with the
instruction it claims.

## The live test

```bash
levipack-forge live-test -o live-test --bonus 3     # or run the "Live test" workflow on GitHub
```
Generates a levipack that adds the bonus in `Item::getAttackDamage` and logs the first 40 calls. `LIVE_TEST.md` in the
output lists exactly which log lines prove which stage (module found, guard passed, SDK cross-check, hook installed,
detour running, subclass overrides). Run it, then send back the log lines.

## What was verified how

| claim | how |
|---|---|
| generated Hooks/Resolve compile against the real SDK | `tools/check_sdk_compile.py`: preloader-android 0.2.2 + fmt 11.2.0 headers, all 11 signatures, `-Wall -Wextra` |
| detour dispatch, guards, dedupe, unhook, SDK disagreement | host test with a fake `libminecraftpe.so` mmapped from a file and a mocked preloader |
| `so_probe` RTTI/relocation/subclass/verify logic | synthetic aarch64 ELF (`tests/elfsynth.py`) |
| anything on the real binary or a device | **not done**: needs your files / your phone |
