=====================================================================
 ANDROID HOOKING GUIDE - MEASURED ON YOUR libminecraftpe.so
 (replaces the generic android-hooking-guide.txt; builds on
  amethyst-learnings.txt)
=====================================================================

1. WHAT I MEASURED (facts from your file)
---------------------------------------------------------------------
 file        : libminecraftpe.so, 342,231,392 bytes, ELF64 aarch64, stripped
 sha256      : 4de40e1dcbbca6d4773af57fa6753afd991b95878bc5d51dcceaebf0d65283d8
 build-id    : NONE (no .note.gnu.build-id) -> identify the build by the
               sha256 above, or by hashing a few KB of .text at load time
 game version: the string "1.26.62.01_RC0" sits next to "base_game_version".
               Treat that as likely, not proven - confirm with the version
               shown by the app you took the .so from.
 .dynsym     : 91,693 entries, but they are third-party code (V8, cohtml,
               webrtc, Xbox Live SDK, GameActivity). I found NO exported
               game functions (no Item::, Actor::, Level:: ...).
               => dlsym() will not work for game code.
 .symtab     : none.
 RTTI        : PRESENT. Itanium typeinfo names exist, so vtables for game
               classes can be found even though the file is stripped.
 relocations : .rela.dyn (RELATIVE). Vtable pointers resolve through them.
 Image base  : 0. ELF virtual address == RVA. Runtime address =
               load base of libminecraftpe.so (from /proc/self/maps) + RVA.

2. VTABLES FOUND (RVA of vptr = address of slot 0)
---------------------------------------------------------------------
 Item 0x13d9a680 (133 slots)    ItemStack 0x13d96650   ItemStackBase 0x13d93b40
 Actor 0x13cf5d40 (137)         Mob 0x13cc5328 (175)   Player 0x13d43330 (181)
 LocalPlayer 0x139f74e0         ServerPlayer 0x13c7c690
 SurvivalMode 0x13d22f58        (GameMode base class: not found by that name)
 BlockType 0x13ded6f0           (= Amethyst's BlockLegacy, renamed)
 Block 0x13dfc700               BlockActor 0x13e408d0  BlockSource 0x13d6e328
 Level 0x13e0a750 / 0x13e0b448 / 0x13e0b4a8 (143 in the first)
 Container 0x13d073c8           Minecraft 0x13d076b8
 ClientInstance 0x138904b0 (+5 secondary vtables, see dump)
 ScreenController 0x138c7818    LevelRenderer 0x13a555c0 / 0x13a556f0
 Dimension 0x13e0d530 (+3 more)
 NOT FOUND by name: BlockLegacy (renamed BlockType), GameMode, ILevel,
 ScreenView, CreativeMode. They may be renamed/templated; search the
 other names listed in vtables_dump.txt or look near SurvivalMode.
 Every slot of the main vtables, with its RVA and first instructions, is
 in vtables_dump.txt. symbols.json holds the same vptr addresses.

3. AMETHYST INDEX -> ANDROID INDEX: THE MAPPING IS NOT A CONSTANT
---------------------------------------------------------------------
Amethyst's @vidx values (MSVC, 1.21.0.3) do NOT transfer by a fixed
offset. Checked on Item by reading what each slot's code actually does:

  function (Amethyst)        MSVC   Android  evidence in your binary
  ~Item                       0     0 and 1  two destructors (Itanium)
  initServer                  1       2      large function
  setDescriptionId            3       4      builds/copies a string
  getDescriptionId            4       5      add x0,x0,#0x90 ; ret
  getMaxUseDuration           5       6      ldr w0,[x0,#0x114] ; ret
  setMaxDamage               24      27      strh w1,[x0,#0x110] ; ret
  canBeDepleted              30      33      short@0x110 > 0 && flag@0x112 bit 2
  getMaxDamage               34      37      ldrh w0,[x0,#0x110] ; ret
  getAttackDamage            35      38      mov w0,wzr ; ret   (int, default 0)
  getAttackDamageBonus       36      39      movi d0,#0 ; ret   (float)
  isHandEquipped             37      40      ldrb [x0,#0x112]; ubfx #1

 So the shift is +1 for the first slots (destructor takes 2 slots),
 then +3 by index 24 - Mojang added virtuals between 1.21.0 and 1.26.x.
 For indices I did not check (6-23 and 38+), the shift is in the range
 +1..+3 and must be confirmed per function the same way:
   a) take the Amethyst signature (return type, args, "const");
   b) look at candidate slots in vtables_dump.txt - tiny getters are
      easy to recognise (mov w0,wzr; ret / ldrb / ldr from [x0,#off]);
   c) confirm by behaviour with a test hook (print, or change a value).
 Do not hook any slot you have not confirmed this way.

 Field offsets seen on Item (verified from the getters above):
   maxDamage (short) @ 0x110 ; flags (byte) @ 0x112 ; maxUseDuration
   (int) @ 0x114. Do not reuse Amethyst's field offsets: they are MSVC
   layouts for 1.21.0.3.

 Combat functions for Mob/Actor/Player (_hurt, knockback, die, attack):
 their MSVC indices were not calibrated yet. Method: diff the Actor,
 Mob, Player vtables in vtables_dump.txt (slots where Mob differs from
 Actor are Mob's overrides), match by argument count/return type, then
 confirm with a test hook. I can do this next for the specific
 functions your mods need.

4. HOW TO HOOK (runtime recipe for the .levipack native part)
---------------------------------------------------------------------
 1. Identify build: hash check against the sha256 above (or a small
    .text fingerprint). Mismatch -> skip all native hooks, load packs only.
 2. base = address of libminecraftpe.so from /proc/self/maps (lowest
    mapping of that file; confirm it is offset 0).
 3. Resolve:  fn = *(uintptr_t*)(base + vptr_rva + 8*slot)
    (the slot holds an absolute address after relocation at runtime.)
 4. Hook with the LeviLauncher template's hook API, or Dobby/ShadowHook:
      using F = int(*)(void* self);   F orig;
      int Item_getAttackDamage(void* self){ return orig(self) + 3; }
      hook(base + vptr_rva + 8*38 -> its target, Item_getAttackDamage, &orig)
    IMPORTANT: Item::getAttackDamage for the base Item returns 0, and
    SUBCLASS vtables (swords, etc.) may have their own override. Hooking
    the base Item slot only affects items whose vtable still points to
    that function. To change swords you must hook each subclass's slot
    or inline-hook the shared target function. Check the subclass
    vtables (find them with so_probe.py --classes SwordItem,...).
 5. Alternative that avoids per-subclass work: inline-hook the function
    body at its address (not the vtable slot) when many classes share it.
 6. First live test: add +3 in getAttackDamage for one custom/sword item
    and hit a mob. If the number changes, build-id check, base address,
    index mapping and hook install are all proven.

5. FUNCTIONS THAT ARE NOT VIRTUAL
---------------------------------------------------------------------
 (Minecraft::update, ClientInstance::onStartJoinGame, ScreenView::
 setupAndRender, VanillaItems::registerItems, LevelRenderer::renderLevel,
 ResourcePackRepository::_initializePackSource ...)
 These have no vtable slot and no export. Find each in Ghidra/IDA:
   - via a string it references (log text, UI/resource names), or
   - via a caller that IS in a vtable slot,
 then make a signature:
     python3 so_probe.py libminecraftpe.so --sig 0x<function RVA>
 Needs exactly 1 match in .text. With a 342 MB library the scan is slow
 in Python; expect minutes. The result goes in symbols.json as
 {"kind":"sig","sig":"...","sha256":"4de40e..."}.
 Not done yet: I have not located any non-virtual function in your
 binary, so none of these have an address or signature yet.

6. WHAT THIS MEANS FOR THE CONVERTER
---------------------------------------------------------------------
 Ready now (verified on this binary):
   * Item vtable hooks for the slots in the table in section 3
     (attack damage, max damage, hand-equipped, max use duration...).
   * A repeatable method + tooling (so_probe.py, vtables_dump.txt,
     symbols.json) to calibrate more slots.
 Not ready yet:
   * Combat/block/UI/render hooks: indices uncalibrated, non-virtual
     targets unlocated.
   * Anything depending on a class I couldn't find (GameMode, ScreenView,
     BlockLegacy under its old name).
 Version warning: you are on a 1.26.x build and the Amethyst headers
 are 1.21.0.3. Function names mostly persist, but signatures, argument
 lists and class names (BlockLegacy->BlockType) have changed. Treat the
 headers as hints, the binary as the truth.
 Every game update changes addresses; regenerate with so_probe.py and
 key the tables by sha256.

7. NEXT STEPS (in order of payoff)
---------------------------------------------------------------------
 1. Pick the first behaviours you want working (e.g. "+N attack damage
    on item X", "run code every tick", "add a menu button"); I calibrate
    just those slots/functions against the binary.
 2. Find the subclass vtables for weapon items so the attack-damage
    test works on a real sword.
 3. Locate Minecraft::update and registerItems via strings; generate
    ARM64 signatures.
 4. Wire symbols.json + resolver + hook emitter into levipack-forge.
 5. Pack emitter for data-driven content (works without any of this).
