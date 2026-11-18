"""Fix advice for everything the transpiler cannot convert by itself.

Each rule maps a pattern in the unsupported call to a category and a concrete way to solve it.
The advice is printed in CONVERSION_REPORT.md and MANUAL_WORK.md next to each item, so a person
never has to guess what to do with a flagged line.
"""
from __future__ import annotations
import re

GAME_PREFIXES = ("net/minecraft/", "com/mojang/", "net/fabricmc/fabric/", "net/fabricmc/api/",
                 "org/spongepowered/", "net/neoforged/", "net/minecraftforge/")

# (regex over the dotted call text, category, how to solve it)
RULES = [
    (r"command|brigadier|CommandDispatcher", "Commands",
     "Expose what each command changes as a typed config field (it then shows up in the launcher UI), "
     "or hook the Bedrock command registry. Leave the command as a reported TODO if it is debug-only, or implement it in the native command/hook layer."),
    (r"KeyMapping|KeyBinding|keybind|Keybind|InputConstants", "Key bindings",
     "Bedrock/Android has touch input: map the action to a config toggle or a touch-HUD button; "
     "desktop key bindings have no equivalent. Usually safe to ignore on Android."),
    (r"ResourceManager|ReloadListener|resource\.", "Resource reload",
     "Bedrock loads resources from the pack itself. Ship assets in `resources/` and ignore the listener."),
    (r"Screen|gui\.|Gui\b|GuiGraphics|widget|toast|Toast", "UI / screens",
     "Java screens cannot run on Bedrock. Move the options into the typed config (launcher UI) "
     "and drop the screen; in-game UI needs a native hook or a Bedrock UI JSON pack."),
    (r"render|Render|Model|model|Camera|Matrix|PoseStack|Animation|animation|Pose", "Rendering / animation",
     "Rendering is engine-specific. Re-implement as Bedrock render controllers / animation JSON in a resource pack, "
     "or hook the matching native renderer function (use --symbols to get candidate names)."),
    (r"Player|Entity|LivingEntity|LocalPlayer|Mob|HumanoidArm|InteractionHand", "Entities / player",
     "Hook the matching Bedrock Actor/Player virtual (use --symbols), or implement the behavior with an addon "
     "behavior pack (entity events / animation controllers)."),
    (r"Block|Item|Level|World|Chunk|BlockPos|Registry|Identifier|ResourceLocation", "Items / blocks / world",
     "Bedrock defines items, blocks and entities in behavior-pack JSON. Generate/port the JSON, "
     "keep native code only for logic that JSON cannot express."),
    (r"Minecraft|SharedConstants|WorldVersion|Options|Window", "Client/game state",
     "Replace the query with a constant (e.g. game version) in the native implementation, or read the value "
     "through a native hook."),
    (r"Event|event|Callback|callback|tick|Tick", "Game events",
     "Hook the Bedrock equivalent (tick/use/attack) via `<pl/memory/Hook.hpp>`; lifecycle events are already mapped."),
    (r"Network|network|Packet|packet|Payload", "Networking",
     "Java custom payloads do not exist on Bedrock. Use a Bedrock script event / packet hook, or drop it (client-only mods)."),
    (r"modmenu|ModMenu|config\.|Config", "Config screen",
     "The launcher already shows the typed config. Nothing to port beyond field defaults."),
]
DEFAULT_GAME = ("Game API",
                "Needs a native hook (`<pl/memory/Hook.hpp>`). Run `levipack-forge symbols ...` and pass --symbols so each "
                "stub lists candidate Bedrock symbols, or implement a native replacement in the generated C++ project.")
DEFAULT_JAVA = ("Plain Java logic",
                "Pure Java helper that the transpiler subset cannot express (branches/loops/objects). "
                "Implement the equivalent in the generated native C++ project.")


def is_game_owner(owner: str) -> bool:
    return owner.startswith(GAME_PREFIXES)


def advise(text: str, game: bool = True):
    for pat, cat, fix in RULES:
        if re.search(pat, text):
            return cat, fix
    return DEFAULT_GAME if game else DEFAULT_JAVA
