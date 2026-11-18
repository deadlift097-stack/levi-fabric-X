# Java asset and data-pack porting boundary

The default converter intentionally produces a native `.levipack` without embedding or requiring a Bedrock resource pack. This removes the previous mandatory `resource_pack/` generation and packaging stages.

That packaging choice has a real trade-off: Java assets are not automatically usable by Bedrock. Java texture atlases, item/block models, entity models, animation definitions, sound events, loot tables, recipes, tags, world-generation data and predicates use different schemas and runtime systems. A report or renamed file is not a functional port.

The converter therefore inventories files under `assets/` and `data/` in `CONVERSION_REPORT.md` instead of shipping an incomplete pack or claiming that assets work. To make those features visible in-game, a future optional asset backend must translate each format to the appropriate Bedrock format and package it through a resource/behavior pack (or a verified native asset-loading API). Without one of those delivery mechanisms, textures/models/data packs cannot be installed in-game.

For gameplay behavior, use a native implementation against the exact `libminecraftpe.so` build and verify hook targets before enabling them. Mixin injection points and Java Minecraft API calls must be mapped to equivalent Bedrock behavior; they cannot be executed as Java code inside Bedrock.
