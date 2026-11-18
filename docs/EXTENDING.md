# Extending the transpiler

* Call mapping lives in `Transpiler._call` (`levipack_forge/transpile.py`). Add a rule that returns C++ lines
  appended to `lines`; return a stack value if the Java method returns something.
* Unsupported bytecode must call `self._todo(...)` so it shows up in the report. Never drop code silently.
* Typical next steps: string concatenation (`StringConcatFactory`), `if (config.flag)` guards mapped to
  `mConfig` checks, command registration, item-use / tick events via `pl::memory::Hook`.

## v0.2 routing order in `Transpiler._call`

1. `_fabric` (Loader/metadata/Optional folded from fabric.mod.json) 2. `_tokens` (Component/Identifier -> string)
3. `_by_design` (no Bedrock equivalent, reported) 4. `_inline` (in-jar helpers with no game calls and no branches)
5. stub: `gap` if it touches the game, else `manual`. Unsupported behavior is implemented in native source, not through an external overrides file.
Add advice for a new category in `levipack_forge/solutions.py` (`RULES`).

## v0.3 modules
* `commands.py` - Brigadier command tree -> `cmd_*` config fields.  * `hooks.py` - Hooks.h/.cpp registry.
* Resource-pack generation is not part of the default conversion or `.levipack` build path. Java assets are inventoried in the conversion report for a future explicit Bedrock asset port.
