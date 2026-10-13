# Reverse engineering an old game (DOS/4GW LE, Win32 PE)

## 0. Identifying the binary

```
python -c "d=open('GAME.EXE','rb').read();o=int.from_bytes(d[0x3c:0x40],'little');print(hex(o), d[o:o+2])"
```
- `b'LE'` → DOS/4GW / DOS32A / PMODE/W, 32-bit flat → `analyze.ps1`.
- `b'LX'` → OS/2 (`-Loader LxLoader`).
- `b'PE'` → Win32 → `analyze_pe.ps1` (section 7). `b'NE'` → Ghidra handles it natively.
- Only `MZ` without a new header → 16-bit real mode; Ghidra x86 16-bit
  (`x86:LE:16:Real Mode`) + MZ loader, this kit is not needed.
- If the EXE is "bound" with a DOS4GW stub (typical), the loader finds the LE header itself.
  This also covers the variant where `e_lfanew` is garbage and the small MZ stub is followed
  by `BW` headers (DOS/4G bind): chain BW → second MZ → LE.
  Note: the LE data page offset is then relative to the **second MZ**, not to the start
  of the file (`le.py` handles this).
  Some games keep the LE in a separate file or compressed (PKLITE,
  UPX for DOS32A) – unpack it first.

Compiler: strings such as `Watcom`, `WATCOM C/C++32 Run-Time`, `DOS/4GW` →
Watcom. Borland (BC 4.x + DPMI) uses a different convention (the borlandcpp cspec ships with
Ghidra).

## 1. Loader and compiler spec (LE/LX)

`ghidra-lx-loader` (derived from yetmorecode/ghidra-lx-loader) is the only usable LE loader;
an upstream release may not exist for your Ghidra version, so it is built from source
(`build.ps1`). The loader sets up the objects from the LE table (including r/w/x permissions
from the LE flags; typically code in object 1 from 0x10000, data in the next object – see
`memory_blocks.txt`), **applies the fixups** (important – without them there are no references
to strings/data) and writes them into the Ghidra relocation table.

`x86watcom.cspec` has two prototypes:
- `__watcall_stack` (**default**): arguments pushed, caller cleans up
  (`ADD ESP,n`), EAX/ECX/EDX scratch, EBX/ESI/EDI/EBP preserved. Used by game code
  compiled with `-3s/-5s`.
- `__watcall`: register convention `-3r/-5r` (EAX, EDX, EBX, ECX), callee cleans up.
  The Watcom runtime (libc) mostly uses this convention.

**How to tell which one applies:** `python tools\detect_cc.py GAME.EXE` (statistics over
all `CALL`s in the code object, before import), or manually disassemble any game function
(`DumpDisasm.java ADDR`): if `CALL` is preceded by `PUSH`es and followed by
`ADD ESP,4/8/…` → stack (`-Cspec watcom`). If arguments are set with
`MOV EAX,…; MOV EDX,…` without pushes and functions end with `RET n` → register
(`-Cspec watcomreg`; `x86watcom_reg.cspec` has `__watcall` as the default).
Even in a register-convention program, varargs functions (printf etc.) use `ADD ESP`.
Wrong default = the decompiler throws away all call arguments as dead code
(`FUN_xxx()` without arguments everywhere).

**Register convention and preserved registers.** A Watcom callee saves (`push`) every
register it modifies except EAX and the argument registers; the caller never reads an
argument register after the `CALL`. `x86watcom_reg.cspec` therefore models EBX/ECX/EDX as
`unaffected` in `__watcall` and has no EDX:EAX output. A model with EBX/ECX/EDX as
`killedbycall` produces thousands of `extraout_*`, a fake parameter from every
`push ebx/ecx/edx` in a prologue, and lots of `undefined8` from the 64-bit output (see the
comment in the cspec).

## 2. Pipeline (`analyze.ps1`) – what it does and why

1. Import + standard auto-analysis (on the order of minutes for hundreds of KB of code).
2. `CreateFunctionsFromFixups.java`: walks the relocation table; every 32-bit
   fixup pointing into the code object where there is no function yet gets disassembled
   and turned into a function. Watcom games call a large part of their logic through
   function-pointer tables (state machines, drawing routines) and Ghidra does not find
   them on its own – this raises function coverage considerably.
   If the game code sits in an object without the execute flag or shares an object with data,
   use `CreateFunctionsAtEntries.java --fixup-insns` / `--fixup-code=LO-HI` /
   `--gap-prologues=LO-HI` (see the script header).
3. `FixTruncatedCallers.java`: Ghidra sometimes marks an ordinary function as
   "no return", which **truncates every caller** after the `CALL`. The script clears the flag,
   disables the `Non-Returning Functions - Discovered` analyzer, disassembles the
   fall-through and rebuilds the bodies. Without arguments it runs in auto mode
   (no-return functions that contain a `RET`).
4. `MarkStringsConstant.java`: marks strings in the writable data object as
   `constant` so the decompiler prints `"text"` literals (otherwise `&DAT_xxx`).
5. Only for `-Cspec watcomreg` (or with `-Prototypes`):
   - `ApplyStackConvention.java`: functions whose calls are followed by `ADD ESP,n`
     get `__cdecl`; if `n` differs between calls it is varargs
     (sprintf…) → min(n)/4 fixed parameters + `...`, locked signature.
   - `RecoverPrototypes.java`: prototypes from the decompiler **bottom-up** by
     call-graph level (in parallel within a level). Trailing `unaff_*` parameters
     (saved registers) are dropped unless at least half of the callers set them
     right before the `CALL` (so e.g. `main(argc=EAX, argv=EDX)` survives).
     Callers then see the real number of arguments. Note: a data-flow check in the callee
     (whether a register is "really used") does not work – partial writes such as
     `mov bh,cl` make every saved register look used.
6. `ExportDecompiled.java` + `DumpFixups.java`.

**Pitfall – block permissions.** If the loader creates every object as `r--`,
the decompiler treats globals in the data object as constants, substitutes their
initial values and deletes branches ("Removing unreachable block" – whole dialogs and
options disappear). The loader in this kit sets `rw-`/`r-x` from the LE
flags; projects imported with an older loader must be re-imported.

How to measure decompilation quality: counts of `extraout_`, `unaff_`, `undefined8`,
"unreachable block" in the log, and string literals in the `.c`. The correct cspec,
`rw` data, `MarkStringsConstant` and prototype recovery each have a measurable effect;
`unaff_` remains mainly inside large functions and the asm runtime, not in signatures.

`EnableDeepAnalysis.java` (Decompiler Parameter ID) is not recommended – on a program
with thousands of functions it runs for tens of minutes without a result. The stack convention
gives good signatures even without it; `RecoverPrototypes.java` is a parallel replacement if needed.

If you kill the headless process, delete `ghidra_project\*.lock*`.

## 3. Finding your way around megabytes of C code

1. `strings.txt` – file names, debug messages, progress texts
   = subsystem anchors. `fixups.txt` tells you **which function uses a string**
   (grep column 4 = containing function). Grepping the `.c` directly for a
   `"text"` literal only works once the cspec is right.
2. `find_tables.py` – function-pointer tables in data (state machines:
   fixed-stride records, e.g. `{name*, id, fn, enabled}`) and string tables
   (level names, sprite names).
3. `functions.csv`: functions with the most callers = runtime helpers
   (memset/open/read); the largest ones = renderer / main loop / AI.
4. Entry: Watcom `_entry` → `__CMain` → `main` = the function that first sets up
   paths/argv and calls the "game main" (argument parsing + `alloc` of large
   structures). Look for `stricmp` over the arguments and the switch strings.
5. Global structures: games often allocate a few large blobs (`DAT_xxx =
   alloc(0x…)`); all offsets `*(int*)(DAT_xxx + 0x…)` are fields of one
   structure. Save-game/demo file dumps are often verbatim copies – verify
   offsets against them.
6. Constant tables are not readable in the decompilation (pointers in data are
   **unrelocated** in the file): `tools/le.py rec ADDR N SIZE fmt` reads them
   straight from the EXE (Ghidra addresses); add the object base to pointers (see
   `memory_blocks.txt` or `le.py info`) or look in `fixups.txt`.

## 4. Data formats (common in DOS-era games)

- **RNC ProPack** (`RNC\x01`): `tools/rnc.py` (method 1, CRC verified).
  Common in both DOS and Amiga games.
- `.TAB/.DAT` style sprite banks: TAB 6 B `{offset u32, w u8, h u8}`, RLE
  rows (0 end, <128 copy N, ≥128 skip 256−N).
- 768 B palettes, 6-bit VGA.
- **Autodesk FLIC** (FLI 0xAF11 / FLC 0xAF12, frames 0xF1FA): cutscenes as well as
  animated sprites. `tools/flic.py info|png|video` – also handles the stripped 12-byte
  header, 6/8-bit palette detected automatically. Games often change the frame rate during
  a video (a table of "cue" commands in the EXE: delays, sounds, music) – find the
  player (calls the FLIC decoder in a loop) and its table; then render the video
  at a fixed 60 fps with repeated frames and trigger sounds by time.
  Godot plays `.ogv` (Theora) without import: `VideoStreamTheora.new().file = path`.
- Document formats as you go (`notes\formats.md`: offset, size, meaning, V/G).

## 4b. Related EXEs (add-on, sequel, other version) – transferring names

Once one game is analyzed (names in `notes\names_*.csv`), a second one on the same engine
does not have to be analyzed from scratch:

1. Run the new EXE through `analyze.ps1` as usual (cspec from `detect_cc.py`).
2. Copy `decomp\` to `decomp_unnamed\` (matching must run on an export without transferred names).
3. `python tools\match_names.py --a-exe A.EXE --a-decomp A\decomp --a-names A\notes\merged\names_all.csv
   --b-exe B.EXE --b-decomp B\decomp_unnamed --out B\notes\match --names-out B\notes\names_match.csv`
   – matches functions (bytes with masked fixups, unique string sets, call-graph neighbourhood,
   shared "anchors" = mapped global data + matched callees/callers, fuzzy instruction similarity);
   aligned instructions of matched functions vote on an A → B data address map (`data_map.csv`).
4. `analyze.ps1 ... -SkipImport -Names B\notes\names_match.csv`.

What stays unmatched is mostly functions that exist in only one EXE. Look for constant tables
across EXEs first via `data_map.csv` (references from matched functions), then by content – watch
out for tables indexed from a "virtual" base (id·stride) and for a changed record stride.

## 5. Delegating the analysis to AI agents

The decompilation is too large to read in one go; splitting it into
several parallel tasks has worked well (startup/state/loading, world generator, entities/AI,
renderer), each with precisely defined inputs (paths, `showfn.py`, `fixups.txt`,
known anchors) and an output = markdown with offset tables + "V/G" (verified /
guess). Templates are in `AGENT_PROMPTS.md`. Agents should also have
reference dumps (save/demo files) and the Python tools available so they can
**measure** their hypotheses (e.g. "100 % height match") – that is the main difference
between an impression and a fact.

## 6. Port

- First the data formats + an extractor (PNG/JSON), then debug viewers
  in the engine (asset verification), then the deterministic cores (world generator,
  RNG) with bit-exact verification against dumps, and only then the game logic.
- Always keep the original's integer arithmetic (16/32-bit wrap, `>>` as `sar`,
  `%` as an unsigned 16-bit `div`) – otherwise the world does not match the seed.
- Godot 4: `--headless -s script.gd` for verification without a window; run
  with `-- --screenshot=out.png` for a visual check.
- Godot input: full-screen `Control` nodes (containers, `ColorRect` backgrounds,
  HUD canvas) default to `mouse_filter = STOP` and "eat" the mouse before it
  reaches the game's `_unhandled_input` → read game input in `_input` and set decorative
  Controls to `MOUSE_FILTER_IGNORE`. Verify with a script that sends
  `Input.parse_input_event` to the main scene (note: in headless mode Godot
  rescales relative mouse motion by the window size – calibrate).
- Copy the mouse controls from the original exactly (e.g. cursor position relative to
  the centre as a joystick vs. relative motion).
- `-s` scripts: autoloads do not exist yet in `_init` – load scenes that
  use them in the first frame.

## 7. Win32 PE (`analyze_pe.ps1`)

1. `python -I tools\strings_scan.py GAME.EXE <out>\strings` – string inventory even before
   import (source paths from asserts, data file names, extensions).
2. `pwsh analyze_pe.ps1 -Exe GAME.EXE -Out <out>` – import, auto-analysis, export
   (+ `imports.txt` from `DumpImports.java`).
3. Auto-analysis does not find functions called only through pointer tables (vtables, handler
   tables in `.rdata`/`.data`) or code after `CC` padding without direct references.
   `tools\find_entries.py` lists such addresses in `.text` that are not in any function;
   `analyze_pe.ps1 -SkipImport -Entries entries.txt` creates functions there
   (`CreateFunctionsAtEntries.java` as a pre-script) and runs re-analysis and export.
   Repeat while new addresses keep appearing.
4. Programs with assert/log strings containing source paths (`.\ui\menu.cpp` + line number):
   `tools\module_map.py` maps functions to source files and modules. Module rules
   (`regex<TAB>module`, first match wins) live in the `--rules` file. Functions without a direct
   reference inherit the module from their neighbours (MSVC links object files contiguously).
5. Names: the same `names_*.csv` format, `analyze_pe.ps1 -SkipImport -Names <out>\notes`.
