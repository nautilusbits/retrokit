# Reverse engineering an old game (DOS/4GW LE, Win32 PE)

## 0. Identifying the binary

```
python -c "d=open('GAME.EXE','rb').read();o=int.from_bytes(d[0x3c:0x40],'little');print(hex(o), d[o:o+2])"
```
`retrokit info GAME.EXE` does all of this section (format, BW chain, extender, compiler,
calling convention). By hand:

- `b'LE'` → DOS/4GW / DOS32A / PMODE/W, 32-bit flat → LE pipeline.
- `b'LX'` → OS/2 (`-Loader LxLoader`).
- `b'PE'` → Win32 → PE pipeline (section 7). `b'NE'` → Ghidra handles it natively.
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

The kit's own loader (`retrokit/le-loader`, built against your Ghidra by
`retrokit install-loader`) sets up the objects from the LE table (including r/w/x permissions
from the LE flags; typically code in object 1 from 0x10000, data in the next object – see
`memory_blocks.txt`), **applies the fixups** (important – without them there are no references
to strings/data) and writes them into the Ghidra relocation table. It also loads DOS/4G
BW-bound files, OS/2 LX modules (imports as external locations) and VxDs.

`x86watcom.cspec` has two prototypes:
- `__watcall_stack` (**default**): arguments pushed, caller cleans up
  (`ADD ESP,n`), EAX/ECX/EDX scratch, EBX/ESI/EDI/EBP preserved. Used by game code
  compiled with `-3s/-5s`.
- `__watcall`: register convention `-3r/-5r` (EAX, EDX, EBX, ECX), callee cleans up.
  The Watcom runtime (libc) mostly uses this convention.

**How to tell which one applies:** `retrokit info GAME.EXE` (statistics over
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

## 2. LE pipeline (`retrokit analyze`) – what it does and why

1. Import + standard auto-analysis (on the order of minutes for hundreds of KB of code).
2. `CreateFunctionsFromFixups.java`: walks the relocation table; every 32-bit
   fixup pointing into the code object where there is no function yet gets disassembled
   and turned into a function. Watcom also stores `switch` jump tables in the code
   object; a table is recognised by the fixup in the operand of an indirect `JMP`, its
   slots become pointers and its cases stay inside the switch's function. Watcom games call a large part of their logic through
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
4. `MarkStringsConstant.java`: defines the short strings Ghidra's ASCII analyzer skips
   (fewer than 5 characters, e.g. `"seed"`, `"rb"`) wherever code takes their address, then
   marks strings in the writable data object as `constant` so the decompiler prints
   `"text"` literals (otherwise `&DAT_xxx`).
5. Library functions (skip with `--no-sigs`): before the export pass `retrokit` looks for the
   shipped Watcom C library signatures (and your own, see below) in the code without Ghidra,
   creates functions where they start, names them (`notes/sigs/names_sigs.csv`, applied before
   your own names so yours win) and `ApplyLibraryPrototypes.java` gives every function declared
   in `retrokit/knowledge/*.h` its documented prototype (`size_t strlen(char *s)`,
   `FILE *fopen(...)`, variadic `printf` on the stack). These functions are tagged `LIBRARY`
   and the next two passes leave them alone; their callers then see real types.
6. Parameter counts and prototypes (skip with `--no-prototypes`):
   - `ApplyStackConvention.java`: parameter counts from `ADD ESP,n` right after calls
     (only counted when n/4 argument pushes precede the call – otherwise the ADD releases
     the caller's frame). Stack convention: every such function gets n/4 parameters, and
     functions ending in `RET n` (e.g. the stack check `__CHK`) get `__stdcall`. Register
     convention: these are the functions called through the stack and get `__cdecl`.
     If n differs between calls the function is varargs (sprintf…): the fixed parameters
     end at the argument that is a format string, `...` follows, the signature is locked.
   - `RecoverPrototypes.java`: prototypes from the decompiler **bottom-up** by
     call-graph level (in parallel within a level); functions with counts from step 6a
     only get their return type. A `void` or untyped 8-byte return is never committed
     (both turn call sites into `extraout_*`). Trailing `unaff_*` parameters are dropped
     unless at least half of the callers set the register right before the `CALL`
     (e.g. `main(argc=EAX, argv=EDX)`) or – register convention – the function reads the
     register without saving it in its prologue: a Watcom callee saves every register it
     modifies except EAX and its argument registers. This also works for functions only
     called through pointer tables. Kept register parameters are renamed `param_N`.
7. `ExportDecompiled.java` + `DumpFixups.java`.

**Library signatures.** A signature is the code of one library function exactly as the linker
placed it, with fixup fields and the rel32 operands of calls/jumps leaving the function
masked; calls to other library functions are kept as callee names and confirm short or
ambiguous matches (functions with identical code such as `atoi`/`atol` get the documented name
and a `G` comment). The shipped sets (`retrokit/sigs/`) come from Open Watcom 2.0 and 1.9
(`clib3r`/`clib3s` + `math3r`/`math3s`, DOS) and name ~90 % of the run-time of a program built
with those compilers, with no wrong names on the test programs.

Code from another compiler version (the original Watcom 10.x/11.0 run-time) differs byte for
byte, so few functions match exactly. A **fuzzy tier** follows: every call target and code
pointer the exact pass did not name is compared with the signatures as a normalised
instruction stream (registers abstracted, addresses masked; sequence similarity plus an
order-free comparison for moved blocks); a name is taken at similarity >= 0.80 (0.70 with an
agreeing callee) when it beats every other name by 0.08, and short functions that only call
others need a matching callee. Fuzzy names are always `G`. Measured: between Open Watcom 1.9
and 2.0 it adds ~20 correct names per test program (one wrong: a function renamed between the
versions); on a 1994 Watcom 10.0 program it raised the named run-time from 17 to 73 functions.
`--exact-sigs` (analyze) / `--exact` (sigs match) switch it off.

If you own an old Watcom, build signatures from its libraries – they stay on your machine and
are picked up automatically from `~/.retrokit/sigs/`:

```
retrokit sigs build --watcom C:\WATCOM --lib C:\WATCOM\lib386\dos\clib3r.lib --lib C:\WATCOM\lib386\math3r.lib -o ~/.retrokit/sigs/watcom106-clib3r.sig
retrokit sigs match GAME.EXE          # what would be named, without Ghidra
retrokit sigs learn GAME_analysis -o ~/.retrokit/sigs/game-lib.sig --names GAME_analysis/notes/names_clib.csv
```

The shipped sets are rebuilt with `scripts/build_sigs.py` (Open Watcom 2.0 + 1.9 run-time;
zlib and libjpeg sources compiled with `-3`/`-5` x `-ox`/`-oneatx` x stack checks on/off in
both conventions, because the switches a game was built with change the code more than the
library version does).

`retrokit libs GAME.EXE` lists the libraries of the period the game uses (catalog:
`retrokit/knowledge/libraries.json`) with the evidence (strings, imported DLLs and functions,
driver and data files with their signatures), the version where the library embeds one, what
the kit has for it and notes on formats and porting; `analyze` writes the same into
`notes/libraries.md`. Proprietary libraries (Miles, HMI, Smacker, Bink, ...) have no shipped
signatures - Win32 games import their functions by name, for DOS builds use `sigs learn`.

`sigs build` links every public of the libraries into one reference program with `wlink`
(any OMF library works: sound, graphics or compression libraries of the period), `sigs learn`
turns functions you identified in one analysed program into signatures for the next program
built with the same tools.

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
with thousands of functions it runs for tens of minutes without a result; `RecoverPrototypes.java`
is the parallel replacement and runs by default.

Every change to the pipeline is measured on the synthetic test programs (`tests/`), see
`tests/README.md`.

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
   **unrelocated** in the file): `retrokit le GAME.EXE rec ADDR N SIZE fmt` reads them
   straight from the EXE (Ghidra addresses); add the object base to pointers (see
   `memory_blocks.txt` or `retrokit le GAME.EXE info`) or look in `fixups.txt`.

## 4. Data formats (common in DOS-era games)

- **Music, sound, video**: `retrokit convert GAME_DIR [-o OUT]` finds the files by content
  (not by extension; `--list` only reports) and converts them:
  - XMIDI (`FORM XDIR` / `FORM XMID`; Miles AIL, MIDPAK) -> one standard MIDI file per
    sequence. Sequence 1 is often an empty set-up sequence. AIL plays at 120 Hz; the XMIDI
    tempo events are dropped (the delays already include them). Files often come in pairs
    for MT-32 and General MIDI (`*GM.XMI`), and the MT-32 ones also need the custom timbres
    (`TIMB` chunk) to sound right.
  - HMI (`HMI-MIDISONG`) and HMP (`HMIMIDIP`), HMI SOS -> standard MIDI. HMI's own loop
    and branch events (0xFE) are skipped.
  - VOC (Creative Voice File) -> WAV: 8-bit unsigned and 16-bit signed PCM, silence,
    extended and new-format blocks; Creative ADPCM blocks are reported, not decoded.
  - Smacker (`SMK2`/`SMK4`), Bink (`BIK`), FLI/FLC -> MP4 through FFmpeg.
  Verified on game files: every track of a few dozen HMI songs parses to its end-of-track
  event and MT-32 / GM versions of the same XMIDI songs come out with the same length;
  HMP only with synthetic test files so far.
- **RNC ProPack** (`RNC\x01`): `retrokit rnc` (method 1, CRC verified).
  Common in both DOS and Amiga games.
- `.TAB/.DAT` style sprite banks: TAB 6 B `{offset u32, w u8, h u8}`, RLE
  rows (0 end, <128 copy N, ≥128 skip 256−N).
- 768 B palettes, 6-bit VGA.
- **Autodesk FLIC** (FLI 0xAF11 / FLC 0xAF12, frames 0xF1FA): cutscenes as well as
  animated sprites. `retrokit flic info|png|video` – also handles the stripped 12-byte
  header, 6/8-bit palette detected automatically. Games often change the frame rate during
  a video (a table of "cue" commands in the EXE: delays, sounds, music) – find the
  player (calls the FLIC decoder in a loop) and its table; then render the video
  at a fixed 60 fps with repeated frames and trigger sounds by time.
  Godot plays `.ogv` (Theora) without import: `VideoStreamTheora.new().file = path`.
- Document formats as you go (`notes\formats.md`: offset, size, meaning, V/G).

## 4b. Related EXEs (add-on, sequel, other version) – transferring names

Once one game is analyzed (names in `notes\names_*.csv`), a second one on the same engine
does not have to be analyzed from scratch:

1. Run the new EXE through `retrokit analyze` as usual.
2. Copy `decomp\` to `decomp_unnamed\` (matching must run on an export without transferred names).
3. `retrokit match --a-exe A.EXE --a-decomp A\decomp --a-names A\notes\merged\names_all.csv
   --b-exe B.EXE --b-decomp B\decomp_unnamed --out B\notes\match --names-out B\notes\names_match.csv`
   – matches functions (bytes with masked fixups, unique string sets, call-graph neighbourhood,
   shared "anchors" = mapped global data + matched callees/callers, fuzzy instruction similarity);
   aligned instructions of matched functions vote on an A → B data address map (`data_map.csv`).
4. `retrokit names B B\notes\names_match.csv`.

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

## 7. Win32 PE pipeline

1. `retrokit strings GAME.EXE <out>\strings` – string inventory even before
   import (source paths from asserts, data file names, extensions).
2. `retrokit analyze GAME.EXE` – import, auto-analysis, entry passes (3.), the string /
   parameter / prototype passes of the LE pipeline (MSVC `__cdecl` cleans up with `ADD ESP,n`
   too, `__stdcall` with `RET n`), export (+ `imports.txt`, `fixups.txt` from the base relocations).
3. Auto-analysis does not find functions called only through pointer tables (vtables, handler
   tables in `.rdata`/`.data`) or code after `CC` padding without direct references.
   `find_entries.py` lists such addresses in the code section that are not in any function;
   the pipeline creates functions there (`CreateFunctionsAtEntries.java`), re-analyses and
   repeats while new functions appear (`--entry-passes N`, default 3). `retrokit entries WS`
   writes the list for a manual `retrokit reexport WS --entries FILE`.
4. Programs with assert/log strings containing source paths (`.\ui\menu.cpp` + line number):
   `retrokit modules WS --rules rules.tsv` maps functions to source files and modules. Module rules
   (`regex<TAB>module`, first match wins) live in the `--rules` file. Functions without a direct
   reference inherit the module from their neighbours (MSVC links object files contiguously).
5. Names: the same `names_*.csv` format, `retrokit names WS`.
