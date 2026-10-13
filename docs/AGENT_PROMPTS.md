# Task templates for AI agents (decompilation analysis)

With an MCP client the agent can work through the retro-kit MCP server instead of reading
files: `retrokit mcp <OUT>` (e.g. `claude mcp add retrokit -- retrokit mcp <OUT>`). Tools:
workspace_info, libraries, list_functions, get_function, call_graph, xrefs, search_code,
strings, pointer_tables, disassemble, read_bytes (read); propose_names, write_note (write
to notes/ only); reexport + reexport_status (Ghidra, needs confirm=true). The templates below
work the same way - replace "read the file" with the matching tool, and give one agent the
right to reexport while the others only read and propose.

Common header (fill in the paths):

```
You are reverse-engineering <GAME> (<platform>, <year>, <compiler>, e.g. DOS/4GW + Watcom C
or Win32 + MSVC) from a Ghidra decompilation, to port it to <engine>. Work ONLY with files;
do not run Ghidra.

Workspace: <OUT>
- decomp\<exe>_decompiled.c – decompiled C of all functions (FUN_<addr>). Code and data ranges
  are in decomp\memory_blocks.txt (code 0x<start>-0x<end>, data 0x<base>-0x<end>).
- decomp\functions.csv (addr,name,size,callers,callees,cc,signature), calls.txt (caller -> callee),
  strings.txt, data_symbols.txt.
- LE only: fixups.txt (source addr -> target addr, type, kind FUNC/INFUNC/DATA, containing
  function, target string). Function pointers stored in data = kind FUNC with source >= data base.
  `retrokit le <EXE> rec ADDR N SIZE [fmt]` reads raw constant tables from the EXE at Ghidra addresses.
- PE only: imports.txt (LIB, name, IAT slots); optional module map from `retrokit modules <OUT>`.
- `retrokit show <OUT> FUN_00012345 ...` prints functions, `retrokit tables <OUT>` pointer tables.
  Prefer it over reading the whole file. Grep the .c for globals (DAT_xxx).
- Known facts: <calling convention, identified helpers, anchors found so far>.
- Reference data: <save/demo dumps, extracted assets, format docs>.

Be rigorous: cite function addresses and decompiled statements; mark each claim V (verified)
or G (guess); propose function names; report a summary at the end.
Write your findings to <OUT>\notes\<topic>.md and name proposals to <OUT>\notes\names_<topic>.csv
with header `addr,name,confidence,comment` (addr 8 hex digits, C identifier, V or G).
Do not run Ghidra and do not modify <OUT>\decomp while other agents are reading it.
```

## Task A – program structure and game state
```
YOUR TASK: main() and startup order; command-line keywords; the main loop and per-frame order
(input, tick, render, flip); timer/tick rate; how a level starts/ends; every data file -> loader
function -> receiving global + in-memory format; the layout of the big global structs (every
offset with meaning and size), cross-checked against save-game dumps; save/demo file formats.
```

## Task B – world / level generator (deterministic core)
```
YOUR TASK: fully understand <world generation> and write (1) notes with every function, the PRNG
(exact formula and width), how each parameter is used, memory layout of the map planes, constant
tables (addresses + dump); (2) a faithful Python port with exact 8/16/32-bit integer semantics,
plus a __main__ that compares its output with the reference dump <file> and prints measured match
percentages. Do not claim a match you did not measure.
```

## Task C – entities / AI / rules
```
YOUR TASK: the entity ("thing") struct (size, every field), the pool/allocation, spatial index,
how level records are instantiated (per class), the per-class/model descriptor tables with
function pointers (record layout, state machine, update dispatch), AI overview per enemy/unit type,
economy (health/ammo/resources), abilities/weapons table with constants, triggers/switches.
```

## Task D – renderer and world representation
```
YOUR TASK: map memory layout as used by the renderer (planes, strides, meaning, coordinate
scales, wrap-around), camera model (position, eye offset, FOV, near/far, fog), terrain texturing
(texture index math, orientation, lighting tables), sprite drawing (scaling, direction frames,
animation format, shadows, translucency), buildings/models, HUD – enough to reproduce the look
in a modern engine. Give a "parameter summary" table for the target engine.
```

When done: check the reported "pitfalls" (no-return errors, functions that were not
created), apply the names (`retrokit names <OUT>`, which re-exports); copy the agents' helper scripts from their temporary scratchpad to
`notes\data\`, otherwise they are lost.
