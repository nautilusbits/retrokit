# Changelog

## 0.1.0 - 2026-10-14

First public release: DOS (LE/LX, Watcom) analysis end to end, Win32 PE pipeline.

- **CLI** `retrokit`: `doctor`, `install-loader`, `info`, `analyze`, `reexport`, `names`,
  `show`, `tables`, `entries`, `modules`, `strings`, `match`, `libs`, `sigs`, `convert`,
  `mcp`, `le`, `rnc`, `flic`. Workspaces remember how a binary was analysed.
- **LE/LX loader** for Ghidra 12 (DOS/4GW, DOS/32A, PMODE/W, CauseWay, DOS/4G bind, OS/2 LX,
  VxD): objects with permissions, fixups applied and recorded, imports, exports, header
  structures; checked against an independent Python model of each image.
- **Watcom compiler specs** for the register and the stack calling convention, detected
  automatically.
- **Pipeline**: functions from fixup targets and pointer tables, switch tables kept inside
  their functions, wrong no-return flags undone, short strings as literals, parameter
  counts from call-site cleanup, prototypes recovered callees-first.
- **Library signatures**: Open Watcom 2.0 / 1.9 C run-time, math and C++ libraries, zlib
  1.0.4-1.2.3 and libjpeg 6b, exact and fuzzy matching (other compiler versions and
  switches); prototypes from `knowledge/*.h`; `sigs build` / `sigs learn` for local sets.
- **Library catalog** (`retrokit libs`): about 20 libraries of the period recognised from
  strings, imports and data files, with notes on formats and porting.
- **Data formats** (`retrokit convert`): XMIDI, HMI, HMP -> MIDI, VOC -> WAV, Smacker / Bink
  / FLIC -> MP4 via FFmpeg; RNC ProPack and FLIC tools.
- **MCP server** (`retrokit mcp`) for AI agents over a workspace; guide in `docs/MCP.md`,
  `AGENTS.md` for agents.
- **Test corpus**: synthetic programs built with Open Watcom, scored against the linker map
  (function coverage, parameter counts, call arguments, string literals, library names,
  decompiler noise) with a baseline; CI on Windows and Linux.

Known limitations: Watcom debug information, PMODE/W compressed executables and LX
EXEPACK2 pages are not read; OS/2 LX programs without internal fixups get fewer functions;
proprietary libraries (Miles, HMI, Smacker, Bink) are recognised but have no shipped
signatures; floating-point library prototypes are left to the decompiler.
