# Roadmap

Scope: 32-bit x86 games from roughly 1993 to 2010 – DOS (LE/LX, Watcom first) and Win32 PE.
Out of scope: x64, .NET, consoles, 16-bit DOS, bypassing copy protection.

Rules: the repository contains no game binaries, no game code and no decompiled output;
library signatures are shipped only when built from open-source or public-domain code.

1. ~~License (Apache 2.0), repository hygiene~~
2. ~~Test corpus: synthetic programs built with Open Watcom, scored against the linker map, CI~~
3. ~~Python CLI (`retrokit doctor | install-loader | info | analyze | reexport | names | show | ...`),
   automatic format and calling-convention detection, settings remembered per workspace,
   PowerShell scripts replaced, runs on Windows and Linux~~
4. ~~Own LE/LX loader (retrokit-le-loader), identical to the legacy loader on every LE test
   program, checked against an independent Python model (LX, imports, BW bind included)~~
   - open: Watcom debug info, PMODE/W compressed executables, LX EXEPACK2 pages
   - open: LX programs linked without internal fixups (OS/2 EXEs) - pointer tables cannot be
     found from fixups; scan the data objects for code pointers instead (as find_entries does
     for PE)
5. Library knowledge base: detection rules (strings, imports, file signatures), prototypes,
   format notes and porting hints per library; signature generator
   - done: signature format + matcher (`retrokit sigs`, applied by `analyze`), generator for OMF
     libraries via wlink (`sigs build`), signatures learned from a named workspace (`sigs learn`),
     shipped Open Watcom 2.0 / 1.9 DOS clib + math signatures, C library prototypes
     (`knowledge/watcom_clib.h`, `ApplyLibraryPrototypes`)
   - done: fuzzy tier for other compiler versions (`retrokit/fuzzy.py`); open: tune it on more
     Watcom 10.x/11.0 programs, PE (MSVC) libraries
   - open: floating-point prototypes (how Watcom passes doubles depends on the -fp switch)
   - done: library catalog with detection rules, versions and notes (`knowledge/libraries.json`,
     `retrokit libs`), zlib 1.0.4-1.2.3 and libjpeg 6b signatures + prototypes, Open Watcom
     math387 and C++ run-time signatures, `scripts/build_sigs.py`
   - open: prototypes for the APIs of proprietary libraries (Miles, Smacker, Bink, HMI) - with
     Win32 (step 9), where they are imported by name; AIL 2.0 is 16-bit only; libpng, Lua
6. ~~Data formats: `retrokit convert` - XMIDI, HMI, HMP -> MIDI, VOC -> WAV, Smacker/Bink/FLIC
   via FFmpeg~~
   - open: Creative ADPCM in VOC, MT-32 timbres (XMIDI TIMB, AIL global timbre library) for
     faithful MT-32 output, DMX MUS, CMF, HMP checked on real files
7. ~~MCP server over the export (`retrokit mcp`: function/xref/string/table/disassembly queries,
   name proposals, notes, guarded background re-export)~~
8. ~~Release 0.1 (DOS)~~
9. ~~Win32: MSVC RTTI (classes, vtables), DirectX 3-9 COM interfaces, RAD/FMOD/BASS prototypes,
   MSVC CRT identification~~ - Rich header version, `sigs build --coff`, `sigs learn` for PE
   - open: QueryInterface results, C++ member functions (`this` in ECX, __thiscall) from RTTI,
     DirectX structures (DDSURFACEDESC, ...) instead of void *, more Win32 libraries
   - open (PE pipeline): a code address used as data (`mov esi, offset table`) can become a
     bogus function whose decompilation runs into the next function

## Known pipeline problems found by the test corpus

See `tests/baseline.json` for the current numbers. Fixed: switch functions cut short,
`undefined f(void)` signatures with the stack convention, missing register parameters of
table-only functions, one fixed parameter too many on varargs functions, short strings
not shown as literals.

Open:
- Stack convention: functions only reached through pointer tables have no call-site cleanup
  to count; the decompiler misses parameters they never read (e.g. an empty draw handler).
- Without optimization (`-od`) a few 64-bit helpers keep 0 parameters.
- Most remaining noise (`extraout_`, `unaff_`, `in_*`) is in the Watcom runtime, which the
  library signatures (step 5) will name and type.
