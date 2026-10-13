# Roadmap

Scope: 32-bit x86 games from roughly 1993 to 2010 – DOS (LE/LX, Watcom first) and Win32 PE.
Out of scope: x64, .NET, consoles, 16-bit DOS, bypassing copy protection.

Rules: the repository contains no game binaries, no game code and no decompiled output;
library signatures are shipped only when built from open-source or public-domain code.

1. ~~License (Apache 2.0), repository hygiene~~
2. ~~Test corpus: synthetic programs built with Open Watcom, scored against the linker map, CI~~
3. ~~Python CLI (`retrokit doctor | install-loader | info | analyze | reexport | names | show | ...`),
   automatic format and calling-convention detection, settings remembered per workspace,
   PowerShell scripts replaced (Linux run in CI not verified yet)~~
4. Own LE/LX loader, validated against the current one on the test corpus; Watcom debug info,
   PMODE/W compressed pages
5. Library knowledge base: detection rules (strings, imports, file signatures), prototypes,
   format notes and porting hints per library; signature generator
   - shipped signatures: Watcom clib (Open Watcom sources), AIL 2.0 (public domain), zlib, ...
   - locally generated signatures from SDKs the user owns; signatures learned from analysed binaries
6. Data formats: XMIDI -> MIDI, Miles driver files, VOC, Smacker/Bink via FFmpeg
7. MCP server over the export (function/xref/string/table queries, name proposals, guarded re-export)
8. Release 0.1 (DOS)
9. Win32: MSVC RTTI (classes, vtables), DirectX 3-9 COM interfaces, RAD/FMOD/BASS prototypes,
   MSVC CRT identification

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
