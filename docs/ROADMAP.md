# Roadmap

Scope: 32-bit x86 games from roughly 1993 to 2010 – DOS (LE/LX, Watcom first) and Win32 PE.
Out of scope: x64, .NET, consoles, 16-bit DOS, bypassing copy protection.

Rules: the repository contains no game binaries, no game code and no decompiled output;
library signatures are shipped only when built from open-source or public-domain code.

1. ~~License (Apache 2.0), repository hygiene~~
2. ~~Test corpus: synthetic programs built with Open Watcom, scored against the linker map, CI~~
3. Python CLI (`retrokit doctor | install-loader | analyze | show | names | extract`), automatic
   format and calling-convention detection, settings remembered per workspace, cross-platform
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

See `tests/baseline.json` for the current numbers.

- Functions with a `switch` are cut short (jump table not followed) in both conventions.
- Stack convention: exported signatures are `undefined f(void)` unless `-Prototypes` is used,
  although the decompiled call sites mostly have the right arguments.
- Register convention: functions reached only through pointer tables get too few parameters;
  varargs functions get one fixed parameter too many.
- String literals passed in registers are often printed as data references, not `"..."`.
