# retrokit-le-loader

Ghidra loader for Linear Executables, part of retro-kit:

- DOS extender programs in LE format: DOS/4GW, DOS/32A, PMODE/W, CauseWay; also DOS/4G
  "BW"-bound files (old-style MZ stub, BW header chain, then the bound program - its LE offsets
  are relative to that program's MZ header)
- OS/2 LX modules (imports by ordinal or name become external locations, exports labels;
  EXEPACK1 iterated pages)
- Windows VxDs (LE)

What it produces: one block `.objectN` per object at its base address (objects without a base
go to N * 0x100000) with the object's read/write/execute permissions; every fixup applied and
recorded in the relocation table (type = LE source type, status APPLIED, the written value);
the entry point `_entry`; the raw file as overlay `.image` with typed MZ / BW / LE headers and
the object table. Option: override object base addresses (to match a debugger's layout).

Also ships the Watcom compiler specs (`data/languages/`): `watcom` (stack convention -3s/-5s)
and `watcomreg` (register convention -3r/-5r).

Install with `retrokit install-loader` (compiles against your Ghidra 12.x, registers the specs).
Tested by `tests/check_loader.py`: every LE/LX test program is loaded and compared with an
independent Python model of the image (`retrokit/formats.py`).

Not supported yet: LX EXEPACK2 compressed pages, PMODE/W compressed executables, Watcom debug
information.
