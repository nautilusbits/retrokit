# retro-kit – reverse engineering old games (headless Ghidra)

A toolkit for decompiling old games with headless Ghidra. Two pipelines:

- `analyze.ps1` – 32-bit DOS games in LE/LX format (DOS/4GW, DOS32A, PMODE/W),
  compiled with Watcom C/C++.
- `analyze_pe.ps1` – Win32 PE (typically MSVC).

The output is one large `.c` file with every function plus indexes (functions, call graph,
strings, data) that you can grep and split up between AI agents.

```
retro-kit/
  analyze.ps1            pipeline for DOS LE/LX (Watcom)
  analyze_pe.ps1         pipeline for Win32 PE (MSVC)
  ghidra-lx-loader/      LE/LX loader for Ghidra (sources, build.ps1, prebuilt zip)
    data/languages/x86watcom.cspec       Watcom compiler spec, default stack convention (id "watcom")
    data/languages/x86watcom_reg.cspec   the same, default register convention (id "watcomreg")
  ghidra_scripts/        headless scripts (see below)
  tools/                 Python tools (see below)
  docs/WORKFLOW.md       detailed procedure, what to expect, known pitfalls
  docs/AGENT_PROMPTS.md  task templates for AI agents (subsystem analysis)
```

## License

Apache License 2.0 (`LICENSE`). The `ghidra-lx-loader` loader is derived from the upstream
project [yetmorecode/ghidra-lx-loader](https://github.com/yetmorecode/ghidra-lx-loader)
(also Apache 2.0); the changes are listed in `NOTICE`.

retro-kit contains no game files and no decompiled game code. Use it only on software you own.

## Prerequisites

Ghidra 12.x (unpacked), JDK 21+ (`JAVA_HOME`), PowerShell 7, Python 3
(`detect_cc.py` needs `capstone`).

Ghidra is looked up in this order: the `-Ghidra` parameter, `$env:GHIDRA_INSTALL_DIR`,
`<kit>\..\ghidra`, `<kit>\ghidra` (the directory containing `support\analyzeHeadless.bat`).

Recommended layout (then no paths need to be given):
```
<game>\GAME.EXE
<game>\ghidra\           unpacked Ghidra
<game>\retro-kit\
```

## Pipeline 1: DOS LE/LX (`analyze.ps1`)

1. **Install the loader + cspec** (once per Ghidra installation):
   ```
   pwsh retro-kit\ghidra-lx-loader\build.ps1                      # Ghidra in ..\ghidra or ..\..\ghidra
   pwsh retro-kit\ghidra-lx-loader\build.ps1 -GhidraDir <ghidra>
   ```
   Compiles the plugin directly with `javac` against the Ghidra jars (no Gradle needed),
   installs it into `Ghidra\Extensions\ghidra-lx-loader` and registers
   `x86watcom.cspec` + `x86watcom_reg.cspec` in `Processors\x86\data\languages\x86.ldefs`.
   For a different Ghidra version just run it again – the version is filled in automatically.
   (The prebuilt zip targets a single Ghidra version and can also be installed via
   `File > Install Extensions`, but the cspec would then have to be installed by hand.)

2. **Detect the calling convention and run the pipeline:**
   ```
   python retro-kit\tools\detect_cc.py GAME.EXE          # => -Cspec watcom or watcomreg
   pwsh retro-kit\analyze.ps1 -Exe GAME.EXE -Cspec watcomreg
   pwsh retro-kit\analyze.ps1 -Ghidra <ghidra> -Exe <dir>\GAME.EXE -Out <out>
   ```
   Parameters:
   - `-Cspec watcom|watcomreg` – stack (`-3s/-5s`, default) or register (`-3r/-5r`) convention
   - `-Loader LeLoader|LxLoader|VxDLoader` – LE (default), OS/2 LX, VxD
   - `-SkipImport` – no import: rerun the fixup pass + export on the existing project
   - `-Names <dir|csv>` – applies name proposals from `names_*.csv` before export
   - `-NoPrototypes` – skips parameter counts from call sites and the bottom-up prototype recovery
   - `-CName` – name of the output `.c` (default `<exe>_decompiled.c`)

   Output in `<out>\decomp\` (default `<out>` = `<EXE directory>\<exe>_analysis`):
   - `<exe>_decompiled.c` – decompiled C code of all functions
   - `functions.csv` – address, name, size, caller/callee counts, convention, signature
   - `strings.txt`, `calls.txt` (call graph), `data_symbols.txt`, `memory_blocks.txt`
   - `fixups.txt` – every LE fixup: source → target (function/string) – the key
     to function-pointer tables and to which function uses which string
   - before export, parameter counts are taken from `ADD ESP` cleanups at call sites (varargs
     functions split at their format string) and prototypes are recovered bottom-up

3. **Read:** `python tools\showfn.py --dir <out>\decomp FUN_00012345`,
   `python tools\find_tables.py <out>\decomp\fixups.txt`.

4. **Names back into Ghidra:** agents write proposals to `notes\names_<topic>.csv`
   (`addr,name,confidence,comment`); then
   `pwsh retro-kit\analyze.ps1 -Exe GAME.EXE -Cspec ... -SkipImport -Names <out>\notes`
   renames functions/labels (V takes precedence over G, collisions get `_<addr>`) and re-exports.

## Pipeline 2: Win32 PE (`analyze_pe.ps1`)

Uses Ghidra's standard PE loader, no plugin needed.

```
pwsh retro-kit\analyze_pe.ps1 -Exe GAME.EXE -Out <out>
python -I retro-kit\tools\find_entries.py GAME.EXE <out>\decomp entries.txt   # code addresses without a function
python -I retro-kit\tools\module_map.py <out>\decomp <out>\notes --rules rules.tsv  # functions -> source files
pwsh retro-kit\analyze_pe.ps1 -Exe GAME.EXE -Out <out> -SkipImport -Entries entries.txt
pwsh retro-kit\analyze_pe.ps1 -Exe GAME.EXE -Out <out> -SkipImport -Names <out>\notes
```
Without switches: import + standard auto-analysis, then export. Parameters:
- `-Entries <file>` – one hex address per line; creates functions at these addresses
  (pointer-table targets that auto-analysis missed) and runs re-analysis
- `-Names <dir|csv>` – applies `names_*.csv` before export
- `-SkipImport` – works on the existing project
- `-NoExport` – only import / function creation, no export
- `-CName` – name of the output `.c`

Output in `<out>\decomp\`: `<exe>_decompiled.c`, `functions.csv`, `calls.txt`, `strings.txt`,
`data_symbols.txt`, `memory_blocks.txt`, `imports.txt` (library, name, IAT slots).

## Ghidra scripts (`ghidra_scripts/`)

| script | purpose |
|---|---|
| `CreateFunctionsFromFixups.java` | LE: functions at the targets of 32-bit fixups into code (pointer tables) |
| `CreateFunctionsAtEntries.java` | functions at given addresses (list or `@file`), optionally from fixups or prologues in code gaps |
| `FixTruncatedCallers.java` | clears a wrong "no return" that truncates callers |
| `FixAnalysis.java` | manual fixes: `noreturn:ADDR`, `func:ADDR` |
| `MarkStringsConstant.java` | marks strings in writable data as `constant` (literals in the decompilation) |
| `ApplyStackConvention.java` | `__cdecl`/varargs based on `ADD ESP,n` at call sites |
| `RecoverPrototypes.java` | prototypes from the decompiler, bottom-up by call-graph level |
| `ApplyNames.java` | names from `names_*.csv` |
| `ExportDecompiled.java` | exports `.c` + `functions.csv`, `calls.txt`, `strings.txt`, … |
| `DumpFixups.java` | LE fixups → `fixups.txt` |
| `DumpImports.java` | PE imports and IAT slots → `imports.txt` |
| `DumpDisasm.java` | disassembly of a function to stdout |
| `EnableDeepAnalysis.java` | turns on the slow analyzers (not recommended, see WORKFLOW) |

## Python tools (`tools/`)

| tool | purpose |
|---|---|
| `detect_cc.py` | LE: stack vs. register Watcom convention, before import (capstone) |
| `le.py` | reads tables from an LE EXE at Ghidra addresses, including DOS/4G "BW"-bound files |
| `showfn.py` | prints selected functions from the export |
| `find_tables.py` | pointer tables (function pointers, strings) from `fixups.txt` |
| `find_entries.py` | PE: addresses in `.text` without a Ghidra function – pointer-table targets in `.rdata`/`.data` and gap starts after `CC` padding; input for `analyze_pe.ps1 -Entries` |
| `strings_scan.py` | PE string inventory without Ghidra (ASCII, UTF-16LE, source paths, file extensions) |
| `module_map.py` | maps functions to the original source files/modules using assert strings with `.cpp` paths; module rules in the `--rules` file (TSV `regex<TAB>module`) |
| `match_names.py` | transfers names from an analyzed EXE to a related one (sequel, add-on, other version) |
| `rnc.py` | RNC ProPack decompressor |
| `flic.py` | Autodesk FLI/FLC: info / PNG / video via ffmpeg |

## Typical settings

- **LE with a stub** (MZ stub, LE header via `e_lfanew`): `-Loader LeLoader`, the loader finds the LE itself.
- **DOS/4G BW-bound** (after the MZ stub come `BW` headers → a second MZ → LE): also `LeLoader`;
  page offsets are relative to the second MZ (both the loader and `le.py` handle this).
- **Stack convention** (`PUSH` before `CALL`, `ADD ESP,n` after it): `-Cspec watcom`.
- **Register convention** (arguments in EAX/EDX/EBX/ECX, `RET n`): `-Cspec watcomreg`;
  varargs functions (printf…) still use the stack – handled by `ApplyStackConvention.java`.
- **Win32 PE / MSVC**: `analyze_pe.ps1`; after the first run add functions via `find_entries.py` + `-Entries`.

Details and typical problems: `docs/WORKFLOW.md`.

## Tests

`tests/` builds small synthetic programs with Open Watcom (a dev/CI dependency only), runs the
pipeline on them and scores the result against the linker map (function addresses, parameter
counts, string literals, truncated functions, decompiler noise). See `tests/README.md`.
Planned work: `docs/ROADMAP.md`.
