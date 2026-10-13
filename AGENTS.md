# Notes for AI agents

## Using retro-kit to analyse a game

retro-kit reverse-engineers 32-bit DOS (LE/LX, Watcom) and Win32 executables of about
1993-2010 with headless Ghidra. As an agent you work on an *analysis workspace*, ideally
through the MCP server - full guide: [docs/MCP.md](docs/MCP.md).

1. Check the environment: `retrokit doctor` (install: `pipx install git+https://github.com/nemo22/retrokit`,
   then `retrokit install-loader`).
2. Analyse once: `retrokit info GAME.EXE`, then `retrokit analyze GAME.EXE` -> `GAME_analysis/`.
3. Connect: `claude mcp add retrokit -- retrokit mcp /abs/path/GAME_analysis` (other clients:
   stdio, command `retrokit`, args `mcp <workspace>`).
4. Work: `workspace_info` and `libraries` first; find code through `strings`, `xrefs`,
   `pointer_tables`, `call_graph`, `search_code`; read it with `get_function`; record names with
   `propose_names` (V = proven by the code, G = guess) and findings with `write_note`;
   `reexport` (confirm=true, one agent at a time) applies the names.

Without MCP the same data is in files: `GAME_analysis/decomp/` (`*_decompiled.c`,
`functions.csv`, `calls.txt`, `strings.txt`, `fixups.txt`, ...) and the CLI (`retrokit show`,
`retrokit tables`, `retrokit names`); task templates in [docs/AGENT_PROMPTS.md](docs/AGENT_PROMPTS.md),
the full procedure in [docs/WORKFLOW.md](docs/WORKFLOW.md).

Decompiled code and game data belong to the game's copyright holder: keep them in the
workspace, never in issues, pull requests or this repository.

## Working on retro-kit itself

- Code: `retrokit/` (CLI `cli.py`, pipelines `pipeline.py`, signatures `sigs.py` / `fuzzy.py`,
  MCP `mcp_server.py`, loader `le-loader/`, Ghidra scripts `ghidra_scripts/`), tests `tests/`.
- Unit tests (no Ghidra): `python -m unittest discover -s tests`.
- Full pipeline tests: `WATCOM=<Open Watcom 2> GHIDRA_INSTALL_DIR=<Ghidra 12> python tests/run_tests.py -v`
  (builds synthetic programs, analyses them, compares with `tests/baseline.json`; a metric that
  gets worse fails, `--update-baseline` after a deliberate improvement).
- Never add game executables, game data, decompiled game code or names of analysed games to
  the repository or commit messages. Library signatures only from open-source or public-domain
  code (`scripts/build_sigs.py`).
- No runtime dependencies beyond capstone; Python 3.10+, Windows and Linux.
