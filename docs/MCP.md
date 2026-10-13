# retro-kit MCP server - guide for AI agents and their users

`retrokit mcp` gives an MCP client (Claude Code, Claude Desktop, or any client that speaks the
Model Context Protocol over stdio) direct access to a retro-kit analysis: functions,
decompiled C, call graph, cross references, strings, pointer tables, disassembly, raw bytes
and the libraries the game uses. The agent records what it finds as name proposals and notes,
and can have the names applied in Ghidra and the export regenerated.

## 1. Prerequisites (once per machine)

```
pipx install git+https://github.com/nemo22/retrokit    # or: pip install . in a checkout
retrokit doctor                                        # Python, Ghidra 12, JDK 21+, loader, cspecs
retrokit install-loader                                # LE/LX loader + Watcom compiler specs into Ghidra
```

Ghidra is found through `--ghidra DIR` or `$GHIDRA_INSTALL_DIR`. `doctor` says what is missing
and how to fix it.

## 2. Create the workspace (once per executable)

The MCP server serves an existing analysis; it does not run the first analysis itself.

```
retrokit info GAME.EXE         # format, DOS extender, compiler, calling convention, libraries
retrokit analyze GAME.EXE      # several minutes; creates GAME_analysis/ next to the EXE (-o DIR to choose)
```

A workspace is a directory with `retrokit.json`, `decomp/` (the export), `notes/` (findings and
name proposals), `ghidra_project/` and `logs/`.

## 3. Connect the MCP server

The server is a local process speaking newline-delimited JSON-RPC on stdin/stdout. It needs no
network and no extra Python packages. Give it one or more workspace directories (absolute
paths are safest).

**Claude Code**

```
claude mcp add retrokit -- retrokit mcp /path/to/GAME_analysis
claude mcp list                        # should show retrokit as connected
```

Project-wide instead (a `.mcp.json` next to your notes, shared with the team):

```json
{
  "mcpServers": {
    "retrokit": { "command": "retrokit", "args": ["mcp", "/path/to/GAME_analysis"] }
  }
}
```

**Claude Desktop** - `claude_desktop_config.json` (Settings -> Developer -> Edit Config):

```json
{
  "mcpServers": {
    "retrokit": { "command": "retrokit", "args": ["mcp", "C:\\games\\GAME\\GAME_analysis"] }
  }
}
```

**Any other MCP client** - stdio transport, command `retrokit`, arguments
`mcp <workspace> [<workspace> ...]`. If `retrokit` is not on the client's PATH, use the full
path of the executable (`pipx` puts it in `~/.local/bin` or `%USERPROFILE%\.local\bin`) or
`python -m retrokit mcp ...` with the Python that has retro-kit installed.

Several workspaces (e.g. a game and its sequel): list them all; tools then take a
`workspace` argument with the directory name (`GAME_analysis`) or path.

Check by hand: `retrokit mcp GAME_analysis` and type
`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` - one JSON line with the tools comes back.

## 4. Tools

Addresses are hex (`12345`, `0x12345`, `FUN_00012345`); functions and data can also be given
by name. Long results are cut at about 60,000 characters with a note - narrow the query then.

| tool | arguments (* required) | what it returns |
|---|---|---|
| `workspace_info` | - | executable, format, extender, compiler, calling convention, function counts (named / unnamed), libraries, name files |
| `libraries` | - | libraries of the period the game uses (Miles, HMI, Smacker, zlib, ...) with evidence, version, notes on formats and porting |
| `list_functions` | `pattern` (regex on the name), `which` all/named/unnamed, `sort` addr/size/callers, `offset`, `limit` (100, max 1000) | address, name, size, callers, callees, signature |
| `get_function` | `functions`* (list of names / addresses, up to 20) | decompiled C with signature, callers and callees; for an address inside a function, that function |
| `call_graph` | `function`*, `direction` callers/callees/both, `depth` 1-4 | the call tree |
| `xrefs` | `address`* | calls to it and every pointer to it (fixup / relocation) with the function that holds it |
| `search_code` | `regex`*, `limit` (50) | matching lines of the decompiled C with their function |
| `strings` | `pattern` (regex on the text), `offset`, `limit` | string literals with address and the functions using them |
| `pointer_tables` | `min_entries` (3) | pointer tables stored in data: plain tables of function pointers and arrays of records (with the record size), every entry resolved |
| `disassemble` | `address`*, `count` (40, max 400) | x86 disassembly from the executable (no Ghidra), called functions and pointer targets named |
| `read_bytes` | `address`*, `length` (128, max 4096) | hex dump of the loaded image (fixups applied) |
| `propose_names` | `topic`*, `names`* (list of `{address, name, confidence V/G, comment}`) | writes `notes/names_<topic>.csv`; invalid names or addresses are rejected and listed; a new proposal for an address replaces the old one in that file |
| `list_proposals` | - | all proposals, conflicts between files (one address, two names; one name, two addresses) |
| `write_note` | `topic`*, `text`*, `append` (true) | appends to `notes/<topic>.md` |
| `reexport` | `confirm`* (must be true) | starts `retrokit names` in the background: names applied in Ghidra, export regenerated (minutes) |
| `reexport_status` | - | running / finished, exit code, last log lines; the server reloads the new export by itself |

The server writes only under `notes/` (and `logs/` for a reexport); `decomp/` changes only
through `reexport`.

## 5. How to work (for the agent)

1. `workspace_info`, then `libraries` - know the compiler, the calling convention and which
   library code to expect. Functions already named (`fopen`, `inflate`, ...) come from
   library signatures; `G` names in their plate comments are guesses.
2. Find entry points into the part you are asked about:
   - text the game shows or file names it opens: `strings` -> the functions using them;
   - data the game reads: `xrefs` on the address;
   - behaviour driven by tables (entity types, menus, AI states, script opcodes):
     `pointer_tables`, then `get_function` on the handlers;
   - `call_graph` around a function you understand, `search_code` for a constant or global.
3. Read with `get_function` (several at once). Use `disassemble` / `read_bytes` when the
   decompiler is unclear or for raw tables.
4. Record names as you go with `propose_names`, one topic per area (`audio`, `ui`, `ai`,
   `fileio`, ...). Confidence `V` only when the code proves it (e.g. it opens "SAVE%d.DAT" and
   writes the game state), otherwise `G`. Names are C identifiers, lowercase_with_underscores
   for functions, `g_` prefix for globals is a good habit.
5. Write findings (formats, structures with offsets, open questions) with `write_note`,
   citing function addresses; mark claims V or G.
6. When a batch of names is in, `reexport` with `confirm=true` - only if you are the agent
   allowed to (one at a time per workspace), then poll `reexport_status` every minute or so.
   The next `get_function` shows the new names and better types at the call sites.

Do not copy decompiled game code or game data into places outside the workspace (issues,
public repositories, chats with third parties): it is the copyright holder's.

## 6. Example session

```
workspace_info                                 -> LE, DOS/4GW, Watcom C/C++, register convention, 2140 functions (420 named)
libraries                                      -> Watcom run-time, HMI SOS, zlib 1.1.4
strings {"pattern": "SAVE"}                    -> 0004a210 "SAVE%02d.DAT"  FUN_00031c40
get_function {"functions": ["FUN_00031c40"]}   -> sprintf(buf,"SAVE%02d.DAT",slot); fopen(buf,"wb"); fwrite(&DAT_00052000,0x1a40,1,fp) ...
propose_names {"topic": "save", "names": [
   {"address": "31c40", "name": "save_game", "confidence": "V", "comment": "writes SAVE%02d.DAT"},
   {"address": "52000", "name": "g_game_state", "confidence": "G", "comment": "0x1a40 bytes saved"}]}
write_note {"topic": "save", "text": "Save file: 0x1a40 bytes, the block at 0x52000 written as is (V, save_game)."}
reexport {"confirm": true}    ...    reexport_status -> finished, exit code 0
```

## 7. Troubleshooting

- *The client shows no tools / server not connected*: run the command from the config by hand;
  `retrokit` must be on the PATH of the client (use the full path otherwise). The workspace
  must contain `retrokit.json` (created by `retrokit analyze`).
- *"workspace has no export yet"*: the analysis did not finish; see `logs/` and run
  `retrokit analyze GAME_analysis` again.
- *reexport fails*: `reexport_status` shows the log tail; usually Ghidra is not found
  (`retrokit doctor`) or the Ghidra project is locked by an open Ghidra GUI (close it).
- *Several agents*: let all of them read and propose (different topics), and only one
  reexport; proposals for the same address in two files show up in `list_proposals`.
