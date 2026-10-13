"""retrokit command line.

    retrokit doctor                      check Python, Ghidra, Java, loader, cspecs
    retrokit install-loader              build + install the LE/LX loader and Watcom cspecs into Ghidra
    retrokit info GAME.EXE               format, extender, compiler, calling convention
    retrokit analyze GAME.EXE [-o OUT]   full pipeline into a workspace (default GAME_analysis/)
    retrokit reexport WS                 fix-up passes + export again on the existing project
    retrokit names WS [CSV|DIR]          apply names_*.csv (default WS/notes) and re-export
    retrokit show WS FUN_00012345 ...    print decompiled functions
    retrokit tables WS                   pointer tables from fixups.txt (LE)
    retrokit entries WS [-o FILE]        code addresses without a function (PE)
    retrokit modules WS --rules FILE     functions -> source files via assert paths (PE)
    retrokit strings GAME.EXE OUT        string inventory without Ghidra (PE)
    retrokit libs GAME.EXE               period libraries the game uses (evidence, notes, kit support)
    retrokit sigs match GAME.EXE         library functions by signature -> names CSV
    retrokit sigs build --watcom DIR --lib X.lib -o X.sig   signatures from an OMF library
    retrokit sigs learn WS -o X.sig       signatures from the named functions of a workspace
    retrokit match ...                   transfer names to a related EXE (tools/match_names.py)
    retrokit le GAME.EXE info|dump|rec|s16|s32 ...   read LE tables at Ghidra addresses
    retrokit mcp WS [WS ...]             MCP server (stdio) over workspaces, for AI agents
    retrokit convert FILE|DIR [-o OUT]   XMIDI/HMI/HMP -> MIDI, VOC -> WAV, Smacker/Bink/FLIC -> MP4
    retrokit rnc IN [OUT]                RNC ProPack decompressor
    retrokit flic info|png|video FILE ...  Autodesk FLI/FLC
"""
import argparse
import json
import os
import struct
import subprocess
import sys

from . import __version__
from . import detect
from . import doctor
from . import formats
from . import ghidra as gh
from . import libs
from . import loader
from . import media
from . import paths
from . import pipeline
from . import sigs
from . import workspace as wsp


def _tool(name, args, env=None):
    return subprocess.call(paths.tool_cmd(name) + list(args),
                           env=dict(os.environ, **(env or {})))


def _workspace(path):
    if not wsp.is_workspace(path):
        raise SystemExit("not a retrokit workspace (no %s): %s" % (wsp.FILE, path))
    return wsp.load(path)


def _describe(info, cc=None):
    lines = ["%s: %s, %s bytes" % (info["path"], info["format"], format(info["size"], ","))]
    for k in ("extender", "compiler", "toolchain", "machine", "loader"):
        if info.get(k):
            lines.append("  %-10s %s" % (k, info[k]))
    if info.get("objects"):
        for i, o in enumerate(info["objects"]):
            lines.append("  object %d  base 0x%08x size 0x%x flags 0x%x" % (i + 1, o["base"], o["size"], o["flags"]))
    if info.get("dlls"):
        lines.append("  imports    " + ", ".join(info["dlls"]))
    for n in info["notes"]:
        lines.append("  note: " + n)
    if cc:
        lines += ["  " + l for l in detect.format_convention(cc).splitlines()]
    if info["pipeline"]:
        lines.append("=> retrokit analyze %s%s" % (info["path"], "" if info["pipeline"] == "pe" else
                                                     "   (cspec %s)" % cc["cspec"] if cc else ""))
    else:
        lines.append("=> no retrokit pipeline for this file")
    return "\n".join(lines)


def cmd_info(a):
    info = formats.identify(a.exe)
    cc = None
    if info["pipeline"] == "le":
        try:
            cc = detect.watcom_convention(a.exe)
        except RuntimeError as e:
            info["notes"].append(str(e))
    found = libs.detect(a.exe)
    if a.json:
        print(json.dumps(dict(info, convention=cc, libraries=found), indent=1))
    else:
        print(_describe(info, cc))
        if found:
            print("  libraries  " + ", ".join(f["name"] + (" " + f["version"] if f["version"] else "") for f in found)
                  + "   (retrokit libs for details)")
    return 0


def cmd_libs(a):
    exe = _workspace(a.exe)["exe"] if wsp.is_workspace(a.exe) else a.exe
    found = libs.detect(exe, a.dir)
    print(json.dumps(found, indent=1) if a.json else libs.format_report(found))
    return 0


def _new_workspace(a):
    exe = os.path.abspath(a.exe)
    info = formats.identify(exe)
    if not info["pipeline"]:
        raise SystemExit(_describe(info))
    out = os.path.abspath(a.out or wsp.default_dir(exe))
    ws = {"dir": out, "exe": exe, "format": info["format"], "pipeline": info["pipeline"],
          "cname": a.cname or os.path.splitext(os.path.basename(exe))[0].lower() + "_decompiled.c",
          "prototypes": not a.no_prototypes, "sigs": not a.no_sigs, "fuzzy_sigs": not a.exact_sigs}
    if a.sigs:
        ws["sig_files"] = [os.path.abspath(x) for x in a.sigs]
    if info["pipeline"] == "le":
        ws["loader"] = info["loader"] if a.loader == "auto" else a.loader
        if a.cspec == "auto":
            ws["cspec"] = detect.watcom_convention(exe)["cspec"]
            print("calling convention: %s (detected; override with --cspec)" % ws["cspec"])
        else:
            ws["cspec"] = a.cspec
    else:
        ws["entry_passes"] = a.entry_passes
    for k in ("extender", "compiler", "toolchain"):
        if info.get(k):
            ws[k] = info[k]
    return ws


def cmd_analyze(a):
    if wsp.is_workspace(a.exe):           # re-run an existing workspace with its settings
        ws = wsp.load(a.exe)
        if a.no_prototypes:
            ws["prototypes"] = False
        if a.no_sigs:
            ws["sigs"] = False
    else:
        ws = _new_workspace(a)
    ghidra = gh.find(a.ghidra or ws.get("ghidra"), near=os.path.dirname(ws["exe"]))
    ws["ghidra"] = ghidra
    if ws["pipeline"] == "le":
        st = gh.loader_status(ghidra)
        if not st["installed"] or ws["cspec"] not in st["cspecs"]:
            raise SystemExit("LE/LX loader or Watcom cspec missing in %s: run retrokit install-loader" % ghidra)
    pipeline.run(ws, ghidra, skip_import=a.skip_import, names=a.names, entries=a.entries)
    return 0


def cmd_reexport(a):
    ws = _workspace(a.workspace)
    ghidra = gh.find(a.ghidra or ws.get("ghidra"))
    pipeline.run(ws, ghidra, skip_import=True, names=a.names, entries=a.entries)
    return 0


def cmd_names(a):
    ws = _workspace(a.workspace)
    names = a.names or wsp.sub(ws, "notes")
    ghidra = gh.find(a.ghidra or ws.get("ghidra"))
    pipeline.run(ws, ghidra, skip_import=True, names=names)
    return 0


def cmd_show(a):
    return _tool("showfn.py", ["--dir", wsp.sub(_workspace(a.workspace), "decomp")] + a.functions)


def cmd_tables(a):
    extra = ["--data-base", a.data_base] if a.data_base else []
    return _tool("find_tables.py", extra + [os.path.join(wsp.sub(_workspace(a.workspace), "decomp"), "fixups.txt")])


def cmd_entries(a):
    ws = _workspace(a.workspace)
    out = a.output or os.path.join(wsp.sub(ws, "notes"), "entries.txt")
    n = pipeline.find_entries(ws, out)
    print("%d addresses -> %s (retrokit reexport %s --entries %s)" % (n, out, a.workspace, out))
    return 0


def cmd_modules(a):
    ws = _workspace(a.workspace)
    args = [wsp.sub(ws, "decomp"), a.output or wsp.sub(ws, "notes")]
    return _tool("module_map.py", args + (["--rules", a.rules] if a.rules else []))


def cmd_sigs(a):
    if a.action == "build":
        if not a.watcom or not a.lib or not a.output:
            raise SystemExit("sigs build needs --watcom DIR, --lib LIB (repeatable) and -o FILE")
        n = sigs.build(a.watcom, a.lib, a.output, a.label, a.system)
        print("%d signatures -> %s" % (n, a.output))
        return 0
    if a.action == "learn":
        if not a.exe or not wsp.is_workspace(a.exe) or not a.output:
            raise SystemExit("sigs learn needs an analysed workspace and -o FILE")
        ws = _workspace(a.exe)
        keep = None
        if a.names:
            import csv
            with open(a.names, encoding="utf-8") as fh:
                keep = {int(r["addr"].split(":")[-1], 16) for r in csv.DictReader(fh)}
        found = sigs.learn(ws["exe"], os.path.join(wsp.sub(ws, "decomp"), "functions.csv"), keep,
                           a.label or os.path.basename(ws["exe"]))
        sigs.write(a.output, found, ["label: %s" % (a.label or "learned from " + os.path.basename(ws["exe"])),
                                     "built by retrokit sigs learn"])
        print("%d signatures -> %s" % (len(found), a.output))
        return 0
    if not a.exe:
        raise SystemExit("sigs match needs an executable or workspace")
    exe = _workspace(a.exe)["exe"] if wsp.is_workspace(a.exe) else a.exe
    files = sigs.sig_files(a.sigs)
    if not a.sigs:
        files = sigs.relevant_files(exe, files)
    found, n = sigs.match_file(exe, files, fuzzy=not a.exact)
    out = a.output or (os.path.join(wsp.sub(_workspace(a.exe), "notes"), "sigs", "names_sigs.csv")
                       if wsp.is_workspace(a.exe) else None)
    print("%d signatures from %d files, %d functions found (%d V, %d G)" % (
        n, len(files), len(found), sum(1 for v in found.values() if v[1] == "V"),
        sum(1 for v in found.values() if v[1] == "G")))
    if out:
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        sigs.write_names(out, found)
        print("-> %s" % out)
    else:
        for addr in sorted(found):
            print("%08x %-24s %s %s" % ((addr,) + found[addr]))
    return 0


def cmd_convert(a):
    found = media.scan(a.path)
    if a.list or not found:
        for p, k in found:
            print("%-5s %s" % (k, p))
        if not found:
            print("nothing convertible found in %s" % a.path)
        return 0
    base = a.path if os.path.isdir(a.path) else os.path.dirname(os.path.abspath(a.path))
    out_root = a.output or os.path.join(base, "converted")
    n = failed = 0
    for p, k in found:
        rel = os.path.relpath(os.path.dirname(os.path.abspath(p)), os.path.abspath(base))
        try:
            results = media.convert(p, os.path.normpath(os.path.join(out_root, rel)), a.ffmpeg)
        except (ValueError, IndexError, struct.error) as e:
            print("FAIL  %s: %s" % (p, e))
            failed += 1
            continue
        for o, desc in results:
            print("%-5s %s -> %s  (%s)" % (k, p, o or "-", desc))
            n += o is not None
    print("%d files written to %s%s" % (n, out_root, ", %d failed" % failed if failed else ""))
    return 1 if failed else 0


def cmd_mcp(a):
    from . import mcp_server
    for w in a.workspaces:
        _workspace(w)
    mcp_server.serve(a.workspaces)
    return 0


def cmd_install_loader(a):
    ghidra = gh.find(a.ghidra)
    loader.install(ghidra, build_only=a.build_only)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="retrokit", description="Headless Ghidra toolkit for old DOS and Win32 games.")
    p.add_argument("--version", action="version", version="retrokit " + __version__)
    sp = p.add_subparsers(dest="cmd", metavar="COMMAND")

    def add(name, fn, help_, ghidra=False):
        s = sp.add_parser(name, help=help_, description=help_)
        s.set_defaults(fn=fn)
        if ghidra:
            s.add_argument("--ghidra", help="Ghidra install dir (default $GHIDRA_INSTALL_DIR or ghidra*/ nearby)")
        return s

    s = add("doctor", lambda a: doctor.run(a.ghidra), "check the environment", ghidra=True)
    s = add("install-loader", cmd_install_loader, "build + install the LE/LX loader and Watcom cspecs", ghidra=True)
    s.add_argument("--build-only", metavar="DIR", help="only build the extension into DIR")

    s = add("info", cmd_info, "identify an executable (format, extender, compiler, calling convention)")
    s.add_argument("exe")
    s.add_argument("--json", action="store_true")

    s = add("analyze", cmd_analyze, "run the pipeline into a workspace", ghidra=True)
    s.add_argument("exe", help="executable, or an existing workspace to re-run with its settings")
    s.add_argument("-o", "--out", help="workspace dir (default <exe dir>/<exe>_analysis)")
    s.add_argument("--cspec", default="auto", choices=["auto", "watcom", "watcomreg"], help="LE: calling convention")
    s.add_argument("--loader", default="auto", help="Ghidra loader class (default: LinearExecutableLoader for LE/LX)")
    s.add_argument("--no-prototypes", action="store_true", help="skip parameter counts / prototype recovery")
    s.add_argument("--no-sigs", action="store_true", help="do not name library functions by signature")
    s.add_argument("--sigs", action="append", metavar="FILE|DIR",
                   help="signature files to use instead of the shipped ones + ~/.retrokit/sigs (repeatable)")
    s.add_argument("--exact-sigs", action="store_true", help="library signatures: exact matches only (no fuzzy tier)")
    s.add_argument("--entry-passes", type=int, default=3, help="PE: find_entries rounds after the first export")
    s.add_argument("--names", help="names_*.csv file or directory to apply before export")
    s.add_argument("--entries", help="file with hex addresses to create functions at")
    s.add_argument("--cname", help="name of the decompiled .c (default <exe>_decompiled.c)")
    s.add_argument("--skip-import", action="store_true", help="reuse the Ghidra project (workspace only)")

    s = add("reexport", cmd_reexport, "fix-up passes + export again without re-importing", ghidra=True)
    s.add_argument("workspace")
    s.add_argument("--names")
    s.add_argument("--entries")

    s = add("names", cmd_names, "apply names_*.csv proposals and re-export", ghidra=True)
    s.add_argument("workspace")
    s.add_argument("names", nargs="?", help="CSV or directory (default <workspace>/notes)")

    s = add("show", cmd_show, "print decompiled functions")
    s.add_argument("workspace")
    s.add_argument("functions", nargs="+")

    s = add("tables", cmd_tables, "function/string pointer tables from fixups.txt (LE)")
    s.add_argument("workspace")
    s.add_argument("--data-base", help="hex start of the data object (default from memory_blocks.txt)")

    s = add("entries", cmd_entries, "PE: code addresses not covered by a function")
    s.add_argument("workspace")
    s.add_argument("-o", "--output")

    s = add("modules", cmd_modules, "PE: map functions to source files/modules via assert paths")
    s.add_argument("workspace")
    s.add_argument("--rules", help="TSV regex<TAB>module")
    s.add_argument("-o", "--output", help="output dir (default <workspace>/notes)")

    s = add("libs", cmd_libs, "period libraries a game uses: evidence, version, notes, what the kit supports")
    s.add_argument("exe", help="executable or workspace")
    s.add_argument("--dir", help="game directory to look for data files in (default: the executable's)")
    s.add_argument("--json", action="store_true")

    s = add("sigs", cmd_sigs, "library signatures: match them in an EXE, build them from a library, "
                              "or learn them from the named functions of a workspace")
    s.add_argument("action", choices=["match", "build", "learn"])
    s.add_argument("exe", nargs="?", help="match: executable or workspace; learn: workspace")
    s.add_argument("--exact", action="store_true", help="match: exact matches only (no fuzzy tier)")
    s.add_argument("--names", help="learn: only the addresses of this names CSV (default: every named function)")
    s.add_argument("--sigs", action="append", help="match: .sig file or directory (default: shipped + ~/.retrokit/sigs)")
    s.add_argument("-o", "--output", help="match: names CSV (default <workspace>/notes/sigs/names_sigs.csv); build, learn: .sig file")
    s.add_argument("--watcom", help="build: Watcom install dir (wlink, wlib)")
    s.add_argument("--lib", action="append", help="build: OMF library (repeatable)")
    s.add_argument("--label", help="build: description stored in the file")
    s.add_argument("--system", default="dos4g", help="build: wlink system for the reference link")

    s = add("mcp", cmd_mcp, "MCP server over one or more workspaces (stdio), e.g. "
                            "'claude mcp add retrokit -- retrokit mcp GAME_analysis'")
    s.add_argument("workspaces", nargs="+")

    s = add("convert", cmd_convert, "game music, sound and video to MIDI / WAV / MP4 (by content, not extension)")
    s.add_argument("path", help="file or directory")
    s.add_argument("-o", "--output", help="output directory (default <dir>/converted)")
    s.add_argument("--list", action="store_true", help="only list what would be converted")
    s.add_argument("--ffmpeg", help="ffmpeg executable for video (default: from PATH)")

    for name, tool, help_ in [("strings", "strings_scan.py", "PE string inventory without Ghidra: EXE OUT_DIR"),
                              ("match", "match_names.py", "transfer names to a related EXE (see --help)"),
                              ("rnc", "rnc.py", "RNC ProPack decompressor: IN [OUT]"),
                              ("flic", "flic.py", "Autodesk FLI/FLC: info|png|video FILE ...")]:
        s = add(name, (lambda t: lambda a: _tool(t, a.args))(tool), help_)
        s.add_argument("args", nargs=argparse.REMAINDER)

    s = add("le", lambda a: _tool("le.py", a.args, env={"LE_EXE": os.path.abspath(a.exe)}),
            "read LE data at Ghidra addresses: EXE info|dump ADDR LEN|rec ADDR N SIZE [fmt]|s16|s32")
    s.add_argument("exe")
    s.add_argument("args", nargs=argparse.REMAINDER)
    return p


def main(argv=None):
    p = build_parser()
    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        p.print_help()
        return 2
    try:
        return a.fn(a) or 0
    except (gh.GhidraError, formats.FormatError, RuntimeError, FileNotFoundError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
