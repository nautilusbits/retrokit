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
    retrokit match ...                   transfer names to a related EXE (tools/match_names.py)
    retrokit le GAME.EXE info|dump|rec|s16|s32 ...   read LE tables at Ghidra addresses
    retrokit rnc IN [OUT]                RNC ProPack decompressor
    retrokit flic info|png|video FILE ...  Autodesk FLI/FLC
"""
import argparse
import json
import os
import subprocess
import sys

from . import __version__
from . import detect
from . import doctor
from . import formats
from . import ghidra as gh
from . import loader
from . import paths
from . import pipeline
from . import workspace as wsp


def _tool(name, args, env=None):
    return subprocess.call([sys.executable, "-I", paths.tool(name)] + list(args),
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
    if a.json:
        print(json.dumps(dict(info, convention=cc), indent=1))
    else:
        print(_describe(info, cc))
    return 0


def _new_workspace(a):
    exe = os.path.abspath(a.exe)
    info = formats.identify(exe)
    if not info["pipeline"]:
        raise SystemExit(_describe(info))
    out = os.path.abspath(a.out or wsp.default_dir(exe))
    ws = {"dir": out, "exe": exe, "format": info["format"], "pipeline": info["pipeline"],
          "cname": a.cname or os.path.splitext(os.path.basename(exe))[0].lower() + "_decompiled.c",
          "prototypes": not a.no_prototypes}
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
    except (gh.GhidraError, formats.FormatError, RuntimeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
