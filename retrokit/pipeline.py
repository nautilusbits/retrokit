"""Headless Ghidra pipelines (formerly analyze.ps1 / analyze_pe.ps1).

LE/LX (Watcom):  import with the LE loader and a Watcom cspec, functions from fixup targets,
                 then fix-up passes, parameter counts, prototypes, export.
PE (MSVC era):   import with Ghidra's PE loader and auto-analysis, export, then functions at
                 pointer-table targets / code after padding (tools/find_entries.py) until no
                 new ones turn up.
"""
import csv
import glob
import os
import subprocess
import sys

from . import ghidra as gh
from . import paths
from . import workspace as wsp

LE_SUMMARY = (r"Created|Switch tables|Exporting|Export done|Wrote|ApplyStackConvention:|MarkStringsConstant:|"
              r"ApplyNames:|Recovering|iteration|Entries:")
PE_SUMMARY = r"Exporting|Export done|DumpImports|ApplyNames:|Entries:"


def _dirs(ws):
    d = {k: wsp.sub(ws, k) for k in ("ghidra_project", "decomp", "logs", "notes")}
    for p in d.values():
        os.makedirs(p, exist_ok=True)
    return d


def _clear_locks(project):
    for f in glob.glob(os.path.join(project, "*.lock*")):
        os.remove(f)


def _names_args(names):
    if not names:
        return []
    return ["-postScript", "ApplyNames.java", os.path.abspath(names)]


def _entries_args(entries):
    if not entries:
        return []
    return ["-preScript", "CreateFunctionsAtEntries.java", "@" + os.path.abspath(entries)]


def _summary(log, pattern, out):
    for line in gh.log_lines(log, pattern):
        out(" ", line)


def _function_count(decomp):
    return _function_count_csv(os.path.join(decomp, "functions.csv"))


def _report(ws, decomp, out):
    n = _function_count(decomp)
    cfile = os.path.join(decomp, ws["cname"])
    out("functions: %d, decompiled C: %s bytes" % (n, format(os.path.getsize(cfile), ",")))
    out("output: %s" % decomp)
    return n


def run(ws, ghidra, skip_import=False, names=None, entries=None, out=print):
    """Run the pipeline the workspace describes. Returns the number of exported functions."""
    d = _dirs(ws)
    for f in glob.glob(os.path.join(d["logs"], "*.log")):   # headless appends: start clean
        os.remove(f)
    if not skip_import:
        _clear_locks(d["ghidra_project"])
    out("Ghidra: %s (%s)" % (ghidra, gh.version(ghidra)))
    out("EXE:    %s  [%s%s]" % (ws["exe"], ws["format"],
                                ", loader %s, cspec %s" % (ws["loader"], ws["cspec"]) if ws["pipeline"] == "le" else ""))
    out("Out:    %s" % ws["dir"])
    if ws["pipeline"] == "le":
        n = _run_le(ws, ghidra, d, skip_import, names, entries, out)
    elif ws["pipeline"] == "pe":
        n = _run_pe(ws, ghidra, d, skip_import, names, entries, out)
    else:
        raise gh.GhidraError("no pipeline for format %s" % ws["format"])
    wsp.save(ws)
    return n


def _headless(ghidra, d, args, phase):
    log = os.path.join(d["logs"], phase + ".log")
    gh.run_headless(ghidra, d["ghidra_project"], ["-scriptPath", paths.GHIDRA_SCRIPTS] + args, log,
                    os.path.join(d["logs"], phase + "_stdout.log"))
    return log


def _run_le(ws, ghidra, d, skip_import, names, entries, out):
    name = os.path.basename(ws["exe"])
    if not skip_import:
        out("== import + analysis")
        _headless(ghidra, d, ["-import", ws["exe"], "-loader", ws["loader"], "-processor", "x86:LE:32:default",
                              "-cspec", ws["cspec"], "-overwrite", "-postScript", "CreateFunctionsFromFixups.java"],
                  "import")
    out("== fix-up passes, parameter counts%s, export" % (", prototypes" if ws.get("prototypes", True) else ""))
    args = ["-process", name] + _entries_args(entries) + [
        "-preScript", "FixTruncatedCallers.java",
        "-preScript", "CreateFunctionsFromFixups.java",
        "-preScript", "MarkStringsConstant.java"]
    if ws.get("prototypes", True):
        # parameter counts from "ADD ESP,n" at call sites, then prototypes callees-first
        args += ["-preScript", "ApplyStackConvention.java", "-postScript", "RecoverPrototypes.java"]
    args += _names_args(names) + [
        "-postScript", "ExportDecompiled.java", d["decomp"], ws["cname"],
        "-postScript", "DumpFixups.java", os.path.join(d["decomp"], "fixups.txt")]
    log = _headless(ghidra, d, args, "export")
    _summary(log, LE_SUMMARY, out)
    return _report(ws, d["decomp"], out)


def _export_pe(ws, ghidra, d, names, phase, out):
    """full export: strings, parameter counts and prototypes as for LE, then the dumps"""
    name = os.path.basename(ws["exe"])
    args = ["-process", name, "-noanalysis", "-preScript", "MarkStringsConstant.java"]
    if ws.get("prototypes", True):
        args += ["-preScript", "ApplyStackConvention.java", "-postScript", "RecoverPrototypes.java"]
    log = _headless(ghidra, d, args + _names_args(names) + [
        "-postScript", "ExportDecompiled.java", d["decomp"], ws["cname"],
        "-postScript", "DumpImports.java", os.path.join(d["decomp"], "imports.txt"),
        "-postScript", "DumpFixups.java", os.path.join(d["decomp"], "fixups.txt")], phase)
    _summary(log, LE_SUMMARY + "|" + PE_SUMMARY, out)


def find_entries(ws, out_file, functions=None):
    """tools/find_entries.py over the export (or a functions.csv); returns the number of addresses."""
    src = functions or wsp.sub(ws, "decomp")
    r = subprocess.run([sys.executable, "-I", paths.tool("find_entries.py"), ws["exe"], src, out_file],
                       capture_output=True, text=True)
    if r.returncode:
        raise gh.GhidraError("find_entries.py failed:\n" + r.stdout + r.stderr)
    with open(out_file) as fh:
        return sum(1 for line in fh if line.strip() and not line.startswith("#"))


def _function_list(ghidra, d, name, phase):
    """addr,name,size of every function, without decompiling (cheap, for the entry passes)"""
    csv_path = os.path.join(d["logs"], "functions_%s.csv" % phase)
    _headless(ghidra, d, ["-process", name, "-noanalysis", "-postScript", "DumpFunctions.java", csv_path], phase)
    return csv_path


def _run_pe(ws, ghidra, d, skip_import, names, entries, out):
    name = os.path.basename(ws["exe"])
    if not skip_import:
        out("== import + auto-analysis (PE loader, default analyzers)")
        _headless(ghidra, d, ["-import", ws["exe"], "-overwrite"], "import")
    if entries:
        out("== functions at %s + re-analysis" % entries)
        _summary(_headless(ghidra, d, ["-process", name] + _entries_args(entries), "entries"), PE_SUMMARY, out)
    # functions only reached through pointer tables or registers: add them until none turn up
    passes = ws.get("entry_passes", 3)
    funcs = _function_list(ghidra, d, name, "list0") if passes else None
    for p in range(passes):
        found = os.path.join(d["notes"], "entries_auto.txt")
        n = find_entries(ws, found, funcs)
        out("== entries pass %d: %d code addresses without a function" % (p + 1, n))
        if n == 0:
            break
        before = _function_count_csv(funcs)
        _summary(_headless(ghidra, d, ["-process", name] + _entries_args(found), "entries%d" % (p + 1)),
                 PE_SUMMARY, out)
        funcs = _function_list(ghidra, d, name, "list%d" % (p + 1))
        if _function_count_csv(funcs) <= before:
            break   # the remaining addresses are not code Ghidra accepts
    out("== export")
    _export_pe(ws, ghidra, d, names, "export", out)
    return _report(ws, d["decomp"], out)


def _function_count_csv(path):
    with open(path, encoding="utf-8") as fh:
        return sum(1 for _ in csv.DictReader(fh))
