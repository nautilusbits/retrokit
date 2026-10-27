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
import struct
import subprocess

from . import formats
from . import ghidra as gh
from . import formats
from . import libs
from . import paths
from . import sigs
from . import workspace as wsp

LE_SUMMARY = (r"Created|Switch tables|Exporting|Export done|Wrote|ApplyStackConvention:|MarkStringsConstant:|"
              r"ApplyNames:|ApplyLibraryPrototypes:|library signatures|Recovering|iteration|Entries:")
PE_SUMMARY = r"Exporting|Export done|DumpImports|ApplyNames:|Entries:|PropagateComTypes:|ApplyLibraryPrototypes:"


def _dirs(ws):
    d = {k: wsp.sub(ws, k) for k in ("ghidra_project", "decomp", "logs", "notes")}
    for p in d.values():
        os.makedirs(p, exist_ok=True)
    return d


def _clear_locks(project):
    for f in glob.glob(os.path.join(project, "*.lock*")):
        os.remove(f)


def _names_args(*names):
    """ApplyNames over the given CSVs/directories; earlier ones win on equal confidence"""
    names = [os.path.abspath(n) for n in names if n]
    return ["-postScript", "ApplyNames.java"] + names if names else []


def _entries_args(*entries, trusted=None):
    """functions at the addresses of the files; trusted (library signature starts) may split
    a function whose body runs over them"""
    out = []
    for e in entries:
        if e:
            out += ["-preScript", "CreateFunctionsAtEntries.java", "@" + os.path.abspath(e)]
    if trusted:
        out += ["-preScript", "CreateFunctionsAtEntries.java", "--split", "@" + os.path.abspath(trusted)]
    return out


def knowledge_headers(win32=False):
    """the prototype headers, in parse order: the C library first (the others use its types),
    then the other libraries, then (win32) the Win32 headers starting with their base types"""
    headers = sorted(glob.glob(os.path.join(paths.KNOWLEDGE, "*.h")),
                     key=lambda h: (os.path.basename(h) != "watcom_clib.h", h))
    if win32:
        headers += sorted(glob.glob(os.path.join(paths.KNOWLEDGE, "win32", "*.h")))
    return headers


def _library_args(lib_names, win32=False):
    """preScripts: library names from signatures, then the documented prototypes (Watcom:
    named library functions; Win32: imported functions) - before the parameter-count and
    prototype passes, which leave the typed (LIBRARY) functions alone"""
    args = ["-preScript", "ApplyNames.java", os.path.abspath(lib_names)] if lib_names else []
    headers = knowledge_headers(win32)
    if headers and (lib_names or win32):
        args += ["-preScript", "ApplyLibraryPrototypes.java"] + headers
    return args


def library_names(ws, d, out):
    """library functions found by signature -> (names CSV, entries file) under notes/sigs/, or
    (None, None). Kept out of notes/ itself so that 'retrokit names' applies the user's names first."""
    if not ws.get("sigs", True):
        return None, None
    try:
        found, n = sigs.match_file(ws["exe"], ws.get("sig_files"), fuzzy=ws.get("fuzzy_sigs", True))
    except (formats.FormatError, struct.error, ValueError) as e:
        out("library signatures: skipped, the executable could not be read (%s)" % e)
        return None, None
    if not found:
        out("library signatures: none found (%d signatures)" % n)
        return None, None
    sd = os.path.join(d["notes"], "sigs")
    os.makedirs(sd, exist_ok=True)
    names, entries = os.path.join(sd, "names_sigs.csv"), os.path.join(sd, "entries_sigs.txt")
    sigs.write_names(names, found)
    with open(entries, "w", newline="\n") as fh:
        fh.write("# library functions found by signature\n")
        for a in sorted(found):
            fh.write("%08x\n" % a)
    out("library signatures: %d functions named (%d V, %d G) -> %s" % (
        len(found), sum(1 for v in found.values() if v[1] == "V"), sum(1 for v in found.values() if v[1] == "G"),
        names))
    return names, entries


def rtti_names(ws, d, out):
    """PE: MSVC RTTI classes -> decomp/classes.txt and names for their unnamed virtual methods
    (notes/sigs/names_rtti.csv, G); returns the CSV or None"""
    from . import rtti
    try:
        with open(ws["exe"], "rb") as fh:
            classes = rtti.scan(fh.read())
    except formats.FormatError:
        return None
    if not classes:
        return None
    with open(os.path.join(d["decomp"], "classes.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(rtti.format_report(classes) + "\n")
    props = [p for p in rtti.name_proposals(classes) if p[2] == "G"]     # vftables: Ghidra's RTTI analyzer
    sd = os.path.join(d["notes"], "sigs")
    os.makedirs(sd, exist_ok=True)
    path = os.path.join(sd, "names_rtti.csv")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("addr,name,confidence,comment\n")
        for a, name, conf, comment in props:
            fh.write("%08x,%s,%s,%s\n" % (a, name, conf, comment.replace(",", ";")))
    out("MSVC RTTI: %d classes, %d virtual methods named -> decomp/classes.txt" % (len(classes), len(props)))
    return path


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
    with open(ws["exe"], "rb") as fh:
        prot = formats.protection(fh.read())
    ws["protection"] = prot
    if prot:
        out("WARNING: the executable looks packed, encrypted or DRM-wrapped:")
        for p in prot:
            out("  - " + p)
        out("  Ghidra will mostly see the unpacker/DRM stub; functions, names and C may be incomplete or")
        out("  wrong. Unpack it first (e.g. upx -d, Steamless for SteamStub) and analyze the result.")
    found = libs.detect(ws["exe"])
    libs.write_notes(os.path.join(d["notes"], "libraries.md"), ws["exe"], found)
    if found:
        out("Libs:   %s  (notes/libraries.md)" % ", ".join(
            f["name"] + (" " + f["version"] if f["version"] else "") for f in found))
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


LEGACY_LOADERS = ("LeLoader", "LxLoader", "VxDLoader")   # ghidra-lx-loader, replaced by retrokit-le-loader


def _run_le(ws, ghidra, d, skip_import, names, entries, out):
    name = os.path.basename(ws["exe"])
    if ws["loader"] in LEGACY_LOADERS:
        out("note: workspace used the legacy %s, importing with %s" % (ws["loader"], gh.LOADER_CLASS))
        ws["loader"] = gh.LOADER_CLASS
    if not skip_import:
        out("== import + analysis")
        _headless(ghidra, d, ["-import", ws["exe"], "-loader", ws["loader"], "-processor", "x86:LE:32:default",
                              "-cspec", ws["cspec"], "-overwrite", "-postScript", "CreateFunctionsFromFixups.java"],
                  "import")
    lib_names, lib_entries = library_names(ws, d, out)
    out("== fix-up passes, parameter counts%s, export" % (", prototypes" if ws.get("prototypes", True) else ""))
    args = ["-process", name] + _entries_args(entries, trusted=lib_entries) + [
        "-preScript", "FixTruncatedCallers.java",
        "-preScript", "CreateFunctionsFromFixups.java",
        "-preScript", "MarkStringsConstant.java"] + _library_args(lib_names)
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
    lib_names, lib_entries = library_names(ws, d, out)
    if rtti_names(ws, d, out):
        lib_names = os.path.join(d["notes"], "sigs")       # ApplyNames takes every names_*.csv there
    args = ["-process", name] + _entries_args(trusted=lib_entries) + ["-noanalysis", "-preScript", "MarkStringsConstant.java"] + \
        _library_args(lib_names, win32=True)
    if ws.get("prototypes", True):
        args += ["-preScript", "ApplyStackConvention.java", "-postScript", "RecoverPrototypes.java"]
    # COM interface pointers (DirectX ...): typed after the prototypes, so calls through their
    # vtables show the method names
    args += ["-postScript", "PropagateComTypes.java"]
    log = _headless(ghidra, d, args + _names_args(names) + [
        "-postScript", "ExportDecompiled.java", d["decomp"], ws["cname"],
        "-postScript", "DumpImports.java", os.path.join(d["decomp"], "imports.txt"),
        "-postScript", "DumpFixups.java", os.path.join(d["decomp"], "fixups.txt")], phase)
    _summary(log, LE_SUMMARY + "|" + PE_SUMMARY, out)


def find_entries(ws, out_file, functions=None):
    """tools/find_entries.py over the export (or a functions.csv); returns the number of addresses."""
    src = functions or wsp.sub(ws, "decomp")
    r = subprocess.run(paths.tool_cmd("find_entries.py") + [ws["exe"], src, out_file],
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
