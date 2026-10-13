"""An analysis workspace: <out>/retrokit.json remembers how the binary was analysed, so later
runs (re-export, names, entries) need only the workspace directory.

    <out>/retrokit.json      settings (exe, format, loader, cspec, ...)
    <out>/ghidra_project/    Ghidra project
    <out>/decomp/            export (.c, functions.csv, calls.txt, strings.txt, fixups.txt, ...)
    <out>/notes/             findings and names_*.csv proposals
    <out>/logs/              headless Ghidra logs
"""
import json
import os

FILE = "retrokit.json"
VERSION = 1


def is_workspace(d):
    return os.path.isfile(os.path.join(d, FILE))


def default_dir(exe):
    base = os.path.splitext(os.path.basename(exe))[0].lower()
    return os.path.join(os.path.dirname(os.path.abspath(exe)), base + "_analysis")


def load(d):
    with open(os.path.join(d, FILE), encoding="utf-8") as fh:
        ws = json.load(fh)
    if ws.get("version", 0) > VERSION:
        raise ValueError("%s was written by a newer retrokit" % os.path.join(d, FILE))
    ws["dir"] = os.path.abspath(d)
    return ws


def save(ws):
    data = {k: v for k, v in ws.items() if k != "dir"}
    data["version"] = VERSION
    os.makedirs(ws["dir"], exist_ok=True)
    with open(os.path.join(ws["dir"], FILE), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")


def sub(ws, name):
    return os.path.join(ws["dir"], name)
