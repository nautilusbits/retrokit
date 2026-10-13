"""Which period libraries a game uses: evidence from knowledge/libraries.json (strings in the
executable, imported DLLs and functions, files and data-file signatures next to it).

    retrokit libs GAME.EXE [--dir GAME_DIR] [--json]
"""
import fnmatch
import json
import os
import re

from . import formats
from . import paths

CATALOG = os.path.join(paths.KNOWLEDGE, "libraries.json")
MAX_FILES = 5000          # files looked at in the game directory
MAX_DEPTH = 3


def catalog():
    with open(CATALOG, encoding="utf-8") as fh:
        return json.load(fh)["libraries"]


def _pe_import_names(data):
    """(dll names, imported function names) of a PE, empty for anything else"""
    import struct
    if data[:2] != b"MZ" or len(data) < 0x40:
        return set(), set()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return set(), set()
    nsec, opt = struct.unpack_from("<HH", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    secs = []
    for i in range(nsec):
        s = pe + 24 + opt + i * 40
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        secs.append((va, max(vsize, rsize), raw))

    def off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return raw + rva - va
        return None

    def cstr(o):
        e = data.find(b"\0", o)
        return data[o:e].decode("latin-1") if o is not None and e > o else ""
    imp_rva = struct.unpack_from("<I", data, pe + 24 + 104)[0]
    dlls, funcs = set(), set()
    o = off(imp_rva) if imp_rva else None
    while o is not None and o + 20 <= len(data):
        oft, _, _, name, ft = struct.unpack_from("<IIIII", data, o)
        if not name:
            break
        dlls.add(cstr(off(name)).upper())
        t = off(oft or ft)
        while t is not None and t + 4 <= len(data):
            v = struct.unpack_from("<I", data, t)[0]
            if not v:
                break
            if not v & 0x80000000:
                n = off(v + 2)
                if n is not None:
                    funcs.add(cstr(n))
            t += 4
        o += 20
    return dlls, funcs


def _game_files(d):
    out = []
    base = d.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(d):
        if root.count(os.sep) - base >= MAX_DEPTH:
            dirs[:] = []
        dirs[:] = [x for x in dirs if not x.lower().endswith("_analysis")]
        for f in files:
            out.append(os.path.join(root, f))
            if len(out) >= MAX_FILES:
                return out
    return out


def detect(exe, game_dir=None):
    """[{id, name, evidence: [...], version, notes, signatures, prototypes}] for every library
    with evidence"""
    data = open(exe, "rb").read()
    dlls, funcs = _pe_import_names(data)
    files = _game_files(game_dir or os.path.dirname(os.path.abspath(exe)))
    heads = {}
    out = []
    for lib in catalog():
        ev = []
        for s in lib.get("strings", ()):
            if data.find(s.encode("latin-1")) >= 0:
                ev.append("string %r" % s)
        for dll in lib.get("imports", ()):
            if dll.upper() in dlls:
                ev.append("imports %s" % dll)
        for pre in lib.get("import_prefix", ()):
            hits = sorted(f for f in funcs if f.startswith(pre))
            if hits:
                ev.append("imports %d %s* functions" % (len(hits), pre))
        pats = [p.lower() for p in lib.get("files", ())]
        if pats:
            hits = sorted({os.path.basename(f) for f in files
                           if any(fnmatch.fnmatch(os.path.basename(f).lower(), p) for p in pats)})
            if hits:
                ev.append("files %s%s" % (", ".join(hits[:5]), " (+%d)" % (len(hits) - 5) if len(hits) > 5 else ""))
        magics = [m.encode("latin-1") for m in lib.get("magic", ())]
        if magics:
            n = 0
            for f in files:
                if f not in heads:
                    try:
                        with open(f, "rb") as fh:
                            heads[f] = fh.read(16)
                    except OSError:
                        heads[f] = b""
                if any(heads[f].startswith(m) for m in magics):
                    n += 1
            if n:
                ev.append("%d data files with signature %s" % (n, "/".join(repr(m.decode("latin-1")) for m in magics)))
        if not ev:
            continue
        version = None
        if lib.get("version"):
            m = re.search(lib["version"].encode("latin-1"), data)
            if m:
                version = m.group(1).decode("latin-1")
        out.append({"id": lib["id"], "name": lib["name"], "vendor": lib.get("vendor"), "license": lib.get("license"),
                    "evidence": ev, "version": version, "notes": lib.get("notes", ""),
                    "signatures": lib.get("signatures"), "prototypes": lib.get("prototypes")})
    return out


def format_report(found):
    if not found:
        return "no known libraries found"
    lines = []
    for f in found:
        lines.append("%s%s  [%s]" % (f["name"], " " + f["version"] if f["version"] else "", f["license"]))
        for e in f["evidence"]:
            lines.append("    evidence: %s" % e)
        kit = [x for x in ("signatures " + f["signatures"] if f["signatures"] else "",
                           "prototypes knowledge/" + f["prototypes"] if f["prototypes"] else "") if x]
        if kit:
            lines.append("    retrokit: %s" % ", ".join(kit))
        lines.append("    " + f["notes"])
    return "\n".join(lines)


def write_notes(path, exe, found):
    """notes/libraries.md for the workspace"""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# Libraries found in %s\n\n" % os.path.basename(exe))
        fh.write("Detected by `retrokit libs` from knowledge/libraries.json; evidence is listed, check it.\n\n")
        for f in found:
            fh.write("## %s%s\n\n" % (f["name"], " " + f["version"] if f["version"] else ""))
            fh.write("- vendor: %s; license: %s\n" % (f["vendor"], f["license"]))
            for e in f["evidence"]:
                fh.write("- evidence: %s\n" % e)
            if f["signatures"] or f["prototypes"]:
                fh.write("- retrokit: %s\n" % ", ".join(x for x in (
                    f["signatures"] and "signatures `%s`" % f["signatures"],
                    f["prototypes"] and "prototypes `knowledge/%s`" % f["prototypes"]) if x))
            fh.write("\n%s\n\n" % f["notes"])
        if not found:
            fh.write("No known library found.\n")
