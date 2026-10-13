"""MCP server over retro-kit workspaces: lets an AI agent query an analysis (functions,
decompiled code, call graph, cross references, strings, pointer tables, disassembly, bytes),
record name proposals and notes, and re-export with the names applied.

    retrokit mcp GAME_analysis [OTHER_analysis ...]

Speaks the Model Context Protocol over stdio (newline-delimited JSON-RPC 2.0), without
third-party packages. Register it with an MCP client, e.g. Claude Code:

    claude mcp add retrokit -- retrokit mcp /path/to/GAME_analysis

Read tools only read the export (decomp/*), so they are fast and safe. Writes go to
notes/ only (names_<topic>.csv, <topic>.md); reexport runs the Ghidra pipeline in the
background and needs confirm=true.
"""
import bisect
import csv
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time

from . import __version__
from . import workspace as wsp

PROTOCOL = "2025-06-18"
MAX_TEXT = 60000
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,120}$")
CONFIDENCE = ("V", "G")


class ToolError(Exception):
    pass


def _hex(a):
    return "%08x" % a


def _parse_addr(s):
    s = str(s).strip().lower()
    m = re.match(r"^(?:0x)?([0-9a-f]{1,8})h?$", s)
    if m:
        return int(m.group(1), 16)
    m = re.match(r"^(?:fun|lab|dat|sub|thunk_fun)_([0-9a-f]{1,8})$", s)
    if m:
        return int(m.group(1), 16)
    return None


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _lines(path):
    return _read(path).splitlines(True)


def _clip(text, limit=MAX_TEXT):
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated: %d of %d characters shown; narrow the query]" % (limit, len(text))


class Workspace:
    """the export of one workspace, (re)loaded when its files change"""

    def __init__(self, path):
        if not wsp.is_workspace(path):
            raise ToolError("not a retrokit workspace: %s" % path)
        self.path = os.path.abspath(path)
        self.ws = wsp.load(self.path)
        self.decomp = wsp.sub(self.ws, "decomp")
        self.notes = wsp.sub(self.ws, "notes")
        self._stamp = None
        self._image = None
        self.job = None

    # -------------------------------------------------------------------------- loading
    def _files_stamp(self):
        out = []
        for f in ("functions.csv", "calls.txt", "fixups.txt", "strings.txt", self.ws.get("cname", "")):
            p = os.path.join(self.decomp, f)
            out.append(os.path.getmtime(p) if os.path.exists(p) else 0)
        return tuple(out)

    def load(self):
        stamp = self._files_stamp()
        if stamp == self._stamp:
            return self
        self.funcs, self.by_name = {}, {}
        fpath = os.path.join(self.decomp, "functions.csv")
        if not os.path.exists(fpath):
            raise ToolError("workspace has no export yet (decomp/functions.csv): run retrokit analyze")
        with open(fpath, encoding="utf-8", errors="replace") as fh:
            for r in csv.DictReader(fh):
                try:
                    a = int(r["addr"], 16)
                except ValueError:
                    continue
                r["size"] = int(r.get("size") or 0)
                self.funcs[a] = r
                self.by_name[r["name"]] = a
        self.starts = sorted(self.funcs)
        self.callees, self.callers = {}, {}
        cpath = os.path.join(self.decomp, "calls.txt")
        if os.path.exists(cpath):
            for line in _lines(cpath):
                m = re.match(r"^([0-9a-f]+) \S+ -> ([0-9a-f]+)", line)
                if m:
                    a, b = int(m.group(1), 16), int(m.group(2), 16)
                    self.callees.setdefault(a, []).append(b)
                    self.callers.setdefault(b, []).append(a)
        self.fixups = []        # (source, target, kind, owner, info)
        xpath = os.path.join(self.decomp, "fixups.txt")
        if os.path.exists(xpath):
            for line in _lines(xpath):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 5 and re.match(r"^[0-9a-f]+$", f[0]) and re.match(r"^[0-9a-f]+$", f[1]):
                    self.fixups.append((int(f[0], 16), int(f[1], 16), f[3], f[4], f[5] if len(f) > 5 else ""))
        self.to_target = {}
        for fx in self.fixups:
            self.to_target.setdefault(fx[1], []).append(fx)
        self.strings = []
        spath = os.path.join(self.decomp, "strings.txt")
        if os.path.exists(spath):
            for line in _lines(spath):
                f = line.rstrip("\n").split("\t", 2)
                if len(f) == 3 and re.match(r"^[0-9a-f]+$", f[0]):
                    self.strings.append((int(f[0], 16), f[2]))
        self.data = {}          # address -> (name, type)
        self.data_by_name = {}
        dpath = os.path.join(self.decomp, "data_symbols.txt")
        if os.path.exists(dpath):
            for line in _lines(dpath):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 3 and re.match(r"^[0-9a-f]+$", f[0]):
                    self.data[int(f[0], 16)] = (f[1], f[2])
                    self.data_by_name.setdefault(f[1], int(f[0], 16))
        self.code = {}
        cfile = os.path.join(self.decomp, self.ws.get("cname", ""))
        if not os.path.isfile(cfile):
            found = sorted(glob.glob(os.path.join(self.decomp, "*decompiled.c")))
            cfile = found[0] if found else None
        self.ctext = _read(cfile) if cfile else ""
        for m in re.finditer(r"^// =+\n// (\S+) @ ([0-9a-f]+)", self.ctext, re.M):
            self.code[int(m.group(2), 16)] = m.start()
        self.code_pos = sorted(self.code.values())
        self._stamp = stamp
        return self

    # ------------------------------------------------------------------------- helpers
    def resolve(self, ref):
        """function address from a name or an address"""
        if ref in self.by_name:
            return self.by_name[ref]
        if ref in self.data_by_name:
            return self.data_by_name[ref]
        a = _parse_addr(ref)
        if a is None:
            raise ToolError("unknown name %r (give a function or data name, or a hex address)" % ref)
        return a

    def containing(self, a):
        i = bisect.bisect_right(self.starts, a) - 1
        if i >= 0:
            f = self.funcs[self.starts[i]]
            if a < self.starts[i] + max(f["size"], 1):
                return self.starts[i]
        return None

    def label(self, a):
        if a in self.funcs:
            return self.funcs[a]["name"]
        if a in self.data:
            return self.data[a][0]
        c = self.containing(a)
        return "%s+0x%x" % (self.funcs[c]["name"], a - c) if c is not None else _hex(a)

    def c_of(self, a):
        """the function's block of the decompiled C (from its banner to the next banner)"""
        start = self.code.get(a)
        if start is None:
            return None
        i = bisect.bisect_right(self.code_pos, start)
        end = self.code_pos[i] if i < len(self.code_pos) else len(self.ctext)
        return self.ctext[start:end].rstrip() + "\n"

    def image(self):
        if self._image is None:
            from . import formats, sigs
            exe = self.ws["exe"]
            if not os.path.isfile(exe):
                raise ToolError("the executable is not where the workspace says: %s" % exe)
            self._image = sigs.code_regions(exe)
            with open(exe, "rb") as fh:
                data = fh.read()
            if formats.find_le(data) is not None:
                le = formats.LinearExecutable(data=data)
                objs, _, _ = le.loaded()
                bases = le.bases()
                self._image = [(bases[n], b) for n, b in objs.items() if b]
        return self._image

    def read(self, a, n):
        for base, buf in self.image():
            if base <= a < base + len(buf):
                return buf[a - base:a - base + n]
        raise ToolError("address %s is not in a loaded block" % _hex(a))


# ------------------------------------------------------------------------------------- tools

def _schema(props=None, required=()):
    return {"type": "object", "properties": props or {}, "required": list(required)}


WS_PROP = {"workspace": {"type": "string", "description": "workspace directory or name (optional when only one is open)"}}


class Server:
    def __init__(self, paths):
        self.workspaces = {}
        for p in paths:
            w = Workspace(p)
            self.workspaces[os.path.basename(w.path)] = w
        self.tools = self._tools()

    def ws(self, args):
        name = args.get("workspace")
        if not name:
            if len(self.workspaces) == 1:
                return next(iter(self.workspaces.values())).load()
            raise ToolError("several workspaces are open, pass workspace: %s" % ", ".join(self.workspaces))
        w = self.workspaces.get(name) or self.workspaces.get(os.path.basename(os.path.abspath(name)))
        if w is None:
            if wsp.is_workspace(name):
                w = Workspace(name)
                self.workspaces[os.path.basename(w.path)] = w
            else:
                raise ToolError("unknown workspace %r (open: %s)" % (name, ", ".join(self.workspaces)))
        return w.load()

    # each tool: name -> (description, schema, function(args) -> text)
    def _tools(self):
        def p(**props):
            return dict(WS_PROP, **props)
        S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
        return {
            "workspace_info": ("Overview of the analysis: executable, format, compiler, calling convention, "
                               "function counts (named / unnamed), libraries found, name proposal files.",
                               _schema(p()), self.t_info),
            "list_functions": ("Functions of the export with address, name, size, callers, callees, signature. "
                               "Filter by name regex and named/unnamed; sort by address, size or callers.",
                               _schema(p(pattern=dict(S, description="regex on the name"),
                                         which=dict(S, enum=["all", "named", "unnamed"]),
                                         sort=dict(S, enum=["addr", "size", "callers"]),
                                         offset=I, limit=dict(I, description="default 100, max 1000"))),
                               self.t_list),
            "get_function": ("Decompiled C of one or more functions (name or hex address), with signature and "
                             "the names of callers and callees.",
                             _schema(p(functions={"type": "array", "items": S, "description": "names or addresses"}),
                                     ["functions"]), self.t_get),
            "call_graph": ("Callers and/or callees of a function, to a given depth.",
                           _schema(p(function=S, direction=dict(S, enum=["callers", "callees", "both"]),
                                     depth=dict(I, description="1-4, default 1")), ["function"]), self.t_graph),
            "xrefs": ("Everything that references an address: calls, and pointers (fixups / relocations) with "
                      "the function they are in. Use it for data, strings and functions.",
                      _schema(p(address=S), ["address"]), self.t_xrefs),
            "search_code": ("Regex search over the decompiled C; returns matching lines with their function.",
                            _schema(p(regex=S, limit=dict(I, description="default 50")), ["regex"]), self.t_search),
            "strings": ("String literals of the program with address and the functions that use them.",
                        _schema(p(pattern=dict(S, description="regex on the text"), offset=I, limit=I)),
                        self.t_strings),
            "pointer_tables": ("Tables of pointers to functions found from consecutive fixups (handler tables, "
                               "state machines, callbacks): start, count and the functions.",
                               _schema(p(min_entries=dict(I, description="default 3"))), self.t_tables),
            "disassemble": ("x86 disassembly at an address (from the executable, no Ghidra), with pointer "
                            "targets and called functions named.",
                            _schema(p(address=S, count=dict(I, description="instructions, default 40, max 400")),
                                    ["address"]), self.t_disasm),
            "read_bytes": ("Hex dump of the loaded image (fixups applied) at an address.",
                           _schema(p(address=S, length=dict(I, description="default 128, max 4096")), ["address"]),
                           self.t_bytes),
            "libraries": ("Libraries the game uses (Miles, HMI, Smacker, zlib, ...) with evidence, version and "
                          "notes on formats and porting.", _schema(p()), self.t_libs),
            "propose_names": ("Record name proposals in notes/names_<topic>.csv for 'retrokit names' / reexport. "
                              "Each: address, name (C identifier), confidence V (verified) or G (guess), comment. "
                              "A proposal for an address already in that file replaces it.",
                              _schema(p(topic=dict(S, description="file topic, e.g. audio, ui, ai"),
                                        names={"type": "array", "items": _schema(
                                            {"address": S, "name": S, "confidence": dict(S, enum=list(CONFIDENCE)),
                                             "comment": S}, ["address", "name"])}),
                                      ["topic", "names"]), self.t_propose),
            "list_proposals": ("All name proposals in notes/names_*.csv, with conflicts (same address, different "
                               "names; same name, different addresses).", _schema(p()), self.t_proposals),
            "write_note": ("Write or append findings to notes/<topic>.md (formats, structures, open questions).",
                           _schema(p(topic=S, text=S, append=dict(B, description="default true")),
                                   ["topic", "text"]), self.t_note),
            "reexport": ("Apply the name proposals in Ghidra and export again (retrokit names): runs in the "
                         "background for minutes; check reexport_status. Needs confirm=true.",
                         _schema(p(confirm=B), ["confirm"]), self.t_reexport),
            "reexport_status": ("State of the last reexport: running / finished, exit code, last log lines.",
                                _schema(p()), self.t_reexport_status),
        }

    # ----------------------------------------------------------------------- read tools
    def t_info(self, a):
        w = self.ws(a)
        named = sum(1 for f in w.funcs.values() if not re.match(r"(FUN|thunk_FUN)_", f["name"]))
        lines = ["workspace: %s" % w.path, "executable: %s" % w.ws.get("exe")]
        for k in ("format", "extender", "compiler", "toolchain", "loader", "cspec"):
            if w.ws.get(k):
                lines.append("%s: %s" % (k, w.ws[k]))
        lines.append("functions: %d (%d named, %d unnamed)" % (len(w.funcs), named, len(w.funcs) - named))
        lines.append("strings: %d, pointers (fixups): %d" % (len(w.strings), len(w.fixups)))
        props = sorted(glob.glob(os.path.join(w.notes, "names_*.csv")) + glob.glob(os.path.join(w.notes, "sigs", "names_*.csv")))
        lines.append("name files: %s" % (", ".join(os.path.relpath(x, w.notes) for x in props) or "none"))
        libmd = os.path.join(w.notes, "libraries.md")
        if os.path.exists(libmd):
            libs = re.findall(r"^## (.+)$", _read(libmd), re.M)
            lines.append("libraries: %s" % (", ".join(libs) or "none"))
        lines.append("open workspaces: %s" % ", ".join(self.workspaces))
        return "\n".join(lines)

    def t_list(self, a):
        w = self.ws(a)
        rows = [w.funcs[x] for x in w.starts]
        if a.get("pattern"):
            try:
                rx = re.compile(a["pattern"])
            except re.error as e:
                raise ToolError("bad regex: %s" % e)
            rows = [r for r in rows if rx.search(r["name"])]
        which = a.get("which", "all")
        if which != "all":
            unnamed = lambda r: bool(re.match(r"(FUN|thunk_FUN)_", r["name"]))
            rows = [r for r in rows if unnamed(r) == (which == "unnamed")]
        key = a.get("sort", "addr")
        if key == "size":
            rows.sort(key=lambda r: -r["size"])
        elif key == "callers":
            rows.sort(key=lambda r: -int(r.get("callers") or 0))
        off, lim = max(0, int(a.get("offset", 0))), min(1000, max(1, int(a.get("limit", 100))))
        out = ["%d functions match; showing %d-%d" % (len(rows), off, min(off + lim, len(rows)))]
        out.append("addr\tname\tsize\tcallers\tcallees\tsignature")
        for r in rows[off:off + lim]:
            out.append("\t".join([r["addr"], r["name"], str(r["size"]), r.get("callers", ""), r.get("callees", ""),
                                  r.get("signature", "")]))
        return "\n".join(out)

    def t_get(self, a):
        w = self.ws(a)
        refs = a.get("functions") or []
        if isinstance(refs, str):
            refs = [refs]
        out = []
        for ref in refs[:20]:
            addr = w.resolve(ref)
            if addr not in w.funcs:
                c = w.containing(addr)
                if c is None:
                    what = "data %s (%s)" % w.data[addr] if addr in w.data else "no function"
                    out.append("// %s at %s: %s; see xrefs / read_bytes" % (ref, _hex(addr), what))
                    continue
                out.append("// %s is inside %s" % (ref, w.funcs[c]["name"]))
                addr = c
            f = w.funcs[addr]
            callers = sorted({w.label(x) for x in w.callers.get(addr, [])})
            callees = sorted({w.label(x) for x in w.callees.get(addr, [])})
            out.append("// %s @ %s  %s" % (f["name"], f["addr"], f.get("signature", "")))
            out.append("// callers (%d): %s" % (len(callers), ", ".join(callers[:40]) + (" ..." if len(callers) > 40 else "")))
            out.append("// callees (%d): %s" % (len(callees), ", ".join(callees[:40]) + (" ..." if len(callees) > 40 else "")))
            out.append(w.c_of(addr) or "// (no decompiled code in the export)")
        return _clip("\n".join(out))

    def t_graph(self, a):
        w = self.ws(a)
        root = w.resolve(a["function"])
        depth = min(4, max(1, int(a.get("depth", 1))))
        direction = a.get("direction", "both")
        out = []
        for d, edges in (("callers", w.callers), ("callees", w.callees)):
            if direction not in (d, "both"):
                continue
            out.append("%s of %s:" % (d, w.label(root)))
            seen, frontier = {root}, [root]
            for lvl in range(1, depth + 1):
                nxt = []
                for x in frontier:
                    for y in sorted(set(edges.get(x, []))):
                        if y not in seen:
                            seen.add(y)
                            nxt.append(y)
                            out.append("%s%s %s" % ("  " * lvl, _hex(y), w.label(y)))
                frontier = nxt
                if len(seen) > 2000:
                    out.append("  ... (stopped at 2000)")
                    break
        return _clip("\n".join(out))

    def t_xrefs(self, a):
        w = self.ws(a)
        addr = w.resolve(a["address"])
        out = ["references to %s (%s):" % (_hex(addr), w.label(addr))]
        for c in sorted(set(w.callers.get(addr, []))):
            out.append("  call   from %s %s" % (_hex(c), w.label(c)))
        for src, tgt, kind, owner, info in w.to_target.get(addr, []):
            out.append("  pointer at %s (%s, in %s)%s" % (_hex(src), kind, owner if owner != "-" else w.label(src),
                                                       " " + info if info else ""))
        if len(out) == 1:
            out.append("  none in the export")
        return _clip("\n".join(out))

    def t_search(self, a):
        w = self.ws(a)
        try:
            rx = re.compile(a["regex"])
        except re.error as e:
            raise ToolError("bad regex: %s" % e)
        lim = min(500, max(1, int(a.get("limit", 50))))
        out, n = [], 0
        cur = None
        for line in w.ctext.splitlines():
            m = re.match(r"^// (\S+) @ ([0-9a-f]+)\s", line)
            if m:
                cur = m.group(1)
                continue
            if rx.search(line):
                n += 1
                if len(out) < lim:
                    out.append("%s: %s" % (cur, line.strip()))
        return _clip("%d matching lines%s\n" % (n, ", first %d:" % lim if n > lim else ":") + "\n".join(out))

    def t_strings(self, a):
        w = self.ws(a)
        rows = w.strings
        if a.get("pattern"):
            try:
                rx = re.compile(a["pattern"])
            except re.error as e:
                raise ToolError("bad regex: %s" % e)
            rows = [r for r in rows if rx.search(r[1])]
        off, lim = max(0, int(a.get("offset", 0))), min(1000, max(1, int(a.get("limit", 100))))
        out = ["%d strings match" % len(rows)]
        for addr, text in rows[off:off + lim]:
            users = sorted({fx[3] if fx[3] != "-" else w.label(fx[0]) for fx in w.to_target.get(addr, [])})
            out.append("%s\t%s\t%s" % (_hex(addr), json.dumps(text), ", ".join(users[:8])))
        return _clip("\n".join(out))

    GAP = 0x20       # pointers further apart than this start a new table

    def t_tables(self, a):
        """runs of pointers stored in data (not inside a function) with at least min_entries
        function pointers: plain tables (stride 4) and arrays of records (stride = record size)"""
        w = self.ws(a)
        need = max(1, int(a.get("min_entries", 3)))
        rows = sorted((src, tgt, info) for src, tgt, kind, owner, info in w.fixups
                      if owner == "-" and w.containing(src) is None)
        groups, cur = [], []
        for r in rows:
            if cur and r[0] - cur[-1][0] > self.GAP:
                groups.append(cur)
                cur = []
            cur.append(r)
        if cur:
            groups.append(cur)
        tables = []
        for g in groups:
            fn = [r for r in g if r[1] in w.funcs]
            if len(fn) < need:
                continue
            deltas = {}
            for x, y in zip(fn, fn[1:]):
                deltas[y[0] - x[0]] = deltas.get(y[0] - x[0], 0) + 1
            stride = max(deltas, key=deltas.get) if deltas else 4
            tables.append((g, fn, stride))
        out = ["%d pointer tables with >= %d function pointers (pointers stored in data)" % (len(tables), need)]
        for g, fn, stride in tables[:200]:
            start = g[0][0]
            users = sorted({fx[3] if fx[3] != "-" else w.label(fx[0]) for fx in w.to_target.get(start, [])})
            kind = "table of function pointers" if stride == 4 and len(fn) == len(g) else \
                "array of records, stride 0x%x" % stride
            out.append("%s  %s: %d function pointers, %d pointers in all%s" % (
                _hex(start), kind, len(fn), len(g), "; referenced by " + ", ".join(users) if users else ""))
            for src, tgt, info in g[:48]:
                what = w.funcs[tgt]["name"] if tgt in w.funcs else (json.dumps(info) if info else w.label(tgt))
                out.append("    +0x%03x -> %s %s" % (src - start, _hex(tgt), what))
            if len(g) > 48:
                out.append("    ... %d more" % (len(g) - 48))
        return _clip("\n".join(out))

    def t_disasm(self, a):
        w = self.ws(a)
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        addr = w.resolve(a["address"])
        count = min(400, max(1, int(a.get("count", 40))))
        code = w.read(addr, count * 15)
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        fix_at = {fx[0]: fx for fx in w.fixups}
        out = []
        for i, ins in enumerate(md.disasm(code, addr)):
            if i >= count:
                break
            note = ""
            if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
                t = int(ins.op_str, 16)
                if t in w.funcs:
                    note = w.funcs[t]["name"]
            for s in range(ins.address, ins.address + ins.size):
                if s in fix_at:
                    tgt = fix_at[s][1]
                    note = (note + " " if note else "") + "-> %s %s" % (_hex(tgt), w.label(tgt) if (
                        tgt in w.funcs or w.containing(tgt) is not None) else fix_at[s][4] or "")
            if ins.address in w.funcs and ins.address != addr:
                out.append("%s:" % w.funcs[ins.address]["name"])
            out.append("%s  %-20s %s %s%s" % (_hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str,
                                              "    ; " + note.strip() if note.strip() else ""))
        return "\n".join(out) or "no instructions decoded at %s" % _hex(addr)

    def t_bytes(self, a):
        w = self.ws(a)
        addr = w.resolve(a["address"])
        n = min(4096, max(1, int(a.get("length", 128))))
        data = w.read(addr, n)
        out = []
        for o in range(0, len(data), 16):
            row = data[o:o + 16]
            out.append("%s  %-47s  %s" % (_hex(addr + o), " ".join("%02x" % b for b in row),
                                         "".join(chr(b) if 32 <= b < 127 else "." for b in row)))
        return "\n".join(out)

    def t_libs(self, a):
        w = self.ws(a)
        from . import libs
        return libs.format_report(libs.detect(w.ws["exe"]))

    # ---------------------------------------------------------------------- write tools
    def t_propose(self, a):
        w = self.ws(a)
        topic = str(a.get("topic", "")).strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,40}$", topic) or topic.lower() == "sigs":
            raise ToolError("topic must be 1-40 letters, digits, '_' or '-' (and not 'sigs')")
        path = os.path.join(w.notes, "names_%s.csv" % topic)
        rows = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8", newline="") as fh:
                for r in csv.DictReader(fh):
                    rows[r["addr"].lower()] = r
        accepted, rejected = [], []
        for item in a.get("names") or []:
            addr = _parse_addr(item.get("address", ""))
            name = str(item.get("name", "")).strip()
            conf = str(item.get("confidence", "G")).strip().upper() or "G"
            if addr is None:
                rejected.append("%r: not an address" % item.get("address"))
                continue
            if not IDENT.match(name) or re.match(r"(FUN|LAB|DAT|SUB)_[0-9a-fA-F]+$", name):
                rejected.append("%s: %r is not a usable C identifier" % (_hex(addr), name))
                continue
            if conf not in CONFIDENCE:
                rejected.append("%s: confidence must be V or G" % _hex(addr))
                continue
            known = addr in w.funcs or w.containing(addr) is not None or addr in w.to_target or any(
                s == addr for s, _ in w.strings)
            if not known:
                try:
                    w.read(addr, 1)
                except ToolError:
                    rejected.append("%s: address is not in the program" % _hex(addr))
                    continue
            comment = str(item.get("comment", "")).replace("\n", " ").strip()
            rows[_hex(addr)] = {"addr": _hex(addr), "name": name, "confidence": conf, "comment": comment}
            accepted.append("%s %s %s" % (_hex(addr), name, conf))
        if accepted:
            os.makedirs(w.notes, exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8", newline="") as fh:
                wr = csv.DictWriter(fh, fieldnames=["addr", "name", "confidence", "comment"], lineterminator="\n")
                wr.writeheader()
                for k in sorted(rows):
                    wr.writerow({f: rows[k].get(f, "") for f in wr.fieldnames})
            os.replace(tmp, path)
        out = ["%d proposals written to %s" % (len(accepted), os.path.relpath(path, w.path))]
        out += ["  " + x for x in accepted]
        if rejected:
            out.append("%d rejected:" % len(rejected))
            out += ["  " + x for x in rejected]
        out.append("They take effect after reexport (or 'retrokit names').")
        return "\n".join(out)

    def t_proposals(self, a):
        w = self.ws(a)
        by_addr, by_name, n = {}, {}, 0
        files = sorted(glob.glob(os.path.join(w.notes, "names_*.csv")))
        for f in files:
            with open(f, encoding="utf-8", newline="") as fh:
                for r in csv.DictReader(fh):
                    n += 1
                    src = os.path.basename(f)
                    by_addr.setdefault(r["addr"].lower(), []).append((r["name"], r.get("confidence", ""), src))
                    by_name.setdefault(r["name"], set()).add(r["addr"].lower())
        out = ["%d proposals in %d files: %s" % (n, len(files), ", ".join(os.path.basename(f) for f in files))]
        conflicts = [(k, v) for k, v in by_addr.items() if len({x[0] for x in v}) > 1]
        dups = [(k, v) for k, v in by_name.items() if len(v) > 1]
        for k, v in sorted(conflicts):
            out.append("conflict at %s: %s" % (k, "; ".join("%s %s (%s)" % x for x in v)))
        for k, v in sorted(dups):
            out.append("name %s proposed for %s (later ones get _<addr>)" % (k, ", ".join(sorted(v))))
        for k in sorted(by_addr):
            if len(out) > 2000:
                out.append("...")
                break
            out.append("%s %s" % (k, "; ".join("%s %s (%s)" % x for x in by_addr[k])))
        return _clip("\n".join(out))

    def t_note(self, a):
        w = self.ws(a)
        topic = str(a.get("topic", "")).strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,40}$", topic):
            raise ToolError("topic must be 1-40 letters, digits, '_' or '-'")
        path = os.path.join(w.notes, topic + ".md")
        os.makedirs(w.notes, exist_ok=True)
        append = a.get("append", True) and os.path.exists(path) and os.path.getsize(path) > 0
        with open(path, "a" if append else "w", encoding="utf-8", newline="\n") as fh:
            if append:
                fh.write("\n")
            fh.write(str(a.get("text", "")).rstrip() + "\n")
        return "written to %s (%d bytes)" % (os.path.relpath(path, w.path), os.path.getsize(path))

    def t_reexport(self, a):
        w = self.ws(a)
        if a.get("confirm") is not True:
            raise ToolError("reexport runs Ghidra for minutes and replaces decomp/: call again with confirm=true")
        if w.job and w.job["proc"].poll() is None:
            raise ToolError("a reexport is already running (reexport_status)")
        log = os.path.join(wsp.sub(w.ws, "logs"), "mcp_reexport.log")
        os.makedirs(os.path.dirname(log), exist_ok=True)
        fh = open(log, "w", encoding="utf-8")
        proc = subprocess.Popen([sys.executable, "-m", "retrokit", "names", w.path], stdout=fh,
                                stderr=subprocess.STDOUT, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        w.job = {"proc": proc, "log": log, "started": time.time(), "fh": fh}
        return "reexport started (pid %d); log %s. Poll reexport_status." % (proc.pid, os.path.relpath(log, w.path))

    def t_reexport_status(self, a):
        w = self.ws(a)
        if not w.job:
            return "no reexport started in this session"
        code = w.job["proc"].poll()
        if code is not None and not w.job["fh"].closed:
            w.job["fh"].close()
        tail = _read(w.job["log"]).splitlines()[-15:]
        state = "running for %ds" % (time.time() - w.job["started"]) if code is None else "finished, exit code %d" % code
        if code == 0:
            w._stamp = None          # reload the new export on the next query
        return "%s\n%s" % (state, "\n".join(tail))

    # ------------------------------------------------------------------------ protocol
    def handle(self, msg):
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if mid is None:
            return None                         # notifications (initialized, cancelled, ...)
        if method == "initialize":
            return self._ok(mid, {
                "protocolVersion": params.get("protocolVersion") or PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "retrokit", "version": __version__},
                "instructions": ("retro-kit analysis of old DOS/Win32 game executables. Start with workspace_info "
                                 "and libraries; find code through strings, xrefs, pointer_tables and call_graph; "
                                 "read it with get_function; record names with propose_names (V only when "
                                 "verified) and findings with write_note; reexport applies the names.")})
        if method == "ping":
            return self._ok(mid, {})
        if method == "tools/list":
            return self._ok(mid, {"tools": [{"name": n, "description": d, "inputSchema": s}
                                            for n, (d, s, _) in self.tools.items()]})
        if method == "tools/call":
            name = params.get("name")
            if name not in self.tools:
                return self._err(mid, -32602, "unknown tool %s" % name)
            try:
                text = self.tools[name][2](params.get("arguments") or {})
                return self._ok(mid, {"content": [{"type": "text", "text": text}], "isError": False})
            except (ToolError, KeyError, ValueError, OSError) as e:
                return self._ok(mid, {"content": [{"type": "text", "text": "error: %s" % e}], "isError": True})
        return self._err(mid, -32601, "method not found: %s" % method)

    @staticmethod
    def _ok(mid, result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _err(mid, code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(paths, stdin=None, stdout=None):
    if stdin is None:
        sys.stdin.reconfigure(encoding="utf-8")
        stdin = sys.stdin
    if stdout is None:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        stdout = sys.stdout
        sys.stdout = sys.stderr      # stray prints must not corrupt the protocol stream
    server = Server(paths)
    lock = threading.Lock()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply = Server._err(None, -32700, "parse error")
        else:
            msgs = msg if isinstance(msg, list) else [msg]
            replies = [r for r in (server.handle(m) for m in msgs if isinstance(m, dict)) if r]
            reply = (replies if isinstance(msg, list) else replies[0]) if replies else None
        if reply is not None:
            with lock:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()
