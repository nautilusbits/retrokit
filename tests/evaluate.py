"""Score a retro-kit export against the ground truth of a synthetic test binary.

    python tests/evaluate.py <variant dir> [--json out.json] [-v]

Ground truth: the Watcom linker map (<variant>/engine.map: address and module of
every function) and the fixture sources (parameter counts, @noreturn / @table /
@varargs annotations). The export is read from <variant>/analysis/decomp.

Metrics (own = functions from the fixture sources, lib = Watcom runtime):
  own_found / lib_found   functions starting exactly at a map address
  own_truncated           own functions whose Ghidra body is clearly shorter than in the map
  own_params_ok           own functions whose signature has the right number of fixed params
  calls_args_ok           calls between own functions passing the right number of arguments
  strings_found           string literals of the sources printed as "..." in the .c
  extraout / unaff / undefined8 / in_reg / warnings   noise counters in the decompiled C
                          (whole file, and *_own for the fixture functions only)
"""
import argparse
import csv
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "fixtures", "dos", "src")


def parse_sources():
    """name -> {nparams, varargs, noreturn, table}"""
    funcs = {}
    defn = re.compile(r'^(?:static\s+)?[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\n\{', re.M)
    for path in glob.glob(os.path.join(SRC, "*.c")):
        text = open(path).read()
        for m in defn.finditer(text):
            name, params = m.group(1), m.group(2).strip()
            if name in ("if", "while", "for", "switch"):
                continue
            plist = [p.strip() for p in params.split(",")] if params and params != "void" else []
            prev = text[:m.start()].rstrip().splitlines()[-1:] or [""]
            notes = prev[0] if prev[0].lstrip().startswith("/*") else ""
            funcs[name] = {
                "nparams": len([p for p in plist if p != "..."]),
                "varargs": "..." in plist,
                "noreturn": "@noreturn" in notes,
                "table": "@table" in notes,
            }
    return funcs


def source_strings():
    """String literals used inside function bodies (file-scope initializers such as a
    table of names only show up in data, never as literals in the decompiled code)."""
    lits = set()
    for path in glob.glob(os.path.join(SRC, "*.c")):
        bodies = re.findall(r'\n\{\n(.*?)\n\}', open(path).read(), re.S)
        for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', "\n".join(bodies)):
            if len(m.group(1)) >= 4 and not m.group(1).endswith(".h"):
                lits.add(m.group(1))
    return lits


def parse_map(path):
    """[(segment, offset, name, own)] for every symbol in the map's memory map. Segmented
    (LE: "0001:00000010") or flat (PE: "00401010", segment None) addresses."""
    syms, module, in_map = [], "", False
    sym = re.compile(r'^(?:([0-9a-f]{4}):)?([0-9a-f]{8})[+* ]\s+(\S+)')
    for line in open(path, errors="replace"):
        if line.startswith("Module:"):
            module = line[7:].strip()
            in_map = True
            continue
        m = sym.match(line) if in_map else None
        if m:
            seg = int(m.group(1), 16) if m.group(1) else None
            syms.append((seg, int(m.group(2), 16), m.group(3), ".lib(" not in module.lower()))
    return syms


def norm(name):
    return name.strip("_")


def parse_blocks(path):
    """block key -> (start, end, perm) from memory_blocks.txt: LE objects keyed by number (the
    map's segment), PE sections by name"""
    blocks = {}
    for row in csv.DictReader(open(path), delimiter="\t"):
        if not re.match(r'^[0-9a-f]+$', row["start"]):
            continue    # overlay blocks such as .image::00000000
        m = re.match(r'\.object(\d+)$', row["name"])
        key = int(m.group(1)) if m else row["name"]
        blocks[key] = (int(row["start"], 16), int(row["end"], 16), row["perm"])
    return blocks


def count_params(sig):
    inner = sig[sig.find("(") + 1:sig.rfind(")")].strip()
    if not inner or inner == "void":
        return 0, False
    parts = [p.strip() for p in inner.split(",")]
    return len([p for p in parts if p != "..."]), "..." in parts


def split_call_args(text, start):
    """Count top-level arguments of the call whose '(' is at text[start]."""
    depth, n, has_tok = 0, 0, False
    for i in range(start, min(len(text), start + 4000)):
        c = text[i]
        if c in "([{":
            depth += 1
            if depth == 1:
                continue
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return n + (1 if has_tok else 0)
        elif c == "," and depth == 1:
            n += 1
            has_tok = False
            continue
        if depth >= 1 and not c.isspace():
            has_tok = True
    return None


def evaluate(vdir, verbose=False):
    decomp = os.path.join(vdir, "analysis", "decomp")
    src = parse_sources()
    blocks = parse_blocks(os.path.join(decomp, "memory_blocks.txt"))
    code_obj = min((k for k, v in blocks.items() if "x" in v[2]), key=lambda k: blocks[k][0])
    code_start, code_end = blocks[code_obj][0], blocks[code_obj][1]

    truth = {}   # addr -> (name, own)
    for seg, off, name, own in parse_map(os.path.join(vdir, "engine.map")):
        if seg is None:     # flat map (PE): absolute addresses
            if code_start <= off <= code_end:
                truth.setdefault(off, (norm(name), own))
        elif seg == code_obj:
            truth.setdefault(blocks[seg][0] + off, (norm(name), own))
    addrs = sorted(truth)
    size_of = {a: (addrs[i + 1] if i + 1 < len(addrs) else code_end) - a for i, a in enumerate(addrs)}

    # bytes of jump tables Watcom stores in the code object (fixup sources outside any
    # instruction): the map counts them into the preceding function
    table_slots = set()
    fx = os.path.join(decomp, "fixups.txt")
    if os.path.exists(fx):
        for line in open(fx):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 5 and f[3] in ("FUNC", "INFUNC") and f[4] == "-":
                slot = int(f[0], 16)
                if code_start <= slot < code_end:
                    table_slots.add(slot)

    def code_size(a):
        """map size of the function at a without in-code tables and alignment padding"""
        n = size_of[a] - 4 * sum(1 for s in table_slots if a <= s < a + size_of[a])
        return max(n - 15, 1)

    gh = {}
    for row in csv.DictReader(open(os.path.join(decomp, "functions.csv"))):
        gh[int(row["addr"], 16)] = row

    m = {"variant": os.path.basename(os.path.normpath(vdir))}
    issues = []
    own = [a for a in addrs if truth[a][1] and truth[a][0] in src]
    lib = [a for a in addrs if not truth[a][1]]
    m["own_total"], m["lib_total"] = len(own), len(lib)
    m["own_found"] = sum(1 for a in own if a in gh)
    m["lib_found"] = sum(1 for a in lib if a in gh)
    for a in own:
        if a not in gh:
            issues.append("missing   %08x %s" % (a, truth[a][0]))

    trunc = 0
    params_ok = 0
    gname = {}   # ghidra name -> source name
    for a in own:
        name = truth[a][0]
        if a not in gh:
            continue
        row = gh[a]
        gname[row["name"]] = name
        gsize, msize = int(row["size"]), size_of[a]
        if gsize < code_size(a) and gsize < 0.9 * msize:
            trunc += 1
            issues.append("truncated %08x %s: %d of %d bytes" % (a, name, gsize, msize))
        n, va = count_params(row["signature"])
        exp = src[name]
        if n == exp["nparams"] and va == exp["varargs"]:
            params_ok += 1
        else:
            issues.append("params    %08x %s: %d%s, expected %d%s  [%s]" % (
                a, name, n, "+..." if va else "", exp["nparams"], "+..." if exp["varargs"] else "",
                row["signature"]))
    m["own_truncated"] = trunc
    m["own_params_ok"] = params_ok

    cfile = glob.glob(os.path.join(decomp, "*_decompiled.c"))[0]
    text = open(cfile, errors="replace").read()

    # call sites between own functions
    calls, calls_ok = 0, 0
    hdr = re.compile(r'^// (\S+) @ ([0-9a-f]+)\s+size=', re.M)
    heads = list(hdr.finditer(text))
    callre = re.compile(r'\b(' + "|".join(re.escape(g) for g in gname) + r')\s*\(') if gname else None
    for i, h in enumerate(heads):
        if h.group(1) not in gname or callre is None:
            continue
        body = text[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        body = body[body.find("{"):] if "{" in body else ""
        for c in callre.finditer(body):
            n = split_call_args(body, c.end() - 1)
            callee = gname[c.group(1)]
            exp = src[callee]
            ok = n is not None and (n >= exp["nparams"] if exp["varargs"] else n == exp["nparams"])
            calls += 1
            calls_ok += ok
            if not ok:
                issues.append("call args %s -> %s: %s args, expected %s%d" % (
                    gname[h.group(1)], callee, n, ">=" if exp["varargs"] else "", exp["nparams"]))
    m["calls_total"], m["calls_args_ok"] = calls, calls_ok

    lits = source_strings()
    # the decompiler escapes quotes inside literals
    ctext = text.replace(r"\'", "'")
    found = sum(1 for s in lits if '"%s"' % s in ctext)
    m["strings_total"], m["strings_found"] = len(lits), found
    for s in sorted(lits):
        if '"%s"' % s not in ctext:
            issues.append('string    "%s" not a literal' % s)

    noise = {"extraout": r'\bextraout_', "unaff": r'\bunaff_', "undefined8": r'\bundefined8\b',
             "in_reg": r'\bin_[A-Z]{2,3}\b', "warnings": r'WARNING:'}
    own_addrs = set(own)
    own_text = "".join(text[h.start():heads[i + 1].start() if i + 1 < len(heads) else len(text)]
                       for i, h in enumerate(heads) if int(h.group(2), 16) in own_addrs)
    for k, pat in noise.items():
        m[k] = len(re.findall(pat, text))
        m[k + "_own"] = len(re.findall(pat, own_text))
    m["functions"] = len(gh)
    m["issues"] = issues
    return m


SUMMARY = [("own_found", "own_total"), ("lib_found", "lib_total"), ("own_params_ok", "own_total"),
           ("calls_args_ok", "calls_total"), ("strings_found", "strings_total")]
COUNTERS = ["own_truncated", "extraout", "unaff", "undefined8", "in_reg", "warnings"]
OWN_NOISE = ["extraout_own", "unaff_own", "undefined8_own", "in_reg_own", "warnings_own"]


def format_metrics(m):
    out = ["%-12s " % m["variant"] + "  ".join("%s %d/%d" % (k.replace("_found", "").replace("_ok", ""), m[k], m[t])
                                              for k, t in SUMMARY),
           " " * 13 + "  ".join("%s %d" % (k, m[k]) for k in COUNTERS),
           " " * 13 + "own code: " + "  ".join("%s %d" % (k[:-4], m[k]) for k in OWN_NOISE)]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("variant_dir")
    ap.add_argument("--json")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    m = evaluate(a.variant_dir)
    print(format_metrics(m))
    if a.verbose:
        for i in m["issues"]:
            print("   " + i)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(m, fh, indent=1)


if __name__ == "__main__":
    main()
