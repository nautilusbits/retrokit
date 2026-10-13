r"""Transfer function/data names from an analysed LE executable (A) to a related one (B: sequel, add-on,
other version) by function matching. Both need a retro-kit export (functions.csv, fixups.txt).

Signals (in this order, iterated to a fixpoint):
  1. exact   - identical code bytes with LE fixup fields and rel32 call/jmp targets masked, hash unique in both EXEs
  2. strings - identical set of referenced string literals, unique in both EXEs (+ fuzzy >= 0.5 sanity check)
  3. graph   - neighbourhood of matched pairs: callees aligned in call-site order, callers/callees paired by
               best mutual similarity of the normalised instruction stream (difflib ratio)
  4. anchors - unmatched functions compared by shared anchors (mapped data globals, matched callees/callers)
               combined with instruction similarity
  5. fuzzy   - global mutual best similarity for the rest (size within +-35 %, ratio >= 0.85; then a weak pass
               ratio >= 0.55 with margin 0.15 for functions >= 150 B, written as G)
Similarity = difflib ratio of normalised instructions (fixup operands/addresses masked), falling back to the
"shape" (mnemonic + operand kinds), which survives changed struct offsets and register allocation.
Data: for every matched pair the instruction streams are aligned; fixup targets of aligned instructions
vote for A data address -> B data address.

python match_names.py --a-exe A.EXE --a-decomp a_analysis/decomp --a-names a_analysis/notes/names_all.csv
                      --b-exe B.EXE --b-decomp b_analysis/decomp_unnamed --out b_analysis/notes/match
                      [--names-out b_analysis/notes/names_a_match.csv]
  -> <out>/func_map.csv (A addr, name, B addr, method, score), data_map.csv (A data addr -> B, votes),
     stats.txt and a names CSV for `retrokit names` (exact / >= 0.9 matches keep A's
     confidence, weaker ones become G; data labels are always G: the address is the same slot in matched
     code, but the variable can mean something else in B).
Use B's pre-rename export (copy decomp/ to decomp_unnamed/ before applying names).
Typical result for a sequel built with the same compiler: ~70 % of B's functions matched in a few minutes.
"""
import csv
import difflib
import hashlib
import os
import re
import sys
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

import argparse
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


class Image:
    """LE objects as ghidra-lx-loader maps them (le.py loaded once per EXE)."""

    def __init__(self, path):
        old = os.environ.get("LE_EXE")
        os.environ["LE_EXE"] = path
        try:
            spec = importlib.util.spec_from_file_location("le_%x" % (hash(path) & 0xffffffff), os.path.join(HERE, "le.py"))
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        finally:
            if old is None:
                del os.environ["LE_EXE"]
            else:
                os.environ["LE_EXE"] = old
        self.mem = {base: bytes(b) for base, b in m.mem.items()}

    def read(self, addr, n):
        for base, b in self.mem.items():
            if base <= addr < base + len(b):
                return b[addr - base: addr - base + n]
        raise KeyError(hex(addr))


ARGS = None

md = Cs(CS_ARCH_X86, CS_MODE_32)
NUM = re.compile(r"0x[0-9a-f]+|\b\d+\b")


class Prog:
    def __init__(self, exe, decomp):
        self.img = Image(exe)
        self.funcs = {}  # addr -> dict
        for r in csv.DictReader(open(os.path.join(decomp, "functions.csv"))):
            self.funcs[int(r["addr"], 16)] = {"name": r["name"], "size": int(r["size"])}
        self.fix = {}  # src -> (target, kind, string)
        for line in open(os.path.join(decomp, "fixups.txt"), encoding="latin-1"):
            p = line.rstrip("\n").split("\t")
            if len(p) < 5:
                continue
            s = p[5] if len(p) > 5 else ""
            self.fix[int(p[0], 16)] = (int(p[1], 16), p[3], s)
        self.fix_sorted = sorted(self.fix)
        self.starts = sorted(self.funcs)
        for a in self.starts:
            self._analyse(a)
        # callers
        self.callers = defaultdict(set)
        for a, f in self.funcs.items():
            for t in f["calls"]:
                if t in self.funcs:
                    self.callers[t].add(a)

    def _analyse(self, a):
        f = self.funcs[a]
        size = max(1, f["size"])
        try:
            code = self.img.read(a, size)
        except KeyError:
            code = b""
        masked = bytearray(code)
        toks, refs, calls, shape = [], [], [], []
        import bisect
        i0 = bisect.bisect_left(self.fix_sorted, a)
        fx = {}
        while i0 < len(self.fix_sorted) and self.fix_sorted[i0] < a + size:
            s = self.fix_sorted[i0]
            fx[s] = self.fix[s]
            for k in range(4):
                if s - a + k < len(masked):
                    masked[s - a + k] = 0
            i0 += 1
        strings = set()
        for s, (t, kind, st) in fx.items():
            if kind == "DATA" and st.startswith('"') and len(st) > 4:
                strings.add(st)
        for ins in md.disasm(code, a):
            op = ins.op_str
            fxi = [s for s in range(ins.address, ins.address + ins.size) if s in fx]
            if ins.mnemonic in ("call", "jmp") and ins.size == 5 and ins.bytes[0] in (0xE8, 0xE9):
                tgt = int(op, 16) if op.startswith("0x") else None
                off = ins.address - a
                for k in range(1, 5):
                    if off + k < len(masked):
                        masked[off + k] = 0
                inside = tgt is not None and a <= tgt < a + size
                if not inside:
                    calls.append(tgt)
                    toks.append(ins.mnemonic + " F")
                    shape.append(ins.mnemonic + " F")
                    refs.append(("C", tgt))
                    continue
            if fxi:
                for s in fxi:
                    t, kind, st = fx[s]
                    refs.append(("D" if kind == "DATA" else "C", t))
                    if kind != "DATA":
                        calls.append(t)
                op = NUM.sub(lambda m: "X" if len(m.group(0)) > 5 else m.group(0), op)
            elif ins.mnemonic.startswith("j") or ins.mnemonic in ("loop", "call"):
                op = "L"
            else:
                op = NUM.sub(lambda m: "N" if (m.group(0).startswith("0x") and int(m.group(0), 16) >= 0x10000) else m.group(0), op)
            toks.append(ins.mnemonic + " " + op)
            shape.append(ins.mnemonic + " " + ",".join(("m" if "[" in o else "r" if re.fullmatch(r"[a-z]{2,3}", o.strip()) else "i") for o in ins.op_str.split(",")) if ins.op_str else ins.mnemonic)
        f["hash"] = hashlib.sha1(bytes(masked)).hexdigest() if code else None
        f["toks"] = toks
        f["shape"] = shape
        f["refs"] = refs  # ordered (kind, target) with the index of the token they belong to lost - see align_refs
        f["calls"] = [c for c in calls if c is not None]
        f["strings"] = frozenset(strings)
        # per-token refs for data alignment
        f["tokrefs"] = self._tokrefs(a, code, fx)

    def _tokrefs(self, a, code, fx):
        out = []
        for ins in md.disasm(code, a):
            r = [fx[s][0] for s in range(ins.address, ins.address + ins.size) if s in fx and fx[s][1] == "DATA"]
            out.append(r)
        return out


def ratio(fa, fb):
    r1 = _ratio(fa["toks"], fb["toks"])
    if r1 >= 0.9:
        return r1
    return max(r1, 0.97 * _ratio(fa["shape"], fb["shape"]))


def _ratio(ta, tb):
    if not ta or not tb:
        return 0.0
    if len(ta) > 3 * len(tb) or len(tb) > 3 * len(ta):
        return 0.0
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    if sm.real_quick_ratio() < 0.5 or sm.quick_ratio() < 0.5:
        return sm.quick_ratio() * 0.5
    return sm.ratio()


def main():
    ea = Prog(ARGS.a_exe, ARGS.a_decomp)
    eb = Prog(ARGS.b_exe, ARGS.b_decomp)
    OUT = ARGS.out
    print("functions A %d B %d" % (len(ea.funcs), len(eb.funcs)))
    m, rm, how = {}, {}, {}  # ea->eb, eb->ea, ea->(method, score)

    def add(d, j, method, score):
        if d in m or j in rm:
            return False
        m[d] = j
        rm[j] = d
        how[d] = (method, score)
        return True

    # 1. exact unique hashes (ignore tiny functions: < 6 bytes carry no information)
    hd, hj = defaultdict(list), defaultdict(list)
    for a, f in ea.funcs.items():
        if f["hash"] and f["size"] >= 6:
            hd[f["hash"]].append(a)
    for a, f in eb.funcs.items():
        if f["hash"] and f["size"] >= 6:
            hj[f["hash"]].append(a)
    for h, l in hd.items():
        if len(l) == 1 and len(hj.get(h, [])) == 1:
            add(l[0], hj[h][0], "exact", 1.0)
    print("exact unique:", len(m))

    # 2. unique string sets
    sd, sj = defaultdict(list), defaultdict(list)
    for a, f in ea.funcs.items():
        if f["strings"]:
            sd[f["strings"]].append(a)
    for a, f in eb.funcs.items():
        if f["strings"]:
            sj[f["strings"]].append(a)
    n = 0
    for k, l in sd.items():
        if len(l) == 1 and len(sj.get(k, [])) == 1 and l[0] not in m and sj[k][0] not in rm:
            r = ratio(ea.funcs[l[0]], eb.funcs[sj[k][0]])
            if r >= 0.5:
                n += add(l[0], sj[k][0], "strings", r)
    print("strings:", n)

    # 3./4. propagation
    cache = {}

    def sim(d, j):
        k = (d, j)
        if k not in cache:
            fd, fj = ea.funcs[d], eb.funcs[j]
            if fd["hash"] and fd["hash"] == fj["hash"]:
                cache[k] = 1.0
            else:
                cache[k] = ratio(fd, fj)
        return cache[k]

    def pair_sets(ds, js, thr, method):
        ds = [d for d in ds if d in ea.funcs and d not in m]
        js = [j for j in js if j in eb.funcs and j not in rm]
        if not ds or not js or len(ds) * len(js) > 400:
            return 0
        sc = {(d, j): sim(d, j) for d in ds for j in js}
        c = 0
        for d in ds:
            bj = max(js, key=lambda j: sc[(d, j)])
            s = sc[(d, bj)]
            if s < thr:
                continue
            bd = max(ds, key=lambda x: sc[(x, bj)])
            if bd != d:
                continue
            second = max([sc[(d, j)] for j in js if j != bj] + [0])
            if s - second < 0.05 and s < 1.0:
                continue
            c += add(d, bj, method, s)
        return c

    def data_votes():
        votes = defaultdict(Counter)
        for d, j in m.items():
            fd, fj = ea.funcs[d], eb.funcs[j]
            key = "toks" if how[d][0] == "exact" else "shape"
            sm = difflib.SequenceMatcher(None, fd[key], fj[key], autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag != "equal":
                    continue
                for k in range(i2 - i1):
                    ra = fd["tokrefs"][i1 + k] if i1 + k < len(fd["tokrefs"]) else []
                    rb = fj["tokrefs"][j1 + k] if j1 + k < len(fj["tokrefs"]) else []
                    if len(ra) == len(rb):
                        for x, y in zip(ra, rb):
                            votes[x][y] += 1
        return votes

    def propagate():
        c = 0
        for d, j in list(m.items()):
            fd, fj = ea.funcs[d], eb.funcs[j]
            cd, cj = fd["calls"], fj["calls"]
            lab_d = [("M", m[x]) if x in m else ("U", ea.funcs[x]["hash"] if x in ea.funcs else x) for x in cd]
            lab_j = [("M", x) if x in rm else ("U", eb.funcs[x]["hash"] if x in eb.funcs else x) for x in cj]
            sm = difflib.SequenceMatcher(None, lab_d, lab_j, autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag in ("equal", "replace") and i2 - i1 == j2 - j1:
                    for x, y in zip(cd[i1:i2], cj[j1:j2]):
                        if x in ea.funcs and y in eb.funcs and x not in m and y not in rm:
                            s = sim(x, y)
                            if s >= (0.5 if tag == "equal" else 0.7):
                                c += add(x, y, "callee", s)
                elif tag == "replace":
                    c += pair_sets(set(cd[i1:i2]), set(cj[j1:j2]), 0.75, "callee")
            c += pair_sets(set(cd), set(cj), 0.8, "callee")
            c += pair_sets(ea.callers[d], eb.callers[j], 0.75, "caller")
        return c

    def anchors():
        """Unmatched functions compared by shared anchors: mapped data globals, matched callees/callers."""
        votes = data_votes()
        dmap = {}
        for x, cnt in votes.items():
            y, v = cnt.most_common(1)[0]
            if v * 2 > sum(cnt.values()):
                dmap[x] = y

        def anc_d(d):
            f = ea.funcs[d]
            s = {("D", dmap[t]) for k, t in f["refs"] if k == "D" and t in dmap}
            s |= {("F", m[t]) for t in f["calls"] if t in m}
            s |= {("C", m[t]) for t in ea.callers[d] if t in m}
            return s

        def anc_j(j):
            f = eb.funcs[j]
            s = {("D", t) for k, t in f["refs"] if k == "D"}
            s |= {("F", t) for t in f["calls"] if t in rm}
            s |= {("C", t) for t in eb.callers[j] if t in rm}
            return s

        uj = [j for j in eb.funcs if j not in rm]
        aj = {j: anc_j(j) for j in uj}
        inv = defaultdict(set)
        for j, s in aj.items():
            for x in s:
                inv[x].add(j)
        best_d = {}
        for d in ea.funcs:
            if d in m:
                continue
            ad = anc_d(d)
            if len(ad) < 2:
                continue
            cands = set()
            for x in ad:
                if len(inv[x]) <= 20:
                    cands |= inv[x]
            sc = []
            for j in cands:
                inter = len(ad & aj[j])
                if inter < 2:
                    continue
                jac = inter / len(ad | aj[j])
                if jac < 0.3:
                    continue
                r = sim(d, j)
                sc.append((0.6 * jac + 0.4 * r, jac, r, j))
            sc.sort(reverse=True)
            if sc and sc[0][0] >= 0.5 and sc[0][2] >= 0.35 and (len(sc) < 2 or sc[0][0] - sc[1][0] >= 0.08):
                best_d[d] = sc[0]
        byj = defaultdict(list)
        for d, t in best_d.items():
            byj[t[3]].append((t[0], d))
        c = 0
        for j, l in byj.items():
            l.sort(reverse=True)
            if len(l) == 1 or l[0][0] - l[1][0] >= 0.08:
                c += add(l[0][1], j, "anchors", l[0][0])
        return c

    def global_fuzzy(thr=0.85, margin=0.05, minsize=48, method="fuzzy"):
        ud = [a for a in ea.funcs if a not in m and ea.funcs[a]["size"] >= minsize]
        uj = [a for a in eb.funcs if a not in rm and eb.funcs[a]["size"] >= minsize]
        best = {}
        for d in ud:
            sd_ = ea.funcs[d]["size"]
            cands = [j for j in uj if 0.65 * sd_ <= eb.funcs[j]["size"] <= 1.35 * sd_]
            sc = sorted(((sim(d, j), j) for j in cands), reverse=True)[:2]
            if sc and sc[0][0] >= thr and (len(sc) < 2 or sc[0][0] - sc[1][0] >= margin):
                best[d] = sc[0]
        byj = defaultdict(list)
        for d, (s, j) in best.items():
            byj[j].append((s, d))
        g = 0
        for j, l in byj.items():
            l.sort(reverse=True)
            if len(l) == 1 or l[0][0] - l[1][0] >= margin:
                g += add(l[0][1], j, method, l[0][0])
        return g

    fuzzy_done = 0
    for it in range(40):
        c = propagate()
        print("round %d propagation +%d" % (it, c))
        if c:
            continue
        c = anchors()
        print("round %d anchors +%d" % (it, c))
        if c:
            continue
        if fuzzy_done == 2:
            break
        c = global_fuzzy() if fuzzy_done == 0 else global_fuzzy(0.55, 0.15, 150, "fuzzy-weak")
        fuzzy_done += 1
        print("round %d global fuzzy +%d" % (it, c))
        if not c and fuzzy_done == 2:
            break

    votes = data_votes()

    os.makedirs(OUT, exist_ok=True)
    # names
    anames = {}
    if ARGS.a_names:
        for r in csv.DictReader(open(ARGS.a_names, encoding="utf-8")):
            anames[int(r["addr"], 16)] = (r["name"], r["confidence"], r["comment"])
    for a, f in ea.funcs.items():
        if a not in anames and not f["name"].startswith(("FUN_", "thunk_FUN_")):
            anames[a] = (f["name"], "V", "ghidra/runtime name in A")

    with open(os.path.join(OUT, "func_map.csv"), "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["a_addr", "a_name", "b_addr", "method", "score", "a_size", "b_size"])
        for d in sorted(m):
            w.writerow(["%08x" % d, anames.get(d, (ea.funcs[d]["name"],))[0], "%08x" % m[d], how[d][0],
                        "%.3f" % how[d][1], ea.funcs[d]["size"], eb.funcs[m[d]]["size"]])
    datamap = {}
    with open(os.path.join(OUT, "data_map.csv"), "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["a_addr", "b_addr", "votes", "total", "a_name"])
        for x in sorted(votes):
            y, v = votes[x].most_common(1)[0]
            tot = sum(votes[x].values())
            datamap[x] = (y, v, tot)
            w.writerow(["%08x" % x, "%08x" % y, v, tot, anames.get(x, ("",))[0]])

    rows = []
    fn_named = dat_named = 0
    for d, j in sorted(m.items()):
        if d in anames:
            name, conf, com = anames[d]
            meth, s = how[d]
            if meth == "fuzzy-weak" or (meth != "exact" and s < 0.9):
                conf = "G"
            rows.append(("%08x" % j, name, conf, "[ea-match %s %.2f A %08x] %s" % (meth, s, d, com)))
            fn_named += 1
    for x, (name, conf, com) in anames.items():
        if x in ea.funcs or x not in datamap:
            continue
        y, v, tot = datamap[x]
        if v * 2 <= tot:
            continue
        rows.append(("%08x" % y, name, "G", "[ea-match data %d/%d A %08x; same slot in matched code, meaning may differ] %s" % (v, tot, x, com)))
        dat_named += 1
    with open(ARGS.names_out or os.path.join(OUT, "names_matched.csv"), "w", newline="", encoding="utf-8") as fo:
        w = csv.writer(fo)
        w.writerow(["addr", "name", "confidence", "comment"])
        for r in rows:
            w.writerow(r)

    meth = Counter(v[0] for v in how.values())
    named_a_funcs = [a for a in anames if a in ea.funcs]
    named_hit = sum(1 for a in named_a_funcs if a in m)
    a_data_named = [a for a in anames if a not in ea.funcs]
    with open(os.path.join(OUT, "stats.txt"), "w") as fo:
        for out in (sys.stdout, fo):
            print("matched functions: %d of A %d (%.1f %%), of B %d (%.1f %%)" % (
                len(m), len(ea.funcs), 100 * len(m) / len(ea.funcs), len(eb.funcs), 100 * len(m) / len(eb.funcs)), file=out)
            print("by method:", dict(meth), file=out)
            print("named A functions matched: %d of %d (%.1f %%)" % (
                named_hit, len(named_a_funcs), 100 * named_hit / max(1, len(named_a_funcs))), file=out)
            print("named A data labels mapped: %d of %d" % (dat_named, len(a_data_named)), file=out)
            print("names written: functions %d, data %d" % (fn_named, dat_named), file=out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--a-exe", required=True)
    ap.add_argument("--a-decomp", required=True)
    ap.add_argument("--a-names", help="names CSV of A (addr,name,confidence,comment); Ghidra names from functions.csv are used too")
    ap.add_argument("--b-exe", required=True)
    ap.add_argument("--b-decomp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--names-out")
    ARGS = ap.parse_args()
    main()
