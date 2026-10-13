"""Fuzzy tier of the library signatures: functions whose code differs from the signature in
register allocation, instruction order or a few changed instructions - the same library
function from another compiler version (Watcom 10.x run-time vs. Open Watcom signatures).

Every signature and every candidate function of the program becomes a sequence of normalised
instructions (registers abstracted to their size, addresses and call targets masked, small
constants kept). Candidates are the call targets and code pointers of the program; for each,
the signatures sharing the most instruction 4-grams are compared with difflib, and a name is
taken when it is clearly better than any other name and, where both sides call named
functions, the callees agree. Results are always confidence G.
"""
import difflib
import hashlib
import os
import pickle
import re
import struct
from collections import Counter, defaultdict

MIN_INSNS = 10        # shorter functions are too alike to tell apart without callees
ACCEPT = 0.80         # similarity needed on its own
ACCEPT_CALLEES = 0.70  # ... when at least one callee name agrees
MARGIN = 0.08         # over the best different name
NEAR = 0.03           # closer than this to the best: a tie
TOP = 10              # signatures compared per candidate after the 4-gram filter
GRAM = 4
WRAPPER = 20          # below this many instructions a function that calls others needs a callee match
MAX_FUNC = 8192

_REG = {}
for _n in ("eax ebx ecx edx esi edi ebp esp".split()):
    _REG[_n] = "r32"
for _n in ("ax bx cx dx si di bp sp".split()):
    _REG[_n] = "r16"
for _n in ("al bl cl dl ah bh ch dh".split()):
    _REG[_n] = "r8"
_NUM = re.compile(r"0x[0-9a-f]+|\b\d+\b")
_WORD = re.compile(r"\b[a-z]{2,3}\b")


def _norm_num(m):
    s = m.group(0)
    v = int(s, 16) if s.startswith("0x") else int(s)
    return s if v < 0x1000 else "N"


def _operand(op):
    op = op.strip()
    if op in _REG:
        return _REG[op]
    if op.startswith(("st", "mm", "xmm")) or op in ("cs", "ds", "es", "fs", "gs", "ss"):
        return op
    if "[" in op:
        size = op.split("ptr")[0].strip() if "ptr" in op else ""
        inner = op[op.index("[") + 1:op.rindex("]")]
        inner = _WORD.sub(lambda m: "r" if m.group(0) in _REG else m.group(0), inner)
        inner = _NUM.sub(_norm_num, inner)
        return "%s[%s]" % (size[:1], inner)
    return _NUM.sub(_norm_num, op)


def normalise(md, code, start, end):
    """(tokens, shapes, [call target or None per call], insn count) of code[start:end] at address start"""
    toks, shapes, calls = [], [], []
    for ins in md.disasm(code[start:end] if isinstance(code, (bytes, bytearray)) else code, start):
        m = ins.mnemonic
        if m.startswith("j") or m.startswith("loop") or m == "call":
            if m == "call" and ins.op_str.startswith("0x"):
                t = int(ins.op_str, 16)
                calls.append(t)
                toks.append("call F")
            elif ins.op_str.startswith("0x"):
                t = int(ins.op_str, 16)
                if m == "jmp" and not (start <= t < end):
                    calls.append(t)
                    toks.append("jmp F")
                else:
                    toks.append(m + " L")
            else:
                toks.append(m + " " + _operand(ins.op_str))
        else:
            ops = [_operand(o) for o in ins.op_str.split(",")] if ins.op_str else []
            toks.append(m + " " + ",".join(ops))
        shapes.append(toks[-1].split(" ")[0] + " " + ",".join(
            "m" if "[" in o else "r" if o.startswith("r") else "i" for o in toks[-1].split(" ", 1)[1].split(",") if o))
    return toks, shapes, calls


class Model:
    """normalised instruction streams of the signatures"""

    def __init__(self, sigs, md):
        self.items, self.bags = [], []
        cache = _Cache()
        for s in sigs:
            toks, shapes = cache.get(s, md)
            if len(toks) < MIN_INSNS // 2:
                continue
            names = [c for _, c in s.callees]
            self.items.append((s, toks, shapes, names))
            self.bags.append(Counter(shapes))
        cache.save()
        self.index = defaultdict(list)
        for i, (_, _, shapes, _) in enumerate(self.items):
            for g in set(_grams(shapes)):
                self.index[g].append(i)
        # grams present in many signatures say little
        self.common = {g for g, l in self.index.items() if len(l) > max(50, len(self.items) // 20)}


class _Cache:
    """normalised signatures on disk (~/.retrokit/cache), keyed by the pattern: normalising
    thousands of signatures costs seconds on every run otherwise"""
    VERSION = 1

    def __init__(self):
        self.path = os.path.join(os.path.expanduser("~"), ".retrokit", "cache", "fuzzy-v%d.pickle" % self.VERSION)
        self.data, self.dirty = {}, False
        try:
            with open(self.path, "rb") as fh:
                self.data = pickle.load(fh)
        except (OSError, EOFError, pickle.UnpicklingError, ValueError):
            self.data = {}

    def get(self, sig, md):
        code = bytes(0x7f if b is None else b for b in sig.pattern)    # masked -> large value -> "N"
        key = hashlib.sha1(code + bytes(b is None for b in sig.pattern)).digest()
        hit = self.data.get(key)
        if hit is None:
            toks, shapes, _ = normalise(md, code, 0, len(code))
            hit = self.data[key] = (toks, shapes)
            self.dirty = True
        return hit

    def save(self):
        if not self.dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "wb") as fh:
                pickle.dump(self.data, fh, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp, self.path)
        except OSError:
            pass        # read-only home: just slower next time


def _grams(shapes):
    return [tuple(shapes[i:i + GRAM]) for i in range(len(shapes) - GRAM + 1)]


def _ratio(a, b):
    if not a or not b or len(a) > 2 * len(b) or len(b) > 2 * len(a):
        return 0.0
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.real_quick_ratio() < 0.6 or sm.quick_ratio() < 0.6:
        return 0.0
    return sm.ratio()


def _bag(a, b):
    """order-free similarity of instruction pairs: survives moved basic blocks"""
    if not a or not b or len(a) > 2 * len(b) or len(b) > 2 * len(a):
        return 0.0
    ca, cb = Counter(zip(a, a[1:])), Counter(zip(b, b[1:]))
    n = sum(ca.values()) + sum(cb.values())
    return 2 * sum((ca & cb).values()) / n if n else 0.0


def _overlap(ca, cb):
    n = sum(ca.values()) + sum(cb.values())
    return 2 * sum((ca & cb).values()) / n if n else 0.0


def similarity(ta, sa, tb, sb, ca=None, cb=None):
    """0..1; ca/cb: Counters of the shapes, an upper bound that skips hopeless pairs cheaply"""
    if ca is not None and _overlap(ca, cb) < ACCEPT_CALLEES:
        return 0.0
    r = _ratio(ta, tb)
    if r >= 0.9:
        return r
    return max(r, 0.95 * _ratio(sa, sb), 0.9 * _bag(ta, tb))


def candidates(regions, relocs=None):
    """addresses inside the code that something calls or points at"""
    out = set()
    for base, buf in regions:
        end = base + len(buf)
        for op in (b"\xe8", b"\xe9"):      # calls and tail jumps
            p = buf.find(op)
            while 0 <= p <= len(buf) - 5:
                t = (base + p + 5 + struct.unpack_from("<i", buf, p + 1)[0]) & 0xffffffff
                if base <= t < end:
                    out.add(t)
                p = buf.find(op, p + 1)
    for t in (relocs or ()):
        if any(base <= t < base + len(buf) for base, buf in regions):
            out.add(t)
    return out


def match(regions, sigs, found, clean_name, function_end, relocs=None, prefer=None):
    """add fuzzy matches to found {address: (name, conf, how)} (exact matches); returns the new ones"""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    model = Model(sigs, md)
    code_of = {id(it[0]): tuple(it[1]) for it in model.items}
    cands = candidates(regions, relocs)
    # an exact match ends where the next function starts (after alignment padding)
    for a in found:
        for base, buf in regions:
            if base <= a < base + len(buf):
                e = function_end(buf, a - base, min(len(buf), a - base + MAX_FUNC), md)
                while e < len(buf) and buf[e] in (0x00, 0x90, 0xcc):
                    e += 1
                if e < len(buf):
                    cands.add(base + e)
    cands = sorted(cands - set(found))
    # extents end at the next exact match at the latest (candidates can lie inside functions)
    known = sorted(found)
    import bisect
    taken_names = {v[0] for v in found.values()}
    funcs = {}
    for a in cands:
        for base, buf in regions:
            if base <= a < base + len(buf):
                lo = a - base
                i = bisect.bisect_right(known, a)
                stop = known[i] - base if i < len(known) and known[i] < base + len(buf) else len(buf)
                hi = min(len(buf), lo + MAX_FUNC, stop)
                end = function_end(buf, lo, hi, md)
                toks, shapes, calls = normalise(md, buf, lo, end)
                # addresses: normalise() saw offsets relative to the region; make them absolute
                calls = [c + base for c in calls]
                if len(toks) >= MIN_INSNS // 2:
                    funcs[a] = (toks, shapes, calls)
                break

    def callee_score(calls, names, have, own_name):
        """named callees of the candidate that the signature also calls (ok) or does not (bad);
        compared as sets - another version adds, drops and reorders calls"""
        sig_names = {clean_name(c) for c in names}
        ok = bad = 0
        for t in set(calls):
            h = have.get(t)
            if h is None:
                continue
            if h[0] == own_name:
                bad += 1        # calls what it would be named: a wrapper of it, not it
            elif h[0] in sig_names:
                ok += 1
            else:
                bad += 1
        return ok, bad

    new = {}
    for _ in range(3):
        have = dict(found)
        have.update(new)
        proposals = []
        for a, (toks, shapes, calls) in funcs.items():
            if a in new:
                continue
            votes = Counter()
            bag = Counter(shapes)
            for g in set(_grams(shapes)):
                if g in model.common:
                    continue
                for i in model.index.get(g, ()):
                    votes[i] += 1
            best = {}
            for i, _ in votes.most_common(TOP):
                s, st, ss, names = model.items[i]
                r = similarity(toks, shapes, st, ss, bag, model.bags[i])
                if r < ACCEPT_CALLEES:
                    continue
                ok, bad = callee_score(calls, names, have, clean_name(s.name))
                score = r + 0.03 * ok - 0.1 * bad
                nm = clean_name(s.name)
                if nm not in best or score > best[nm][0]:
                    best[nm] = (score, r, ok, bad, s)
            if not best:
                continue
            ranked = sorted(best.values(), key=lambda x: -x[0])
            # signatures with the same code as the best one (atoi/atol) are one choice, not rivals
            same = [x for x in ranked if code_of[id(x[4])] == code_of[id(ranked[0][4])]]
            if prefer:
                # a near tie between a documented C function and a variant of it (tolower /
                # towlower, strdup / _mbsdup) goes to the documented one
                near = [x for x in ranked if x not in same and ranked[0][0] - x[0] < NEAR]
                if near and any(not prefer(clean_name(x[4].name))[0] for x in same + near):
                    same = same + near
                same.sort(key=lambda x: (prefer(clean_name(x[4].name)), -x[0]))
            rivals = [x for x in ranked if x not in same]
            score, r, ok, bad, s = same[0]
            second = rivals[0][0] if rivals else 0.0
            if bad > ok or score - second < MARGIN:
                continue
            if len(toks) < MIN_INSNS and not ok:
                continue
            if len(toks) < WRAPPER and s.callees and not ok:
                continue    # a short function that calls others: its callees tell it apart, not its code
            if r < ACCEPT and not ok:
                continue
            proposals.append((score, a, clean_name(s.name), r, ok, s))
        # one address per name: the best-scoring proposal wins
        added = False
        for score, a, nm, r, ok, s in sorted(proposals, key=lambda p: -p[0]):
            if nm in taken_names:
                continue
            taken_names.add(nm)
            new[a] = (nm, "G", "fuzzy %.2f%s %s/%s" % (r, " +%d callees" % ok if ok else "", s.lib, s.module))
            added = True
        if not added:
            break
    found.update(new)
    return new
