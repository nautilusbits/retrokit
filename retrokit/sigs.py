"""Library function signatures: build them from a library, find them in an executable.

A signature is the code of one library function as the linker placed it, with every byte a
loader or linker may change replaced by a wildcard: fixup fields and rel32 operands of calls
and jumps that leave the function. Calls to other library functions are kept as callee names,
which confirm short or ambiguous matches and name the callees too.

Build (OMF libraries, linked with wlink so the bytes are exactly what a program gets):

    retrokit sigs build --watcom DIR --lib clib3r.lib [--lib math3r.lib] -o clib3r.sig

Match (no Ghidra needed; LE/LX and PE):

    retrokit sigs match GAME.EXE [--sigs FILE|DIR ...] [-o names_sigs.csv]

File format (text, one function per line, tab separated):

    # retrokit-sigs 1
    # label: ...
    name    module    pattern (hex, '..' = wildcard)    callees (offset=name,...)
"""
import glob
import gzip
import os
import re
import struct
import subprocess
import tempfile
from collections import defaultdict

from . import formats
from . import paths

MAGIC = "# retrokit-sigs 1"
MIN_FIXED = 6        # fewer fixed bytes than this: no signature at all
STRONG = 16          # fixed bytes for a match that stands on its own
KEY = 4              # bytes of the index key (a run of fixed bytes)
SHIPPED = paths.SIGS


class Sig:
    __slots__ = ("name", "module", "pattern", "callees", "fixed", "_rx", "key", "key_at", "lib")

    def __init__(self, name, module, pattern, callees, lib=""):
        self.name, self.module, self.pattern, self.callees, self.lib = name, module, pattern, callees, lib
        self.fixed = sum(1 for b in pattern if b is not None)
        self._rx = None
        self.key, self.key_at = _key(pattern)

    @property
    def rx(self):
        """the pattern as a regular expression, compiled when first needed"""
        if self._rx is None:
            self._rx = re.compile(b"".join(_ESC[256 if b is None else b] for b in self.pattern), re.S)
        return self._rx

    def size(self):
        return len(self.pattern)

    def line(self):
        hexp = "".join(".." if b is None else "%02x" % b for b in self.pattern)
        return "\t".join([self.name, self.module, hexp, ",".join("%x=%s" % c for c in self.callees)])


_ESC = [re.escape(bytes([b])) for b in range(256)] + [b"."]


def _key(pattern):
    run = 0
    for i, b in enumerate(pattern):
        run = run + 1 if b is not None else 0
        if run == KEY:
            return bytes(pattern[i - KEY + 1:i + 1]), i - KEY + 1
    return None, None


# ---------------------------------------------------------------------------------------- files

def read(path):
    """[Sig] from one .sig file"""
    out, lib = [], re.sub(r"\.sig(\.gz)?$", "", os.path.basename(path))
    with _open(path, "rt") as fh:
        first = fh.readline().rstrip("\n")
        if first != MAGIC:
            raise ValueError("%s: not a retrokit signature file" % path)
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            name, module, hexp, callees = (line.rstrip("\n").split("\t") + ["", ""])[:4]
            pattern = [None if hexp[i:i + 2] == ".." else int(hexp[i:i + 2], 16) for i in range(0, len(hexp), 2)]
            cl = []
            for c in filter(None, callees.split(",")):
                off, _, cname = c.partition("=")
                cl.append((int(off, 16), cname))
            out.append(Sig(name, module, pattern, cl, lib))
    return out


def _open(path, mode):
    if path.endswith(".gz"):
        return gzip.open(path, mode, encoding="utf-8", newline="\n")
    return open(path, mode, encoding="utf-8", newline="\n")


def write(path, sigs, header=()):
    """write a .sig file (.sig.gz: compressed)"""
    with _open(path, "wt") as fh:
        fh.write(MAGIC + "\n")
        for h in header:
            fh.write("# %s\n" % h)
        for s in sorted(sigs, key=lambda s: s.name):
            fh.write(s.line() + "\n")


def sig_files(spec=None):
    """signature files: the given files/directories, else the shipped ones + ~/.retrokit/sigs"""
    if not spec:
        spec = [SHIPPED, os.path.join(os.path.expanduser("~"), ".retrokit", "sigs")]
    out = []
    for p in spec:
        if os.path.isdir(p):
            out += sorted(glob.glob(os.path.join(p, "*.sig")) + glob.glob(os.path.join(p, "*.sig.gz")))
        elif os.path.isfile(p):
            out.append(p)
        elif p not in (SHIPPED,) and not p.endswith(os.path.join(".retrokit", "sigs")):
            raise FileNotFoundError("signature file or directory not found: %s" % p)
    return out


# ---------------------------------------------------------------------------------------- build

def lib_modules(wlib, lib):
    """{module: [public symbols]} from 'wlib -l'"""
    with tempfile.TemporaryDirectory() as tmp:
        lst = os.path.join(tmp, "lib.lst")
        # -m: C++ names mangled, as 'reference' and the map need them
        subprocess.run([wlib, "-q", "-m", "-l=" + lst, lib], check=True, capture_output=True)
        mods, cur = {}, None
        for line in open(lst, errors="replace"):
            line = line.rstrip("\r\n")
            m = re.match(r"^(\S.*?) Offset=[0-9a-fA-F]+H$", line)
            if m:
                cur = mods.setdefault(m.group(1), [])
            elif line.startswith("    ") and cur is not None and line.strip():
                cur.append(line.strip())
        return mods


def parse_map(path):
    """[(segment, offset, name, module)] from a wlink map (segmented addresses)"""
    syms, module = [], ""
    rx = re.compile(r"^([0-9a-f]{4}):([0-9a-f]{8})[+* ]\s+(\S+)")
    in_map = False
    for line in open(path, errors="replace"):
        if line.startswith("Module:"):
            module, in_map = line[7:].strip(), True
            continue
        m = rx.match(line) if in_map else None
        if m:
            syms.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), module))
    return syms


def _host_bin(watcom):
    for c in ("binnt64", "binnt", "binl64", "binl"):
        d = os.path.join(watcom, c)
        if os.path.exists(os.path.join(d, "wlink.exe")) or os.path.exists(os.path.join(d, "wlink")):
            return d
    raise SystemExit("no wlink under %s" % watcom)


def link_reference(watcom, libs, workdir, system="dos4g"):
    """link every public of the libraries into one executable; returns (exe, map)"""
    hb = _host_bin(watcom)
    exe_sfx = ".exe" if os.path.exists(os.path.join(hb, "wlink.exe")) else ""
    wlib, wlink = os.path.join(hb, "wlib" + exe_sfx), os.path.join(hb, "wlink" + exe_sfx)
    publics = []
    for lib in libs:
        for syms in lib_modules(wlib, lib).values():
            publics += syms
    # an empty module to link: wlink needs at least one object file
    obj = os.path.join(workdir, "ref.obj")
    _write_empty_omf(obj)
    exe, mp = os.path.join(workdir, "ref.exe"), os.path.join(workdir, "ref.map")
    lnk = os.path.join(workdir, "ref.lnk")
    with open(lnk, "w") as fh:
        fh.write("system %s\nname '%s'\noption map='%s', mangledn, undefsok, quiet\nfile '%s'\n" % (system, exe, mp, obj))
        for lib in libs:
            fh.write("library '%s'\n" % lib)
        for p in publics:
            fh.write("reference '%s'\n" % p)
    env = dict(os.environ, WATCOM=watcom)
    env["PATH"] = hb + os.pathsep + env.get("PATH", "")
    r = subprocess.run([wlink, "@" + lnk], env=env, capture_output=True, text=True)
    if not os.path.exists(mp) or not os.path.exists(exe):
        raise SystemExit("wlink failed:\n" + r.stdout + r.stderr)
    return exe, mp


def _omf(rtype, body):
    rec = bytes([rtype]) + struct.pack("<H", len(body) + 1) + body
    return rec + bytes([(-sum(rec)) & 0xff])


def _write_empty_omf(path):
    name = b"ref"
    with open(path, "wb") as fh:
        fh.write(_omf(0x80, bytes([len(name)]) + name))   # THEADR
        fh.write(_omf(0x8a, b"\0"))                        # MODEND


def _function_end(code, start, limit, md):
    """end of the function at code[start:] (exclusive): linear disassembly until a ret/jmp that no
    earlier branch jumps past, capped at limit"""
    reach = start
    for ins in md.disasm(code[start:limit], start):
        end = ins.address + ins.size
        m = ins.mnemonic
        if m.startswith("j") or m == "loop" or m.startswith("loop"):
            if ins.op_str.startswith("0x"):
                t = int(ins.op_str, 16)
                if start <= t < limit:
                    reach = max(reach, t)
        if m in ("ret", "retf", "iretd", "iret") or (m == "jmp" and not ins.op_str.startswith("0x")) or \
                (m == "jmp" and ins.op_str.startswith("0x") and not (start <= int(ins.op_str, 16) < end)):
            if reach < end:
                return end
        if m == "int3" or (m == "hlt"):
            if reach < end:
                return end
    return limit


def extract(exe, mapfile):
    """[Sig] for every code symbol of a reference executable (LE) and its map"""
    le = formats.LinearExecutable(exe)
    bases = le.bases()
    by_addr = {}
    for seg, off, name, module in parse_map(mapfile):
        if seg in bases and le.objects[seg - 1][2] & 0x4:
            by_addr.setdefault(bases[seg] + off, (name, re.sub(r"^.*\((.*)\)$", r"\1", module), seg))
    blocks, masked = le_blocks(le)
    return image_sigs(blocks, masked, by_addr)


def le_blocks(le):
    """({object number: (base, bytes)} of the executable objects, fixup bytes)"""
    objs, relocs, _ = le.loaded()
    bases = le.bases()
    masked = set()
    for a, (src, _, _) in relocs.items():
        masked.update(range(a, a + le.SOURCE_SIZE.get(src, 4)))
    return {n: (bases[n], b) for n, b in objs.items() if le.objects[n - 1][2] & 0x4}, masked


def pe_blocks(data):
    """({section index: (address, bytes)} of the executable sections of a PE, bytes of its base
    relocations - the addresses a loader may change)"""
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    nsec, opt = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    image_base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    reloc_rva, reloc_size = struct.unpack_from("<II", data, pe + 24 + 96 + 5 * 8)
    secs, blocks = [], {}
    for i in range(nsec):
        s = pe + 24 + opt + i * 40
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        flags = struct.unpack_from("<I", data, s + 36)[0]
        secs.append((va, max(vsize, rsize), raw))
        if flags & 0x20000020:
            blocks[i + 1] = (image_base + va, data[raw:raw + min(rsize, vsize or rsize)])

    def off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return raw + rva - va
        return None
    masked = set()
    p, end = off(reloc_rva) if reloc_rva else None, None
    if p is not None:
        end = p + reloc_size
        while p + 8 <= end:
            page, size = struct.unpack_from("<II", data, p)
            if size < 8:
                break
            for k in range(8, size, 2):
                e = struct.unpack_from("<H", data, p + k)[0]
                if e >> 12 == 3:                       # IMAGE_REL_BASED_HIGHLOW
                    a = image_base + page + (e & 0xfff)
                    masked.update(range(a, a + 4))
            p += size
    return blocks, masked


def learn(exe, functions_csv, keep=None, module=""):
    """[Sig] from an analysed LE: the functions of a functions.csv (addr,name,...) whose names are not
    Ghidra defaults - or only those in keep (a set of addresses)"""
    import csv
    with open(exe, "rb") as fh:
        data = fh.read()
    if formats.find_le(data) is not None:
        blocks, masked = le_blocks(formats.LinearExecutable(data=data))
    else:
        blocks, masked = pe_blocks(data)

    def seg_of(a):
        for n, (base, b) in blocks.items():
            if base <= a < base + len(b):
                return n
    by_addr = {}
    with open(functions_csv, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            a = int(r["addr"].split(":")[-1], 16)
            seg = seg_of(a)
            if seg:
                by_addr[a] = (r["name"], module, seg)
    named = {a for a, (n, _, _) in by_addr.items() if not DEFAULT_NAME.match(n)}
    return image_sigs(blocks, masked, by_addr, keep if keep is not None else named)


DEFAULT_NAME = re.compile(r"(FUN|thunk_FUN|LAB|SUB)_[0-9a-fA-F]+$")


def image_sigs(blocks, masked, by_addr, keep=None):
    """signatures of the functions by_addr {address: (name, module, block)} lists (each ends at
    the next one at the latest) in blocks {block: (address, bytes)}, the bytes in masked being
    wildcards; keep limits which become signatures"""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    starts = sorted(by_addr)
    out = []
    for i, a in enumerate(starts):
        name, module, seg = by_addr[a]
        if keep is not None and a not in keep:
            continue
        base, code = blocks[seg]
        nxt = starts[i + 1] if i + 1 < len(starts) and by_addr[starts[i + 1]][2] == seg else base + len(code)
        lo, hi = a - base, nxt - base
        end = _function_end(code, lo, hi, md)
        pat = [None if base + k in masked else code[k] for k in range(lo, end)]
        callees = []
        for ins in md.disasm(code[lo:end], a):
            b0 = ins.bytes[0]
            if (b0 in (0xe8, 0xe9) and ins.size == 5) or (b0 == 0x0f and ins.size == 6 and 0x80 <= ins.bytes[1] <= 0x8f):
                t = int(ins.op_str, 16)
                if not (a <= t < base + end):
                    for k in range(ins.address + ins.size - 4, ins.address + ins.size):
                        pat[k - a] = None
                    if t in by_addr and not DEFAULT_NAME.match(by_addr[t][0]):
                        callees.append((ins.address - a, by_addr[t][0]))
        s = Sig(name, module, pat, callees)
        if s.fixed >= MIN_FIXED and s.key is not None:
            out.append(s)
    return out


# ---------------------------------------------------------------------------------------- match

def code_regions(path):
    """[(base, bytes)] of the executable code of an LE/LX or PE file, as Ghidra maps it"""
    data = open(path, "rb").read()
    if formats.find_le(data) is not None:
        le = formats.LinearExecutable(data=data)
        objs, _, _ = le.loaded()
        bases = le.bases()
        return [(bases[n], b) for n, b in objs.items() if le.objects[n - 1][2] & 0x4 and b]
    if data[:2] == b"MZ" and len(data) > 0x40:
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        if data[pe:pe + 4] == b"PE\0\0":
            nsec, opt = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
            image_base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
            out = []
            for i in range(nsec):
                s = pe + 24 + opt + i * 40
                vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
                if struct.unpack_from("<I", data, s + 36)[0] & 0x20000020:
                    out.append((image_base + va, data[raw:raw + min(rsize, vsize or rsize)]))
            return out
    raise formats.FormatError("%s: neither LE/LX nor PE" % path)


def code_pointers(path):
    """addresses in the code that pointers point at: LE/LX internal 32-bit fixup targets, PE
    dwords anywhere in the image that fall into an executable section"""
    data = open(path, "rb").read()
    regions = code_regions(path)

    def in_code(t):
        return any(base <= t < base + len(buf) for base, buf in regions)
    out = set()
    if formats.find_le(data) is not None:
        le = formats.LinearExecutable(data=data)
        _, relocs, _ = le.loaded()
        for src, status, v in relocs.values():
            if src == 7 and status == "APPLIED" and in_code(v):
                out.add(v)
        return out
    for p in range(0, len(data) - 3, 4):
        v = struct.unpack_from("<I", data, p)[0]
        if in_code(v):
            out.add(v)
    return out


_CPP_OPS = {"CT": "ctor", "DT": "dtor", "nw": "operator_new", "dl": "operator_delete",
            "na": "operator_new_array", "da": "operator_delete_array", "aa": "operator_assign"}


def cpp_name(mangled):
    """identifier for a Watcom C++ symbol: W?$CT:_EXC_PR$N(...)_ -> _EXC_PR_ctor,
    W?$nwn(ui)pnv -> operator_new, W?flush$:ostream$n()... -> ostream_flush"""
    m = re.match(r"W\?(\$[A-Za-z]{2}|[A-Za-z_]\w*)((?:\$?:[A-Za-z_]\w*)*)", mangled)
    if not m:
        return re.sub(r"\W", "_", mangled)
    name, scopes = m.group(1), re.findall(r":([A-Za-z_]\w*)", m.group(2))
    if name.startswith("$"):
        name = _CPP_OPS.get(name[1:], "operator_" + name[1:])
    return "_".join(scopes[::-1] + [name])


def clean_name(name):
    """C name of a Watcom symbol: register-convention 'strlen_' -> 'strlen', C++ names as
    identifiers (cpp_name)"""
    if name.startswith("W?"):
        return cpp_name(name)
    return name[:-1] if name.endswith("_") and len(name) > 1 and not name.endswith("__") else name


_KNOWN = None


def known_names():
    """function names declared in the knowledge headers (retrokit/knowledge/*.h)"""
    global _KNOWN
    if _KNOWN is None:
        _KNOWN = set()
        for h in glob.glob(os.path.join(paths.KNOWLEDGE, "*.h")):
            with open(h, encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r"^[A-Za-z_].*?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*;\s*$", line)
                    if m and not line.startswith("typedef"):
                        _KNOWN.add(m.group(1))
    return _KNOWN


def _preference(name):
    """among functions with identical code, prefer a documented, standard name: strtol over
    strtoimax, strcat over _mbscat"""
    return name not in known_names(), len(name) - len(name.lstrip("_")), name


def _rel32_target(buf, base, at):
    return (base + at + 4 + struct.unpack_from("<i", buf, at)[0]) & 0xffffffff


def _call_targets(regions):
    """addresses that some E8 rel32 in the code calls (byte scan: a few false ones do not matter)"""
    out = set()
    for base, buf in regions:
        end = base + len(buf)
        p = buf.find(b"\xe8")
        while 0 <= p <= len(buf) - 5:
            t = _rel32_target(buf, base, p + 1)
            if base <= t < end:
                out.add(t)
            p = buf.find(b"\xe8", p + 1)
    return out


def match(regions, sigs):
    """{address: (name, confidence 'V'/'G', how)} for library functions found in the code regions.

    Accepted, longest signatures first and repeated until nothing changes:
      - one name fits, >= STRONG fixed bytes and no callee contradicts it               -> V
      - one name fits, fewer bytes, but a callee or a caller confirms it                 -> V
      - one short name fits once, >= 10 fixed bytes, the address is called from code    -> G
      - several names fit (identical code): the one callees/callers confirm             -> V,
        else, if long enough, the first name with the others in the comment             -> G
      - call targets of accepted functions without any fitting signature get the callee
        name the signature recorded                                                      -> G
    """
    index = defaultdict(list)
    for s in sigs:
        index[s.key].append(s)
    cands = defaultdict(list)        # address -> [Sig]
    hits = defaultdict(int)          # Sig -> number of addresses it fits
    for base, buf in regions:
        n = len(buf)
        for p in range(n - KEY + 1):
            lst = index.get(buf[p:p + KEY])
            if not lst:
                continue
            for s in lst:
                at = p - s.key_at
                if at >= 0 and at + s.size() <= n and s.rx.match(buf, at):
                    cands[base + at].append(s)
                    hits[s] += 1
    called = _call_targets(regions)

    def where(addr):
        for base, buf in regions:
            if base <= addr < base + len(buf):
                return base, buf
        return None, None

    def callee_targets(addr, s):
        base, buf = where(addr)
        out = []
        for off, cname in s.callees:
            at = addr - base + off
            if buf[at] == 0x0f:
                at += 1
            out.append((_rel32_target(buf, base, at + 1), clean_name(cname)))
        return out

    def names_at(t):
        if t in found:
            return {found[t][0]}
        return {clean_name(o.name) for o in cands.get(t, ())}

    found, taken = {}, []
    wanted = defaultdict(set)        # address -> names accepted callers call it by

    def support(a, s):
        ok = bad = 0
        for t, cname in callee_targets(a, s):
            have = names_at(t)
            if cname in have:
                ok += 1
            elif t in found:
                bad += 1
        if clean_name(s.name) in wanted.get(a, ()):
            ok += 1
        return ok, bad

    def accept(a, s, conf, how):
        found[a] = (clean_name(s.name), conf, "%s %s/%s %dB" % (how, s.lib, s.module, s.fixed))
        taken.append((a, a + s.size()))
        for t, cname in callee_targets(a, s):
            wanted[t].add(cname)

    def inside(a):
        return any(lo < a < hi for lo, hi in taken)

    order = sorted(cands, key=lambda a: (-max(s.fixed for s in cands[a]), a))
    for _ in range(8):
        changed = False
        for a in order:
            if a in found or inside(a):
                continue
            best = max(s.fixed for s in cands[a])
            top = sorted((s for s in cands[a] if s.fixed == best), key=lambda s: _preference(clean_name(s.name)))
            scored = [(support(a, s), s) for s in top]
            scored = [x for x in scored if x[0][1] == 0] or scored     # drop contradicted ones
            if len({clean_name(s.name) for _, s in scored}) == 1:
                (ok, bad), s = scored[0]
                if bad:
                    continue
                if best >= STRONG:
                    accept(a, s, "V", "sig")
                elif ok:
                    accept(a, s, "V", "sig+calls")
                elif best >= 10 and hits[s] == 1 and a in called:
                    accept(a, s, "G", "short sig")
                else:
                    continue
            else:
                # best score per name (the same function can come from several signature files)
                per_name = {}
                for (ok, bad), s in scored:
                    nm = clean_name(s.name)
                    if nm not in per_name or ok - bad > per_name[nm][0]:
                        per_name[nm] = (ok - bad, ok, s)
                ranked = sorted(per_name.values(), key=lambda x: x[0], reverse=True)
                _, ok, s = ranked[0]
                if ok and ranked[0][0] > ranked[1][0]:
                    accept(a, s, "V", "sig+calls")
                elif best >= STRONG and not any(ok for (ok, _), _ in scored) and \
                        len({tuple(c for _, c in o.callees) for _, o in scored}) == 1:
                    # truly identical (same callees too), e.g. atoi/atol where int == long
                    others = sorted({clean_name(o.name) for _, o in scored} - {clean_name(s.name)})
                    accept(a, s, "G", "identical to %s;" % "/".join(others))
                else:
                    continue
            changed = True
        # call targets of accepted functions where no signature fits
        for t, names in list(wanted.items()):
            if t not in found and t not in cands and len(names) == 1 and where(t)[0] is not None:
                found[t] = (next(iter(names)), "G", "called as such by a library function")
                changed = True
        if not changed:
            break
    return found


def relevant_files(exe, files):
    """the signature files worth trying on exe: a file that belongs to a catalogued library
    (knowledge/libraries.json 'signatures') only when `retrokit libs` finds that library -
    signatures of absent libraries only add rivals to the fuzzy tier; other files always"""
    import fnmatch
    from . import libs
    cat = [l for l in libs.catalog() if l.get("signatures")]
    present = {f["id"] for f in libs.detect(exe)}
    out = []
    for f in files:
        base = os.path.basename(f)
        owners = [l["id"] for l in cat if fnmatch.fnmatch(base, l["signatures"])]
        if not owners or any(o in present for o in owners):
            out.append(f)
    return out


def match_file(exe, sig_paths=None, fuzzy=True):
    """match the signature files (sig_files() resolves None to the defaults) in an executable:
    exact matches, then (fuzzy=True) similar code for the rest - see fuzzy.py"""
    files = sig_files(sig_paths)
    if not sig_paths:
        files = relevant_files(exe, files)
    sigs = []
    for p in files:
        sigs += read(p)
    if not sigs:
        return {}, 0
    regions = code_regions(exe)
    found = match(regions, sigs)
    if fuzzy:
        from . import fuzzy as fz
        fz.match(regions, sigs, found, clean_name, _function_end, code_pointers(exe), _preference)
    return found, len(sigs)


def write_names(path, found):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("addr,name,confidence,comment\n")
        for a in sorted(found):
            name, conf, how = found[a]
            fh.write("%08x,%s,%s,%s\n" % (a, name, conf, how.replace(",", ";")))


def build(watcom, libs, out, label=None, system="dos4g"):
    """link the libraries, extract their signatures into the file out; returns the count"""
    with tempfile.TemporaryDirectory() as tmp:
        exe, mp = link_reference(watcom, [os.path.abspath(l) for l in libs], tmp, system)
        found = extract(exe, mp)
    write(out, found, ["label: %s" % (label or ", ".join(os.path.basename(l) for l in libs)),
                       "built by retrokit sigs build (wlink system %s)" % system])
    return len(found)
