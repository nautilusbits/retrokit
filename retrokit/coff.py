"""Signatures from Microsoft COFF libraries (.lib archives of COFF objects - the MSVC run-time
LIBC.LIB / LIBCMT.LIB of a Visual C++ you own, or any static library built with MSVC).

    retrokit sigs build --coff --lib LIBC.LIB [--lib ...] -o msvc6-libc.sig

No linking: every function is cut from its object's code section, the bytes covered by
relocations become wildcards, and calls to external symbols become callee names. Decorated
C names are undecorated (_strlen -> strlen, _Sleep@4 -> Sleep, @fn@8 -> fn); C++ names are kept
only for operator new/delete.
"""
import re
import struct

from . import sigs

MASK = {0x0006: 4, 0x0007: 4, 0x000b: 4, 0x000c: 4, 0x0014: 4,      # DIR32, DIR32NB, SECREL, TOKEN, REL32
        0x0001: 2, 0x0002: 2, 0x000a: 2, 0x000d: 1}                  # DIR16, REL16, SECTION, SECREL7
CPP = {"??2@YAPAXI@Z": "operator_new", "??3@YAXPAX@Z": "operator_delete",
       "??_U@YAPAXI@Z": "operator_new_array", "??_V@YAXPAX@Z": "operator_delete_array"}


def msvc_name(sym):
    """C name of an MSVC symbol, or None for names that are not functions we can name"""
    if sym in CPP:
        return CPP[sym]
    if sym.startswith("?") or sym.startswith("__imp_") or sym.startswith("$"):
        return None
    m = re.match(r"^[_@]?([A-Za-z_]\w*?)(@\d+)?$", sym)
    if not m:
        return None
    return m.group(1) if sym[0] in "_@" else sym


def members(data):
    """[(name, bytes)] of the object members of an 'ar' archive (MSVC .lib)"""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not a COFF library (no !<arch> signature)")
    out, longnames, p = [], b"", 8
    while p + 60 <= len(data):
        hdr = data[p:p + 60]
        name = hdr[:16].rstrip()
        size = int(hdr[48:58].strip() or 0)
        body = data[p + 60:p + 60 + size]
        if name == b"//":
            longnames = body
        elif name not in (b"/", b""):
            if name.startswith(b"/") and name[1:].isdigit():
                o = int(name[1:])
                e = longnames.find(b"\0", o)
                name = longnames[o:e if e >= 0 else len(longnames)].rstrip(b"\n")
            out.append((name.rstrip(b"/").decode("latin-1"), body))
        p += 60 + size + (size & 1)
    return out


def object_sigs(obj, module=""):
    """[Sig] of the functions in one i386 COFF object"""
    if len(obj) < 20:
        return []
    machine, nsec, _, symptr, nsym, optsize, _ = struct.unpack_from("<HHIIIHH", obj, 0)
    if machine != 0x14c or not symptr:
        return []                                 # import descriptors, other machines
    strtab = symptr + 18 * nsym

    def symname(raw):
        if raw[:4] == b"\0\0\0\0":
            o = strtab + struct.unpack_from("<I", raw, 4)[0]
            e = obj.find(b"\0", o)
            return obj[o:e].decode("latin-1")
        return raw.rstrip(b"\0").decode("latin-1")
    syms, i = [], 0
    while i < nsym:
        o = symptr + 18 * i
        raw = obj[o:o + 8]
        value, sec, typ, cls, naux = struct.unpack_from("<IhHBB", obj, o + 8)
        syms.append((symname(raw), value, sec, typ, cls))
        syms.extend([None] * naux)
        i += 1 + naux
    sections = []
    for k in range(nsec):
        s = 20 + optsize + 40 * k
        rsize, rptr, relptr = struct.unpack_from("<III", obj, s + 16)
        nrel = struct.unpack_from("<H", obj, s + 32)[0]
        flags = struct.unpack_from("<I", obj, s + 36)[0]
        sections.append((obj[rptr:rptr + rsize] if rptr else b"", relptr, nrel, flags))
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    out = []
    for k, (code, relptr, nrel, flags) in enumerate(sections):
        if not flags & 0x20 or not code:        # IMAGE_SCN_CNT_CODE
            continue
        pat = list(code)
        calls = {}
        for r in range(nrel):
            va, si, typ = struct.unpack_from("<IIH", obj, relptr + 10 * r)
            for b in range(va, min(va + MASK.get(typ, 4), len(pat))):
                pat[b] = None
            target = syms[si] if si < len(syms) else None
            if typ == 0x0014 and target and target[4] == 2:     # REL32 to an external symbol
                if va >= 1 and code[va - 1] in (0xe8, 0xe9):
                    calls[va - 1] = target[0]
                elif va >= 2 and code[va - 2] == 0x0f and 0x80 <= code[va - 1] <= 0x8f:
                    calls[va - 2] = target[0]
        # functions: symbols defined in this section (statics too, they end the one before)
        starts = sorted({(s[1], s[0], s[4]) for s in syms if s and s[2] == k + 1 and s[4] in (2, 3) and
                         (s[3] & 0x20 or s[4] == 2) and not s[0].startswith(".")})
        for j, (value, name, cls) in enumerate(starts):
            if cls != 2:
                continue
            cname = msvc_name(name)
            if cname is None:
                continue
            nxt = starts[j + 1][0] if j + 1 < len(starts) else len(code)
            end = sigs._function_end(code, value, nxt, md)
            callees = [(o - value, msvc_name(t) or t) for o, t in sorted(calls.items()) if value <= o < end]
            s = sigs.Sig(cname, module, pat[value:end], callees)
            if s.fixed >= sigs.MIN_FIXED and s.key is not None:
                out.append(s)
    return out


def lib_sigs(path):
    with open(path, "rb") as fh:
        data = fh.read()
    out = []
    for name, body in members(data):
        out += object_sigs(body, name.replace("\\", "/").split("/")[-1])
    return out
