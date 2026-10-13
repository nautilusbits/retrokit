"""Executable formats: identification and a small LE/LX reader (no Ghidra needed).

identify(path) tells which pipeline applies (LE/LX, PE, NE, plain MZ), finds the
LE header also behind a DOS/4G "BW" bind chain and names the DOS extender stub,
the compiler and, for PE, the imported DLLs. LinearExecutable maps the linear
addresses Ghidra shows (object base + offset) to file bytes.
"""
import re
import struct

# most specific first: DOS/32A and others also carry "DOS/4G" strings for compatibility
EXTENDERS = [
    (rb"DOS/32A", "DOS/32A"),
    (rb"PMODE/W", "PMODE/W"),
    (rb"CauseWay", "CauseWay"),
    (rb"WDOSX", "WDOSX"),
    (rb"Phar Lap", "Phar Lap"),
    (rb"DOS/4G", "DOS/4GW"),
]
COMPILERS = [
    (rb"WATCOM C/C\+\+32 Run-Time|Open Watcom C/C\+\+32 Run-Time|WATCOM C32 Run-Time", "Watcom C/C++"),
    (rb"Borland C\+\+|Borland C/C\+\+", "Borland C++"),
    (rb"Microsoft Visual C\+\+ Runtime|Microsoft Visual C\+\+", "Microsoft Visual C++"),
    (rb"DJGPP", "DJGPP"),
    (rb"Embarcadero|Borland Delphi|Portions Copyright \(c\) 1983,\d+ Borland", "Delphi"),
]
# PE MajorLinkerVersion.MinorLinkerVersion -> usual Microsoft toolchain
MS_LINKERS = {(5, 0): "VC++ 5", (5, 10): "VC++ 5 (SP)", (6, 0): "VC++ 6", (7, 0): "VS .NET 2002",
              (7, 10): "VS .NET 2003", (8, 0): "VS 2005", (9, 0): "VS 2008", (10, 0): "VS 2010"}


class FormatError(Exception):
    pass


def _u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def _is_le(d, o):
    return (0 <= o < len(d) - 8 and d[o:o + 2] in (b"LE", b"LX") and d[o + 2] == 0 and d[o + 3] == 0
            and _u32(d, o + 4) == 0)


def find_le(d):
    """(le_offset, mz_base) or None. mz_base is the MZ header the LE belongs to: 0 for a plain
    stub + LE file, the secondary MZ for DOS/4G "BW"-bound EXEs; LE offsets such as the data
    pages offset are relative to it."""
    if d[:2] == b"MZ" and len(d) >= 0x40:
        lfanew = _u32(d, 0x3c)
        if _u16(d, 0x18) >= 0x40 and _is_le(d, lfanew):
            return lfanew, 0
        o = (_u16(d, 4) - 1) * 512 + _u16(d, 2) if _u16(d, 2) else _u16(d, 4) * 512
        seen = set()
        while d[o:o + 2] == b"BW" and o not in seen:      # DOS/4G bind chain
            seen.add(o)
            nxt = _u32(d, o + 0x1c)
            if nxt <= o:
                break
            o = nxt
        if d[o:o + 2] == b"MZ" and len(d) >= o + 0x40:
            le_off = o + _u32(d, o + 0x3c)
            if _is_le(d, le_off):
                return le_off, o
    elif _is_le(d, 0):
        return 0, 0
    i = d.find(b"LE\0\0")
    while i >= 0:
        if _is_le(d, i):
            return i, 0
        i = d.find(b"LE\0\0", i + 1)
    return None


class LinearExecutable:
    """LE/LX image: object table and bytes at Ghidra (linear) addresses."""

    def __init__(self, path=None, data=None):
        self.data = data if data is not None else open(path, "rb").read()
        found = find_le(self.data)
        if found is None:
            raise FormatError("no LE/LX header")
        self.offset, self.mz_base = found
        d, le = self.data, self.offset
        self.signature = d[le:le + 2].decode()
        self.page_size = _u32(d, le + 0x28)
        self.n_pages = _u32(d, le + 0x14)
        self.data_pages = self.mz_base + _u32(d, le + 0x80)
        self.page_shift = _u32(d, le + 0x2c) if self.signature == "LX" else 0
        obj_tab, n_obj, self.page_map = _u32(d, le + 0x40), _u32(d, le + 0x44), _u32(d, le + 0x48)
        self.objects = []   # (vsize, base, flags, first page index, page count)
        for i in range(n_obj):
            self.objects.append(struct.unpack_from("<IIIII", d, le + obj_tab + i * 24))
        self.eip_object, self.eip = _u32(d, le + 0x18), _u32(d, le + 0x1c)
        self._mem = None

    def object_bytes(self, i):
        vsize, base, flags, first, count = self.objects[i]
        d, out = self.data, bytearray()
        for p in range(count):
            e = self.offset + self.page_map + (first - 1 + p) * (4 if self.signature == "LE" else 8)
            if self.signature == "LE":
                pnum = d[e] << 16 | d[e + 1] << 8 | d[e + 2]
                foff = self.data_pages + (pnum - 1) * self.page_size
                size = self.page_size
            else:
                poff, size, _ = struct.unpack_from("<IHH", d, e)
                foff = self.data_pages + (poff << self.page_shift)
            out += d[foff:foff + size].ljust(self.page_size, b"\0")
        return bytes(out[:vsize].ljust(vsize, b"\0"))

    def code_object(self):
        """index of the first executable object"""
        return next(i for i, o in enumerate(self.objects) if o[2] & 0x4)

    def read(self, addr, n):
        if self._mem is None:
            self._mem = {o[1]: self.object_bytes(i) for i, o in enumerate(self.objects)}
        for base, b in self._mem.items():
            if base <= addr < base + len(b):
                return b[addr - base:addr - base + n]
        raise KeyError(hex(addr))


def _pe_imports(d, pe):
    """Imported DLL names of a 32-bit PE."""
    try:
        opt = pe + 24
        nsec, optsz = _u16(d, pe + 6), _u16(d, pe + 20)
        secs = [struct.unpack_from("<8sIIII", d, opt + optsz + 40 * i) for i in range(nsec)]

        def rva2off(rva):
            for name, vsize, va, rawsz, rawp in secs:
                if va <= rva < va + max(vsize, rawsz):
                    return rawp + rva - va
            return None
        imp_rva = _u32(d, opt + 96 + 8)
        o = rva2off(imp_rva) if imp_rva else None
        dlls = []
        while o is not None and o + 20 <= len(d):
            name_rva = _u32(d, o + 12)
            if not name_rva:
                break
            no = rva2off(name_rva)
            if no is None:
                break
            dlls.append(d[no:d.index(b"\0", no)].decode("latin-1"))
            o += 20
        return dlls
    except (struct.error, ValueError):
        return []


def identify(path):
    """dict: format (LE, LX, PE, NE, MZ, unknown), pipeline, details."""
    d = open(path, "rb").read()
    info = {"path": path, "size": len(d), "format": "unknown", "pipeline": None, "notes": []}
    for pat, name in EXTENDERS:
        if re.search(pat, d[:0x40000] if len(d) > 0x40000 else d):
            info["extender"] = name
            break
    for pat, name in COMPILERS:
        if re.search(pat, d):
            info["compiler"] = name
            break
    if d[:2] != b"MZ" and not _is_le(d, 0):
        return info
    lfanew = _u32(d, 0x3c) if len(d) >= 0x40 else 0
    sig = d[lfanew:lfanew + 4] if lfanew < len(d) - 4 else b""
    if sig == b"PE\0\0":
        machine = _u16(d, lfanew + 4)
        magic = _u16(d, lfanew + 24)
        info.update(format="PE", pipeline="pe" if machine == 0x14c else None,
                    machine={0x14c: "i386", 0x8664: "x64"}.get(machine, hex(machine)),
                    pe32plus=magic == 0x20b, dlls=_pe_imports(d, lfanew))
        if machine != 0x14c:
            info["notes"].append("only 32-bit x86 PE is supported")
        lv = (d[lfanew + 26], d[lfanew + 27])
        info["linker"] = "%d.%02d" % lv
        if b"Rich" in d[0x80:lfanew]:
            info["toolchain"] = MS_LINKERS.get(lv, "Microsoft linker %d.%d" % lv)
            info.setdefault("compiler", "Microsoft Visual C++")
        return info
    if sig[:2] == b"NE":
        info.update(format="NE", notes=["16-bit Windows/OS2 NE: import with Ghidra directly, this kit is not needed"])
        return info
    found = find_le(d)
    if found:
        le = LinearExecutable(data=d)
        info.update(format=le.signature, pipeline="le", le_offset=le.offset, bound_bw=le.mz_base > 0,
                    objects=[{"base": o[1], "size": o[0], "flags": o[2]} for o in le.objects])
        info["loader"] = "LxLoader" if le.signature == "LX" else (
            "VxDLoader" if _u16(d, le.offset + 0x0a) == 4 else "LeLoader")   # e32_os 4 = Windows 386 (VxD)
        if le.mz_base:
            info["notes"].append("DOS/4G BW-bound: LE behind a bind chain, page offsets relative to MZ at 0x%x"
                                 % le.mz_base)
        return info
    info.update(format="MZ", notes=["16-bit real-mode DOS EXE: use Ghidra's x86:LE:16:Real Mode, this kit is not needed"])
    return info
