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
        self.last_page_size = _u32(d, le + 0x2c) if self.signature == "LE" else self.page_size
        obj_tab, n_obj, self.page_map = _u32(d, le + 0x40), _u32(d, le + 0x44), _u32(d, le + 0x48)
        self.objects = []   # (vsize, base, flags, first page index, page count)
        for i in range(n_obj):
            self.objects.append(struct.unpack_from("<IIIII", d, le + obj_tab + i * 24))
        self.eip_object, self.eip = _u32(d, le + 0x18), _u32(d, le + 0x1c)
        self._mem = None

    def pages(self):
        """[(file offset, stored size, type)] per page (index 0 = page 1). Types: 0 legal,
        1 iterated (LX), 2 invalid, 3 zero-filled, 4 range, 5 compressed."""
        d, out = self.data, []
        for i in range(self.n_pages):
            if self.signature == "LX":
                e = self.offset + self.page_map + i * 8
                poff, size, typ = struct.unpack_from("<IHH", d, e)
                out.append((self.data_pages + (poff << self.page_shift), size, typ))
            else:
                e = self.offset + self.page_map + i * 4
                pnum = d[e] << 16 | d[e + 1] << 8 | d[e + 2]    # 24-bit big-endian page number
                size = self.last_page_size if pnum == self.n_pages else self.page_size
                out.append((self.data_pages + (pnum - 1) * self.page_size, size, d[e + 3]))
        return out

    def object_bytes(self, i, pages=None):
        """object contents as stored in the file (no fixups applied), virtual size"""
        vsize, base, flags, first, count = self.objects[i]
        pages = pages or self.pages()
        out = bytearray(max(vsize, count * self.page_size))
        for k in range(count):
            idx = first + k
            if not 1 <= idx <= len(pages):
                break
            foff, size, typ = pages[idx - 1]
            at = k * self.page_size
            if typ == 0 and size:
                chunk = self.data[foff:foff + min(size, self.page_size)]
                out[at:at + len(chunk)] = chunk
            elif typ == 1 and self.signature == "LX":
                out[at:at + self.page_size] = _expand_iterated(self.data[foff:foff + size], self.page_size)
        return bytes(out[:vsize])

    def fixups(self):
        """every fixup record as a dict: page, src (source type), srcoff, target (target type),
        obj (object / module / entry ordinal), off (target offset / import ordinal or name offset), add"""
        d, le = self.data, self.offset
        fpt, frt = _u32(d, le + 0x68), _u32(d, le + 0x6c)
        out = []
        if not fpt or not frt:
            return out
        for page in range(1, self.n_pages + 1):
            o = le + frt + _u32(d, le + fpt + (page - 1) * 4)
            end = le + frt + _u32(d, le + fpt + page * 4)
            while o < end:
                src, fl = d[o], d[o + 1]
                o += 2
                rec = {"page": page, "src": src & 0xf, "target": fl & 3, "off": 0, "add": 0}
                if src & 0x20:
                    count = d[o]
                    o += 1
                    offs = None
                else:
                    offs = [struct.unpack_from("<h", d, o)[0]]
                    o += 2
                if fl & 0x40:
                    rec["obj"] = _u16(d, o)
                    o += 2
                else:
                    rec["obj"] = d[o]
                    o += 1
                t = rec["target"]
                if t == 0 and rec["src"] != 2 or t == 2:
                    if fl & 0x10:
                        rec["off"] = _u32(d, o)
                        o += 4
                    else:
                        rec["off"] = _u16(d, o)
                        o += 2
                elif t == 1:
                    if fl & 0x80:
                        rec["off"] = d[o]
                        o += 1
                    elif fl & 0x10:
                        rec["off"] = _u32(d, o)
                        o += 4
                    else:
                        rec["off"] = _u16(d, o)
                        o += 2
                if fl & 0x4:
                    if fl & 0x20:
                        rec["add"] = _u32(d, o)
                        o += 4
                    else:
                        rec["add"] = _u16(d, o)
                        o += 2
                if offs is None:
                    offs = [struct.unpack_from("<h", d, o + 2 * k)[0] for k in range(count)]
                    o += 2 * count
                for so in offs:
                    out.append(dict(rec, srcoff=so))
        return out

    def import_modules(self):
        d, le = self.data, self.offset
        o, out = le + _u32(d, le + 0x70), []
        for _ in range(_u32(d, le + 0x74) if _u32(d, le + 0x70) else 0):
            n = d[o]
            out.append(d[o + 1:o + 1 + n].decode("latin-1"))
            o += 1 + n
        return out

    def import_name(self, off):
        o = self.offset + _u32(self.data, self.offset + 0x78) + off
        return self.data[o + 1:o + 1 + self.data[o]].decode("latin-1")

    def bases(self):
        """object number -> linear base as the loader maps it (no base: number * 0x100000)"""
        return {i + 1: (o[1] or (i + 1) * 0x100000) for i, o in enumerate(self.objects)}

    SOURCE_SIZE = {0: 1, 2: 2, 3: 4, 5: 2, 6: 6, 7: 4, 8: 4}

    def loaded(self):
        """What a loader produces, independently of Ghidra: ({object number: bytes with fixups
        applied}, {address: (source type, status, value)}, [(module, name)] imports).
        Internal fixups only resolve; entry-table targets are not needed by DOS programs."""
        pages = self.pages()
        objs = {i + 1: bytearray(self.object_bytes(i, pages).ljust(o[4] * self.page_size, b"\0"))
                for i, o in enumerate(self.objects)}
        bases = self.bases()
        relocs, imports = {}, []
        mods = None
        for f in self.fixups():
            owner = next((i + 1 for i, o in enumerate(self.objects) if o[3] <= f["page"] < o[3] + o[4]), None)
            if owner is None:
                continue
            buf = objs[owner]
            at = (f["page"] - self.objects[owner - 1][3]) * self.page_size + f["srcoff"]
            addr = bases[owner] + at
            src = f["src"]

            def put(v, n, pos=at):
                for k in range(n):
                    if 0 <= pos + k < len(buf):
                        buf[pos + k] = (v >> (8 * k)) & 0xff
            if f["target"] != 0:
                if f["target"] in (1, 2):
                    mods = mods if mods is not None else self.import_modules()
                    m = mods[f["obj"] - 1] if 1 <= f["obj"] <= len(mods) else "MODULE_%d" % f["obj"]
                    imports.append((m, self.import_name(f["off"]) if f["target"] == 2 else "Ordinal_%d" % f["off"]))
                relocs.setdefault(addr, (src, "UNSUPPORTED", 0))
                continue
            t = bases.get(f["obj"], 0) + f["off"] + f["add"]
            sel = max(f["obj"] - 1, 0)
            if src == 0:
                v = t & 0xff
                put(v, 1)
            elif src == 5:
                v = t & 0xffff
                put(v, 2)
            elif src == 7:
                v = t & 0xffffffff
                put(v, 4)
            elif src == 8:
                v = (t - (addr + 4)) & 0xffffffff
                put(v, 4)
            elif src == 2:
                v = sel
                put(v, 2)
            elif src == 3:
                v = (f["off"] & 0xffff) | sel << 16
                put(v, 4)
            elif src == 6:
                v = t & 0xffffffff
                put(v, 4)
                put(sel, 2, at + 4)
            else:
                relocs.setdefault(addr, (src, "UNSUPPORTED", 0))
                continue
            relocs.setdefault(addr, (src, "APPLIED", v))
        return {n: bytes(b[:self.objects[n - 1][0]]) for n, b in objs.items()}, relocs, imports

    def loaded_image_lines(self):
        """the loaded image in the format of ghidra_scripts/DumpLoadedImage.java (for comparison)"""
        import hashlib
        objs, relocs, imports = self.loaded()
        bases = self.bases()
        lines = []
        for n, b in sorted(objs.items(), key=lambda kv: bases[kv[0]]):
            fl = self.objects[n - 1][2]
            if not b:
                continue
            lines.append("block .object%d %08x %08x r%s%s %s" % (n, bases[n], bases[n] + len(b) - 1,
                                                                 "w" if fl & 2 else "-", "x" if fl & 4 else "-",
                                                                 hashlib.sha1(b).hexdigest()))

        def now(a):
            for n, b in objs.items():
                if bases[n] <= a and a + 4 <= bases[n] + len(b):
                    return "%08x" % struct.unpack_from("<I", b, a - bases[n])[0]
            return "?"
        lines += sorted("reloc %08x %d %s %s" % (a, src, st, now(a)) for a, (src, st, v) in relocs.items())
        if self.eip_object:
            lines.append("entry %08x _entry" % (bases[self.eip_object] + self.eip))
        lines += sorted(set("external %s %s" % mi for mi in imports))
        return lines

    def code_object(self):
        """index of the main code object: the largest executable one, 32-bit ("big") preferred -
        LX programs often start with a small 16-bit thunk object"""
        cands = [i for i, o in enumerate(self.objects) if o[2] & 0x4]
        if not cands:
            raise FormatError("no executable object")
        return max(cands, key=lambda i: (bool(self.objects[i][2] & 0x2000), self.objects[i][0]))

    def read(self, addr, n):
        if self._mem is None:
            self._mem = {o[1]: self.object_bytes(i) for i, o in enumerate(self.objects)}
        for base, b in self._mem.items():
            if base <= addr < base + len(b):
                return b[addr - base:addr - base + n]
        raise KeyError(hex(addr))


def _expand_iterated(src, size):
    """LX EXEPACK1 page: records {u16 repeat, u16 length, bytes}"""
    out, s = bytearray(), 0
    while s + 4 <= len(src) and len(out) < size:
        rep, n = struct.unpack_from("<HH", src, s)
        s += 4
        if rep == 0 or s + n > len(src):
            break
        out += src[s:s + n] * rep
        s += n
    return bytes(out[:size]).ljust(size, b"\0")


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
        info["loader"] = "LinearExecutableLoader"      # retrokit-le-loader: LE, LX and VxD
        if _u16(d, le.offset + 0x0a) == 4:               # e32_os 4 = Windows 386
            info["notes"].append("Windows VxD")
        if le.mz_base:
            info["notes"].append("DOS/4G BW-bound: LE behind a bind chain, page offsets relative to MZ at 0x%x"
                                 % le.mz_base)
        return info
    info.update(format="MZ", notes=["16-bit real-mode DOS EXE: use Ghidra's x86:LE:16:Real Mode, this kit is not needed"])
    return info
