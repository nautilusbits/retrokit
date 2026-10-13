r"""Minimal LE (DOS/4GW) reader: map linear addresses (as Ghidra shows them with
the LX loader: object base addresses from the object table) to raw file bytes.
Handy for reading constant tables the decompiler cannot type.

usage: set LE_EXE=path\to\GAME.EXE  (or edit EXE below), then
       python le.py info
       python le.py dump ADDR LEN          hex dump
       python le.py rec ADDR NREC RECSIZE [struct-fmt]   record table
       python le.py s16 ADDR N | s32 ADDR N
"""
import os
import struct
import sys

EXE = os.environ.get("LE_EXE", r"GAME.EXE")
data = open(EXE, "rb").read()

def find_le():
    """Return (le_offset, mz_base). mz_base is the MZ header the LE belongs to:
    0 for a plain stub+LE file, the secondary MZ for DOS/4G "BW"-bound EXEs
    (a DOS/4G bound executable). LE offsets such as the data pages
    offset are relative to that MZ, same as in ghidra-lx-loader."""
    def u16(o): return struct.unpack_from("<H", data, o)[0]
    def is_le(o):
        return 0 <= o < len(data) - 8 and data[o:o+2] in (b"LE", b"LX") \
            and data[o+2] == 0 and data[o+3] == 0 and struct.unpack_from("<I", data, o+4)[0] == 0
    if data[:2] == b"MZ":
        if u16(0x18) == 0x40:  # new-style header: e_lfanew
            o = struct.unpack_from("<I", data, 0x3c)[0]
            if is_le(o):
                return o, 0
        else:                   # old-style stub followed by BW headers (DOS/4G bind)
            o = (u16(4) - 1) * 512 + u16(2)
            while data[o:o+2] == b"BW":
                nxt = struct.unpack_from("<I", data, o + 0x1c)[0]
                if nxt <= o:
                    break
                o = nxt
            if data[o:o+2] == b"MZ":
                le_off = o + struct.unpack_from("<I", data, o + 0x3c)[0]
                if is_le(le_off):
                    return le_off, o
    elif is_le(0):
        return 0, 0
    # fallback: scan for the signature
    off = 0
    while True:
        i = data.find(b"LE", off)
        if i < 0:
            raise SystemExit("no LE header")
        if is_le(i):
            return i, 0
        off = i + 1

le, mz_base = find_le()
def u32(o): return struct.unpack_from("<I", data, le + o)[0]
page_size = u32(0x28)
n_pages = u32(0x14)
obj_tab = u32(0x40)
n_obj = u32(0x44)
page_map = u32(0x48)
data_pages = mz_base + u32(0x80)  # relative to the MZ header owning the LE
last_page_size = u32(0x2c)

objs = []
for i in range(n_obj):
    o = le + obj_tab + i * 24
    vsize, base, flags, pmap_idx, pcount, _ = struct.unpack_from("<IIIIII", data, o)
    objs.append((vsize, base, flags, pmap_idx, pcount))

def obj_bytes(i):
    vsize, base, flags, pmap_idx, pcount = objs[i]
    out = bytearray()
    for p in range(pcount):
        e = le + page_map + (pmap_idx - 1 + p) * 4
        hi, lo, fl = struct.unpack_from("<HBB", data, e)  # LE page map entry: 3-byte page number (big-endian-ish) + flags
        pnum = (data[e] << 16 | data[e+1] << 8 | data[e+2])
        foff = data_pages + (pnum - 1) * page_size
        out += data[foff:foff + page_size]
    out = out[:vsize] + bytes(max(0, vsize - len(out)))
    return bytes(out)

# Ghidra maps every object at the base address from the object table
# (typically 0x10000 code / 0x90000 or 0x100000 data)
mem = {}
for i, (vsize, base, flags, pmap_idx, pcount) in enumerate(objs):
    mem[base] = obj_bytes(i)

def read(addr, n):
    for base, b in mem.items():
        if base <= addr < base + len(b):
            return b[addr - base: addr - base + n]
    raise KeyError(hex(addr))

if __name__ == "__main__":
    if sys.argv[1] == "info":
        print("LE at", hex(le), "MZ base", hex(mz_base), "data pages", hex(data_pages), "page", page_size, "objects:")
        for i, o in enumerate(objs):
            print(i + 1, [hex(x) for x in o])
    elif sys.argv[1] == "dump":
        a = int(sys.argv[2], 16); n = int(sys.argv[3], 16) if sys.argv[3].startswith("0x") else int(sys.argv[3])
        b = read(a, n)
        for i in range(0, n, 16):
            print("%08x  %s" % (a + i, " ".join("%02x" % c for c in b[i:i+16])))
    elif sys.argv[1] == "rec":
        a = int(sys.argv[2], 16); nrec = int(sys.argv[3]); rs = int(sys.argv[4])
        fmt = sys.argv[5] if len(sys.argv) > 5 else None
        for r in range(nrec):
            b = read(a + r * rs, rs)
            if fmt:
                vals = struct.unpack("<" + fmt, b[:struct.calcsize("<" + fmt)])
                print("%08x [%3d] %s" % (a + r * rs, r, " ".join(("%x" % v) if isinstance(v, int) and v > 9 else str(v) for v in vals)))
            else:
                print("%08x [%3d] %s" % (a + r * rs, r, " ".join("%02x" % c for c in b)))
    elif sys.argv[1] == "s16":
        a = int(sys.argv[2], 16); n = int(sys.argv[3])
        b = read(a, n * 2)
        print(list(struct.unpack("<%dh" % n, b)))
    elif sys.argv[1] == "s32":
        a = int(sys.argv[2], 16); n = int(sys.argv[3])
        b = read(a, n * 4)
        print(list(struct.unpack("<%di" % n, b)))
