"""Win32 knowledge without Ghidra: MSVC RTTI from a synthetic PE, the DirectX header,
the Win32 library prototypes (no game data).

    python -m unittest discover -s tests
"""
import os
import re
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from retrokit import paths, rtti  # noqa: E402

BASE = 0x400000


def make_pe(text, rdata):
    """minimal PE32: .text at 0x1000 (executable), .rdata at 0x2000"""
    sections = [(b".text", 0x1000, text, 0x60000020), (b".rdata", 0x2000, rdata, 0x40000040)]
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3c, 0x40)
    hdr[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x44, 0x14c, len(sections), 0, 0, 0, 224, 0x102)
    opt = 0x58
    struct.pack_into("<H", hdr, opt, 0x10b)
    struct.pack_into("<I", hdr, opt + 28, BASE)
    struct.pack_into("<II", hdr, opt + 32, 0x1000, 0x200)
    raw, body = 0x400, b""
    for i, (name, va, data, flags) in enumerate(sections):
        s = opt + 224 + 40 * i
        size = (len(data) + 0x1ff) & ~0x1ff
        hdr[s:s + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", hdr, s + 8, len(data), va, size, raw)
        struct.pack_into("<I", hdr, s + 36, flags)
        body += data.ljust(size, b"\0")
        raw += size
    return bytes(hdr) + body


def rtti_image():
    """classes CBase (2 virtual methods) and CDerived : CBase (overrides method 1)"""
    text = b"\xc3" * 0x40                       # methods at 0x401000, 0x401010, 0x401020
    r = bytearray(0x400)
    va = lambda off: BASE + 0x2000 + off  # noqa: E731

    def td(off, name):
        struct.pack_into("<II", r, off, va(0x3f0), 0)
        r[off + 8:off + 8 + len(name) + 1] = name + b"\0"
    td(0x000, b".?AVCBase@@")
    td(0x020, b".?AVCDerived@@")
    # base class descriptors, arrays, hierarchy descriptors
    struct.pack_into("<IIiiiI", r, 0x040, va(0x000), 0, 0, -1, 0, 0)     # BCD CBase
    struct.pack_into("<IIiiiI", r, 0x060, va(0x020), 1, 0, -1, 0, 0)     # BCD CDerived
    struct.pack_into("<I", r, 0x080, va(0x040))                          # BCA of CBase
    struct.pack_into("<II", r, 0x088, va(0x060), va(0x040))              # BCA of CDerived
    struct.pack_into("<IIII", r, 0x0a0, 0, 0, 1, va(0x080))              # CHD CBase
    struct.pack_into("<IIII", r, 0x0b0, 0, 0, 2, va(0x088))              # CHD CDerived
    struct.pack_into("<IIIII", r, 0x0c0, 0, 0, 0, va(0x000), va(0x0a0))  # COL CBase
    struct.pack_into("<IIIII", r, 0x0e0, 0, 0, 0, va(0x020), va(0x0b0))  # COL CDerived
    struct.pack_into("<III", r, 0x100, va(0x0c0), BASE + 0x1000, BASE + 0x1010)   # vtable CBase at 0x104
    struct.pack_into("<III", r, 0x110, va(0x0e0), BASE + 0x1000, BASE + 0x1020)   # vtable CDerived at 0x114
    return make_pe(text, bytes(r))


class TestRtti(unittest.TestCase):
    def test_scan(self):
        classes = rtti.scan(rtti_image())
        self.assertEqual(sorted(classes), ["CBase", "CDerived"])
        self.assertEqual(classes["CDerived"]["bases"], ["CBase"])
        self.assertEqual(classes["CBase"]["vtables"], [("%08x" % (BASE + 0x2104), 0, ["00401000", "00401010"])])
        self.assertEqual(classes["CDerived"]["vtables"][0][2], ["00401000", "00401020"])

    def test_names(self):
        props = {a: (n, c) for a, n, c, _ in rtti.name_proposals(rtti.scan(rtti_image()))}
        self.assertEqual(props[BASE + 0x2104], ("vftable_CBase", "V"))
        self.assertEqual(props[0x401000], ("CBase_vfunc_0", "G"))      # shared: named after the base
        self.assertEqual(props[0x401020], ("CDerived_vfunc_1", "G"))
        named = rtti.name_proposals(rtti.scan(rtti_image()), {0x401010: "draw"})
        self.assertNotIn(0x401010, [a for a, _, c, _ in named if c == "G"])

    def test_class_name(self):
        self.assertEqual(rtti.class_name(".?AVInner@Outer@@"), "Outer::Inner")
        self.assertEqual(rtti.class_name(".?AUPOINT@@"), "POINT")


def coff_lib():
    """an MSVC-style .lib with one object: _scale (calls the external _helper) and _twice"""
    scale = bytes([0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x50, 0xe8, 0, 0, 0, 0, 0x83, 0xc4, 0x04, 0x8b,
                   0x4d, 0x0c, 0x0f, 0xaf, 0xc1, 0x03, 0x45, 0x10, 0x5d, 0xc3])
    twice = bytes([0x8b, 0x44, 0x24, 0x04, 0x03, 0xc0, 0x05, 0x34, 0x12, 0x00, 0x00, 0xc1, 0xe0, 0x02,
                   0x2d, 0x11, 0x00, 0x00, 0x00, 0xc3])
    text = scale + b"\xcc" * 6 + twice
    nsym = 4
    head_size = 20 + 40
    rel = struct.pack("<IIH", 8, 3, 0x14)                       # REL32 at 8 -> symbol 3 (_helper)
    text_ptr = head_size
    rel_ptr = text_ptr + len(text)
    sym_ptr = rel_ptr + len(rel)
    obj = bytearray(struct.pack("<HHIIIHH", 0x14c, 1, 0, sym_ptr, nsym, 0, 0))
    obj += b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, len(text), text_ptr, rel_ptr, 0, 1, 0, 0x60000020)
    obj += text + rel

    def sym(name, value, sec, typ, cls):
        return name.ljust(8, b"\0") + struct.pack("<IhHBB", value, sec, typ, cls, 0)
    obj += sym(b".text", 0, 1, 0, 3) + sym(b"_scale", 0, 1, 0x20, 2) + sym(b"_twice", 32, 1, 0x20, 2)
    obj += sym(b"_helper", 0, 0, 0x20, 2) + struct.pack("<I", 4)
    member = b"util.obj/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) + \
        str(len(obj)).encode().ljust(10) + b"`\n" + bytes(obj)
    return b"!<arch>\n" + member, scale, twice


class TestCoff(unittest.TestCase):
    def test_lib_sigs(self):
        import tempfile
        from retrokit import coff, sigs
        data, scale, twice = coff_lib()
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "util.lib")
            with open(p, "wb") as fh:
                fh.write(data)
            found = {s.name: s for s in coff.lib_sigs(p)}
        self.assertEqual(sorted(found), ["scale", "twice"])
        self.assertEqual(found["scale"].callees, [(7, "helper")])
        self.assertEqual(found["scale"].pattern[8:12], [None] * 4)
        self.assertEqual(found["scale"].module, "util.obj")
        # found again in a program where the call goes elsewhere
        prog = b"\x90" * 16 + scale[:8] + struct.pack("<i", 0x100) + scale[12:] + b"\x90" * 8 + twice
        hits = sigs.match([(0x401000, prog)], list(found.values()))
        self.assertEqual(hits[0x401010][0], "scale")

    def test_msvc_names(self):
        from retrokit import coff
        self.assertEqual(coff.msvc_name("_strlen"), "strlen")
        self.assertEqual(coff.msvc_name("_Sleep@4"), "Sleep")
        self.assertEqual(coff.msvc_name("@fast@8"), "fast")
        self.assertEqual(coff.msvc_name("??2@YAPAXI@Z"), "operator_new")
        self.assertIsNone(coff.msvc_name("?f@C@@QAEXXZ"))


class TestRichHeader(unittest.TestCase):
    def test_decode(self):
        from retrokit import formats
        key = 0x12345678
        entries = [(0x5d, 6030, 10), (0x5a, 6030, 2), (0x01, 0, 40)]
        body = struct.pack("<IIII", 0x536e6144 ^ key, key, key, key)
        for prod, build, count in entries:
            body += struct.pack("<II", ((prod << 16) | build) ^ key, count ^ key)
        d = bytearray(0x80) + body + b"Rich" + struct.pack("<I", key)
        lfanew = len(d)
        self.assertEqual(formats.rich_header(bytes(d), lfanew), entries)
        self.assertEqual(formats.msvc_version(entries), "VC++ 7.1 (VS .NET 2003)")


class TestKnowledge(unittest.TestCase):
    def header(self, name):
        with open(os.path.join(paths.KNOWLEDGE, "win32", name), encoding="utf-8") as fh:
            return fh.read()

    def test_directx_layouts(self):
        t = self.header("directx.h")
        for name, n in (("IDirectDraw", 23), ("IDirectDrawSurface7", 49), ("IDirectSoundBuffer", 21),
                        ("IDirect3DDevice9", 119), ("IDirectInputDeviceA", 18)):
            m = re.search(r"typedef struct %sVtbl \{(.*?)\} %sVtbl;" % (name, name), t, re.S)
            self.assertIsNotNone(m, name)
            self.assertEqual(m.group(1).count("(__stdcall"), n, name)

    def test_decorated_sizes(self):
        """argument bytes of the prototypes match the _Name@N imports seen in games"""
        sizes = {"SmackOpen": 12, "SmackToBuffer": 28, "SmackClose": 4, "BinkOpen": 8, "BinkCopyToBuffer": 28,
                 "BinkCopyToBufferRect": 44, "BinkPause": 8, "BinkSetSoundSystem": 8, "AIL_set_preference": 8,
                 "AIL_startup": 0, "AIL_set_sequence_volume": 12, "FSOUND_Init": 12}
        text = "".join(self.header(h) for h in ("rad.h", "mss.h", "fmod_bass.h"))
        for name, n in sizes.items():
            m = re.search(r"\b%s\s*\(([^)]*)\)\s*;" % name, text)
            self.assertIsNotNone(m, name)
            args = [x for x in m.group(1).split(",") if x.strip() and x.strip() != "void"]
            self.assertEqual(4 * len(args), n, name)


if __name__ == "__main__":
    unittest.main()
