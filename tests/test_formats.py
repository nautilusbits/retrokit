"""Format detection on synthetic PE images: no false LE hits, packer/DRM warnings."""
import os
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from retrokit import formats, sigs  # noqa: E402


def make_pe(sections, entry_rva):
    """sections: [(name, bytes, characteristics)], file-aligned at 0x200, RVAs from 0x1000"""
    lfanew, opt = 0x80, 0xe0
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3c, lfanew)
    hdr[lfanew:lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HH", hdr, lfanew + 4, 0x14c, len(sections))
    struct.pack_into("<H", hdr, lfanew + 20, opt)
    struct.pack_into("<HBB", hdr, lfanew + 24, 0x10b, 8, 0)
    struct.pack_into("<I", hdr, lfanew + 24 + 16, entry_rva)
    struct.pack_into("<I", hdr, lfanew + 24 + 28, 0x400000)
    body, raw, va = bytearray(), len(hdr), 0x1000
    for i, (name, data, flags) in enumerate(sections):
        data = data + b"\0" * (-len(data) % 0x200)
        o = lfanew + 24 + opt + i * 40
        hdr[o:o + 8] = name.encode().ljust(8, b"\0")
        struct.pack_into("<IIII", hdr, o + 8, len(data), va, len(data), raw + len(body))
        struct.pack_into("<I", hdr, o + 36, flags)
        body += data
        va += (len(data) + 0xfff) & ~0xfff
    return bytes(hdr + body)


CODE = 0x60000020
DATA = 0xc0000040
# looks like code: a small repeated vocabulary of instructions
TEXT = bytes((b"\x55\x8b\xec\x83\xec\x10\x8b\x45\x08\x50\xe8\x00\x00\x00\x00\x83\xc4\x04\x5d\xc3" * 400))


class TestFormats(unittest.TestCase):
    def test_pe_with_le_bytes_is_not_le(self):
        data = bytearray(0x4000)
        data[0x123:0x12b] = b"LE\0\0\0\0\0\0"        # the chance hit from the bug report
        d = make_pe([(".text", TEXT, CODE), (".data", bytes(data), DATA)], 0x1000)
        self.assertIsNone(formats.find_le(d))
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.exe")
            with open(p, "wb") as f:
                f.write(d)
            self.assertEqual(formats.identify(p)["format"], "PE")
            self.assertEqual(sigs.code_regions(p)[0][0], 0x401000)

    def test_clean_pe_has_no_protection(self):
        d = make_pe([(".text", TEXT, CODE), (".data", bytes(0x1000), DATA)], 0x1000)
        self.assertEqual(formats.protection(d), [])

    def test_steamstub(self):
        d = make_pe([(".text", TEXT, CODE), (".data", bytes(0x1000), DATA), (".bind", TEXT[:0x1000], CODE)],
                    0x4000)
        prot = formats.protection(d)
        self.assertTrue(any("SteamStub" in p for p in prot), prot)
        self.assertTrue(any("entry point in the last section" in p for p in prot), prot)

    def test_encrypted_code(self):
        rnd = random.Random(1).randbytes(0x8000)
        d = make_pe([(".text", rnd, CODE)], 0x1000)
        self.assertTrue(any("entropy" in p for p in formats.protection(d)))

    def test_damaged_le_header_raises_format_error(self):
        d = bytearray(0x400)
        d[0:2] = b"MZ"
        struct.pack_into("<H", d, 0x18, 0x40)
        struct.pack_into("<I", d, 0x3c, 0x80)
        d[0x80:0x88] = b"LE\0\0\0\0\0\0"
        struct.pack_into("<III", d, 0x80 + 0x40, 0xffff0000, 5, 0)   # object table far outside
        with self.assertRaises(formats.FormatError):
            formats.LinearExecutable(data=bytes(d))


if __name__ == "__main__":
    unittest.main()
