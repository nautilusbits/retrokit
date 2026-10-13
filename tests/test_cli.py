"""Tests of the retrokit package without Ghidra: format identification, the loader's cspec
registration, workspaces, the command line.

    python -m unittest discover -s tests
"""
import glob
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from retrokit import cli, formats, loader, workspace  # noqa: E402
from retrokit import ghidra as gh  # noqa: E402

BUILD = os.path.join(HERE, "fixtures", "build")


def variant(name):
    p = os.path.join(BUILD, name, "engine.exe")
    return p if os.path.isfile(p) else None


def le_header():
    return b"LE\0\0" + struct.pack("<I", 0) + bytes(0xb0)


class TestFindLe(unittest.TestCase):
    def test_lfanew(self):
        d = bytearray(b"MZ" + bytes(0x3e))
        struct.pack_into("<H", d, 0x18, 0x40)
        struct.pack_into("<I", d, 0x3c, 0x80)
        d += bytes(0x80 - len(d)) + le_header()
        self.assertEqual(formats.find_le(bytes(d)), (0x80, 0))

    def test_bw_chain(self):
        # old-style MZ stub (no e_lfanew), two BW headers, a second MZ whose e_lfanew points to the LE
        stub = bytearray(b"MZ" + bytes(0x3e))
        struct.pack_into("<HH", stub, 2, 0x100, 1)        # 1 page, 0x100 bytes in the last one
        d = stub + bytes(0x100 - len(stub))
        bw1, bw2, mz2 = 0x100, 0x200, 0x300
        for off, nxt in ((bw1, bw2), (bw2, mz2)):
            h = bytearray(b"BW" + bytes(0x3e))
            struct.pack_into("<I", h, 0x1c, nxt)
            d += h + bytes(0x100 - len(h))
        mz = bytearray(b"MZ" + bytes(0x3e))
        struct.pack_into("<I", mz, 0x3c, 0x40)
        d += mz + le_header()
        self.assertEqual(formats.find_le(bytes(d)), (mz2 + 0x40, mz2))

    def test_not_le(self):
        self.assertIsNone(formats.find_le(b"MZ" + bytes(0x100)))


class TestRegisterCspecs(unittest.TestCase):
    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as g:
            lang = os.path.join(g, "Ghidra", "Processors", "x86", "data", "languages")
            os.makedirs(lang)
            ldefs = os.path.join(lang, "x86.ldefs")
            with open(ldefs, "w", newline="") as fh:
                fh.write('<language id="x86:LE:32:default">\r\n    %s\r\n</language>\r\n' % loader.LDEFS_MARKER)
            for _ in range(2):
                loader.register_cspecs(g, log=lambda *a: None)
            text = open(ldefs, newline="").read()
            for f, cid, _ in gh.CSPECS:
                self.assertEqual(text.count('id="%s"' % cid), 1)
                self.assertTrue(os.path.isfile(os.path.join(lang, f)))
            self.assertIn('\r\n    <compiler name="Watcom C"', text)   # line ending + indentation kept
            self.assertEqual(gh.loader_status(g)["cspecs"], ["watcom", "watcomreg"])


class TestWorkspace(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            ws = {"dir": d, "exe": "x.exe", "pipeline": "le", "cspec": "watcom"}
            workspace.save(ws)
            self.assertTrue(workspace.is_workspace(d))
            back = workspace.load(d)
            self.assertEqual((back["exe"], back["cspec"], back["version"]), ("x.exe", "watcom", workspace.VERSION))
        self.assertTrue(workspace.default_dir(os.path.join("a", "GAME.EXE")).endswith("game_analysis"))


class TestCli(unittest.TestCase):
    def test_parser(self):
        a = cli.build_parser().parse_args(["analyze", "GAME.EXE", "--cspec", "watcomreg", "--no-prototypes"])
        self.assertEqual((a.exe, a.cspec, a.no_prototypes), ("GAME.EXE", "watcomreg", True))
        a = cli.build_parser().parse_args(["flic", "info", "x.fli"])
        self.assertEqual(a.args, ["info", "x.fli"])

    def test_not_a_workspace(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit):
            cli.main(["show", d, "main"])


@unittest.skipUnless(glob.glob(os.path.join(BUILD, "*", "engine.exe")), "fixtures not built")
class TestIdentifyFixtures(unittest.TestCase):
    EXPECT = {"dos4g_s": ("LE", "DOS/4GW", "watcom"), "dos4g_r": ("LE", "DOS/4GW", "watcomreg"),
              "dos32a_r": ("LE", "DOS/32A", "watcomreg"), "pmodew_s": ("LE", "PMODE/W", "watcom")}

    def test_le_variants(self):
        for name, (fmt, ext, cspec) in self.EXPECT.items():
            exe = variant(name)
            if not exe:
                continue
            out = io.StringIO()
            with redirect_stdout(out):
                cli.main(["info", exe, "--json"])
            info = json.loads(out.getvalue())
            self.assertEqual((info["format"], info["extender"], info["compiler"], info["loader"]),
                             (fmt, ext, "Watcom C/C++", "LinearExecutableLoader"), name)
            self.assertEqual(info["convention"]["cspec"], cspec, name)

    def test_pe_variant(self):
        exe = variant("nt_s")
        if not exe:
            self.skipTest("nt_s not built")
        info = formats.identify(exe)
        self.assertEqual((info["format"], info["pipeline"], info["machine"]), ("PE", "pe", "i386"))
        self.assertIn("KERNEL32.DLL", [d.upper() for d in info["dlls"]])

    def test_le_reader(self):
        exe = variant("dos4g_s")
        if not exe:
            self.skipTest("dos4g_s not built")
        le = formats.LinearExecutable(exe)
        self.assertEqual(le.objects[le.code_object()][1], 0x10000)
        self.assertEqual(len(le.read(0x10000, 16)), 16)


if __name__ == "__main__":
    unittest.main()
