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

from retrokit import cli, formats, loader, sigs, workspace  # noqa: E402
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


class TestSigs(unittest.TestCase):
    def test_roundtrip(self):
        s = sigs.Sig("f_", "m.c", [0x53, 0x51, 0x52, 0x56, None, None, None, None, 0xc3], [(3, "g_")])
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("x.sig", "x.sig.gz"):
                p = os.path.join(tmp, name)
                sigs.write(p, [s], ["test"])
                (r,) = sigs.read(p)
                self.assertEqual((r.name, r.module, r.pattern, r.callees, r.lib),
                                 (s.name, s.module, s.pattern, s.callees, "x"))

    def test_match_synthetic(self):
        body = bytes([0x55, 0x89, 0xe5, 0x53, 0x8b, 0x45, 0x08, 0x40, 0x5b, 0x5d, 0xc3])
        code = b"\x90" * 7 + body + b"\xcc" * 9
        sig = sigs.Sig("inc_it_", "m.c", list(body), [])
        self.assertEqual(sigs.match([(0x1000, code)], [sig]), {})   # short and nothing calls it
        call = b"\xe8" + struct.pack("<i", 0x1007 - (0x1000 + len(code) + 5))
        found = sigs.match([(0x1000, code + call)], [sig])
        self.assertEqual(list(found), [0x1007])
        self.assertEqual(found[0x1007][:2], ("inc_it", "G"))
        long_body = body[:-1] + bytes(range(0x50, 0x58)) + b"\xc3"   # 19 fixed bytes: stands on its own
        found = sigs.match([(0x1000, code + long_body)], [sigs.Sig("f", "m", list(long_body), [])])
        self.assertEqual(found, {0x1000 + len(code): ("f", "V", "sig /m 19B")})

    def test_shipped_on_fixtures(self):
        """shipped Watcom signatures name the library functions of the test programs, all correctly"""
        sys.path.insert(0, HERE)
        import evaluate
        for name, minimum in (("dos4g_r", 100), ("dos4g_s", 100)):
            exe = variant(name)
            if not exe:
                continue
            le = formats.LinearExecutable(exe)
            bases = le.bases()
            names = {}
            for seg, off, sym, own in evaluate.parse_map(os.path.join(BUILD, name, "engine.map")):
                if seg in bases:
                    names.setdefault(bases[seg] + off, set()).add(evaluate.norm(sym))
            found, _ = sigs.match_file(exe)
            right = [a for a, v in found.items() if evaluate.norm(v[0]) in names.get(a, ())]
            # the rest are static functions the map does not list (OW 1.9 exports them)
            unlisted = [a for a in found if a not in names]
            self.assertGreaterEqual(len(right), minimum, name)
            self.assertEqual(len(right) + len(unlisted), len(found), name)

    def test_fuzzy_other_version(self):
        """Open Watcom 1.9 signatures on programs built with Open Watcom 2: the fuzzy tier
        names functions whose code changed between the versions"""
        sys.path.insert(0, HERE)
        import evaluate
        exe = variant("dos4g_s")
        if not exe:
            self.skipTest("dos4g_s not built")
        le = formats.LinearExecutable(exe)
        bases = le.bases()
        names = {}
        for seg, off, sym, own in evaluate.parse_map(os.path.join(BUILD, "dos4g_s", "engine.map")):
            if seg in bases:
                names.setdefault(bases[seg] + off, set()).add(evaluate.norm(sym))
        ow19 = [os.path.join(sigs.SHIPPED, "watcom-ow19-dos-clib3s.sig.gz")]
        exact, _ = sigs.match_file(exe, ow19, fuzzy=False)
        both, _ = sigs.match_file(exe, ow19)
        added = {a: v for a, v in both.items() if a not in exact}
        right = [a for a, v in added.items() if evaluate.norm(v[0]) in names.get(a, ())]
        wrong = [a for a, v in added.items() if a in names and evaluate.norm(v[0]) not in names[a]]
        self.assertGreaterEqual(len(right), 15)
        self.assertLessEqual(len(wrong), 1)     # __SetIOMode: renamed __SetIOMode_grow in OW 2
        self.assertTrue(all(v[1] == "G" for v in added.values()))


if __name__ == "__main__":
    unittest.main()
