"""Unit tests for the Python tools (no Ghidra needed).

    python -m unittest discover -s tests

Tests that need the built fixtures (tests/build_fixtures.py) are skipped when
the fixtures are missing.
"""
import glob
import json
import os
import struct
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
TOOLS = os.path.join(KIT, "retrokit", "tools")
BUILD = os.path.join(HERE, "fixtures", "build")
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)

import evaluate  # noqa: E402
import flic  # noqa: E402
import rnc  # noqa: E402


def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def built_variants():
    """built LE variants (the PE one has no calling-convention detection / LE reader)"""
    return [os.path.dirname(p) for p in sorted(glob.glob(os.path.join(BUILD, "*", "variant.json")))
            if load_json(p).get("cspec")]


def run_tool(script, *args, env=None):
    r = subprocess.run([sys.executable, "-E", os.path.join(TOOLS, script)] + list(args),
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout + r.stderr


def chunk(ctype, payload):
    return struct.pack("<IH", 6 + len(payload), ctype) + payload


def frame(*chunks):
    body = b"".join(chunks)
    return struct.pack("<IHH8x", 16 + len(body), 0xF1FA, len(chunks)) + body


class TestFlic(unittest.TestCase):
    def make_fli(self):
        w, h = 4, 2
        color64 = struct.pack("<H", 1) + bytes([0, 2]) + bytes([63, 0, 0, 0, 63, 0])
        copy = bytes([0, 1, 0, 1, 1, 0, 1, 0])
        delta = struct.pack("<HH", 1, 1) + bytes([1, 1, 0xFE, 0])   # row 1: skip 1, run of 2 x 0
        frames = frame(chunk(11, color64), chunk(16, copy)) + frame(chunk(12, delta))
        hdr = struct.pack("<IHHHHHHH", 128 + len(frames), 0xAF11, 2, w, h, 8, 0, 5)
        return hdr.ljust(128, b"\0") + frames

    def test_decode(self):
        f = flic.Flic(self.make_fli())
        self.assertEqual((f.frames, f.width, f.height), (2, 4, 2))
        self.assertAlmostEqual(f.speed_ms, 5 * 1000.0 / 70.0)
        out = list(f.iter_frames())
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0][1], bytes([0, 1, 0, 1, 1, 0, 1, 0]))
        self.assertEqual(out[1][1], bytes([0, 1, 0, 1, 1, 0, 0, 0]))
        self.assertEqual(out[0][2][:6], bytes([255, 0, 0, 0, 255, 0]))   # 6-bit palette scaled


class TestRnc(unittest.TestCase):
    def test_crc16(self):
        self.assertEqual(rnc.crc16(b"123456789"), 0xBB3D)   # CRC-16/ARC check value

    def test_header(self):
        data = b"RNC\x01" + struct.pack(">IIHHBB", 1000, 400, 0x1234, 0x5678, 0, 2) + bytes(400)
        self.assertTrue(rnc.is_rnc(data))
        self.assertFalse(rnc.is_rnc(b"XYZ\x01" + data[4:]))


class TestEvaluateSources(unittest.TestCase):
    def test_annotations(self):
        src = evaluate.parse_sources()
        self.assertEqual(src["fatal"], {"nparams": 1, "varargs": True, "noreturn": True, "table": False})
        self.assertTrue(src["upd_walker"]["table"])
        self.assertEqual(src["checksum"]["nparams"], 6)
        self.assertEqual(src["usage"]["nparams"], 0)


@unittest.skipUnless(built_variants(), "fixtures not built (tests/build_fixtures.py)")
class TestFixtures(unittest.TestCase):
    def test_detect_cc(self):
        for vdir in built_variants():
            spec = load_json(os.path.join(vdir, "variant.json"))
            code, out = run_tool("detect_cc.py", os.path.join(vdir, "engine.exe"))
            self.assertEqual(code, 0, out)
            self.assertIn("-Cspec %s\n" % spec["cspec"], out + "\n", "%s: %s" % (spec["name"], out[-200:]))

    def test_le_info(self):
        for vdir in built_variants():
            env = dict(os.environ, LE_EXE=os.path.join(vdir, "engine.exe"))
            code, out = run_tool("le.py", "info", env=env)
            self.assertEqual(code, 0, out)
            self.assertIn("LE at", out)
            self.assertRegex(out, r"(?m)^1 \['0x[0-9a-f]+', '0x10000'")


if __name__ == "__main__":
    unittest.main()
