"""Tests of retrokit.media on synthetic files (no game data).

    python -m unittest discover -s tests
"""
import os
import struct
import sys
import tempfile
import unittest
import wave

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from retrokit import media  # noqa: E402


def read_midi(m):
    """(format, division, [[(abs time, event bytes)] per track]) of a standard MIDI file"""
    fmt, ntr, div = struct.unpack_from(">HHH", m, 8)
    p, tracks = 14, []
    for _ in range(ntr):
        assert m[p:p + 4] == b"MTrk"
        end = p + 8 + struct.unpack_from(">I", m, p + 4)[0]
        q, t, ev = p + 8, 0, []
        while q < end:
            dt, q = media._read_vlq(m, q)
            t += dt
            b = m[q]
            if b == 0xff:
                n, r = media._read_vlq(m, q + 2)
                ev.append((t, m[q:r + n]))
                q = r + n
            else:
                n = 1 + media._DATA_LEN[b & 0xf0]
                ev.append((t, m[q:q + n]))
                q += n
        tracks.append(ev)
        p = end
    return fmt, div, tracks


def chunk(cid, body):
    return cid + struct.pack(">I", len(body)) + body + (b"\0" if len(body) & 1 else b"")


def xmi(*sequences):
    forms = b"".join(chunk(b"FORM", b"XMID" + chunk(b"EVNT", ev)) for ev in sequences)
    xdir = chunk(b"FORM", b"XDIR" + chunk(b"INFO", struct.pack("<H", len(sequences))))
    return xdir + chunk(b"CAT ", b"XMID" + forms)


class TestXmi(unittest.TestCase):
    # program change, note C4 for 30 ticks after a delay of 10 (two delay bytes 4+6),
    # tempo event (dropped), controller, end
    EVNT = bytes([0xc0, 5, 4, 6, 0x90, 60, 100, 30, 0xff, 0x51, 3, 7, 0xa1, 0x20, 0xb0, 7, 90, 40, 0xff, 0x2f, 0])

    def test_sequence(self):
        d = xmi(self.EVNT, self.EVNT)
        seqs = media.xmi_sequences(d)
        self.assertEqual(len(seqs), 2)
        fmt, div, (track,) = read_midi(media.xmi_to_midi(seqs[0]))
        self.assertEqual((fmt, div), (0, 60))
        ev = [(t, e) for t, e in track if e[:2] not in (b"\xff\x2f",)]
        self.assertIn((0, b"\xff\x51\x03\x07\xa1\x20"), ev)       # fixed tempo 500000 us
        self.assertEqual(sum(1 for _, e in ev if e[:2] == b"\xff\x51"), 1)   # the XMIDI tempo is dropped
        self.assertIn((0, b"\xc0\x05"), ev)
        self.assertIn((10, b"\x90\x3c\x64"), ev)                  # delay = 4 + 6
        self.assertIn((40, b"\x80\x3c\x40"), ev)                  # note off after the duration
        self.assertIn((10, b"\xb0\x07\x5a"), ev)

    def test_single_form(self):
        d = chunk(b"FORM", b"XMID" + chunk(b"TIMB", b"\x01\x00\x05\x00") + chunk(b"EVNT", self.EVNT))
        self.assertEqual(len(media.xmi_sequences(d)), 1)
        self.assertEqual(media.kind(d[:32]), "xmi")


class TestHmi(unittest.TestCase):
    def build(self, events):
        head = bytearray(0x180)
        head[:18] = b"HMI-MIDISONG061595"
        head[0xd4] = 100                       # bpm
        head[0xe4] = 1                         # tracks
        struct.pack_into("<I", head, 0x172, len(head))
        th = bytearray(0x60)
        th[:13] = b"HMI-MIDITRACK"
        struct.pack_into("<I", th, 0x57, len(th))
        return bytes(head) + bytes(th) + events

    def test_track(self):
        # running status notes with durations, an HMI 0xFE loop marker, end of track
        ev = bytes([0, 0x91, 64, 80, 20, 5, 65, 81, 10, 0, 0xfe, 0x14, 0xff, 0xff, 3, 0xff, 0x2f, 0])
        fmt, div, (track,) = read_midi(media.hmi_to_midi(self.build(ev)))
        self.assertEqual(div, 60)
        notes = [(t, e) for t, e in track if e[0] & 0xf0 in (0x80, 0x90)]
        self.assertEqual(notes, [(0, b"\x91\x40\x50"), (5, b"\x91\x41\x51"), (15, b"\x81\x41\x40"),
                                 (20, b"\x81\x40\x40")])
        self.assertIn((0, b"\xff\x51\x03" + struct.pack(">I", 600000)[1:]), track)   # 100 bpm


class TestHmp(unittest.TestCase):
    def test_track(self):
        head = bytearray(0x308)
        head[:8] = b"HMIMIDIP"
        struct.pack_into("<I", head, 0x30, 1)
        struct.pack_into("<I", head, 0x38, 120)
        # deltas: little-endian 7-bit groups, high bit on the last byte; 200 = 0x48 + (1 << 7)
        ev = bytes([0x80, 0x92, 70, 90, 0x48, 0x81, 70, 0, 0x80, 0xff, 0x2f, 0])
        trk = struct.pack("<III", 0, 12 + len(ev), 0) + ev
        fmt, div, (track,) = read_midi(media.hmp_to_midi(bytes(head) + trk))
        notes = [(t, e) for t, e in track if e[0] & 0xf0 == 0x90]
        self.assertEqual(notes, [(0, b"\x92\x46\x5a"), (200, b"\x92\x46\x00")])


class TestVoc(unittest.TestCase):
    def test_pcm8(self):
        samples = bytes(range(0, 250, 2))
        block = bytes([1]) + struct.pack("<I", 2 + len(samples))[:3] + bytes([256 - 100, 0]) + samples   # 10 kHz
        d = b"Creative Voice File\x1a" + struct.pack("<HHH", 26, 0x10a, 0x1129) + block + b"\0"
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "a.wav")
            desc = media.voc_to_wav(d, out)
            with wave.open(out) as w:
                self.assertEqual((w.getframerate(), w.getsampwidth(), w.getnchannels()), (10000, 1, 1))
                self.assertEqual(w.readframes(1000), samples)
            self.assertIn("10000 Hz", desc)
            self.assertEqual(media.kind(d[:32]), "voc")


class TestScan(unittest.TestCase):
    def test_convert_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "MUSIC"))
            with open(os.path.join(tmp, "MUSIC", "SONG.DAT"), "wb") as fh:   # extension does not matter
                fh.write(xmi(TestXmi.EVNT))
            with open(os.path.join(tmp, "readme.txt"), "w") as fh:
                fh.write("text")
            found = media.scan(tmp)
            self.assertEqual([k for _, k in found], ["xmi"])
            out = media.convert(found[0][0], os.path.join(tmp, "out"))
            self.assertEqual(len(out), 1)
            self.assertTrue(out[0][0].endswith("SONG.mid"))


if __name__ == "__main__":
    unittest.main()
