"""Converters for the sound and video formats of DOS-era games.

    retrokit convert FILE|DIR [-o OUT] [--list]

Recognised by content, not by extension:
  XMIDI   (.XMI; Miles AIL / MIDPAK)        -> standard MIDI file per sequence
  HMI     (.HMI, 'HMI-MIDISONG'; HMI SOS)   -> standard MIDI file
  HMP     (.HMP, 'HMIMIDIP'; HMI SOS)       -> standard MIDI file
  VOC     (Creative Voice File)             -> WAV
  Smacker, Bink, FLI/FLC                    -> video through FFmpeg (if installed)

XMIDI: IFF ('FORM XDIR' + 'CAT XMID' of 'FORM XMID' sequences, or one 'FORM XMID'). Event data
('EVNT') has no running status; a delay is the sum of consecutive bytes below 0x80; note-on
events carry their duration as a variable-length number instead of a note-off. AIL plays
XMIDI at 120 ticks per second; tempo events were baked into the delays, so they are dropped
and the MIDI file gets a fixed tempo with 60 ticks per quarter note at 120 bpm.
HMI: song header 'HMI-MIDISONG061595', tempo at 0xD4, track count at 0xE4, track offsets at
0x172; every track starts with 'HMI-MIDITRACK' and its header length at +0x57. Events are MIDI
with running status and note durations as in XMIDI; 0xFE events are HMI's own (loops,
branches) and are skipped. 60 ticks per quarter note at the header's bpm.
HMP: 'HMIMIDIP' (+ '013195' in the newer variant), track count at 0x30, bpm at 0x38, tracks
from 0x308 (0x388 in the newer variant), each with a 12-byte header; delta times are
variable-length numbers with the groups in little-endian order and the high bit marking the
LAST byte; events are plain MIDI with running status.
"""
import heapq
import os
import shutil
import struct
import subprocess
import wave

# ------------------------------------------------------------------------------------- MIDI out


def _vlq(n):
    out = [n & 0x7f]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7f))
        n >>= 7
    return bytes(reversed(out))


def _read_vlq(d, p):
    n = 0
    while True:
        b = d[p]
        p += 1
        n = (n << 7) | (b & 0x7f)
        if not b & 0x80:
            return n, p


class Track:
    """absolute-time MIDI events -> track chunk"""

    def __init__(self):
        self.events = []      # (time, order, bytes)
        self.n = 0

    def add(self, t, data):
        self.events.append((t, self.n, bytes(data)))
        self.n += 1

    def chunk(self):
        out, last = bytearray(), 0
        for t, _, data in sorted(self.events):
            if data[:2] == b"\xff\x2f":
                continue
            out += _vlq(t - last) + data
            last = t
        end = max([t for t, _, _ in self.events], default=0)
        out += _vlq(end - last) + b"\xff\x2f\x00"
        return b"MTrk" + struct.pack(">I", len(out)) + bytes(out)


def midi_file(tracks, division, tempo_us=None):
    """standard MIDI file (format 0 for one track, 1 otherwise)"""
    if tempo_us:
        tracks[0].add(0, b"\xff\x51\x03" + struct.pack(">I", tempo_us)[1:])
    fmt = 0 if len(tracks) == 1 else 1
    return b"MThd" + struct.pack(">IHHH", 6, fmt, len(tracks), division) + b"".join(t.chunk() for t in tracks)


_DATA_LEN = {0x80: 2, 0x90: 2, 0xa0: 2, 0xb0: 2, 0xc0: 1, 0xd0: 1, 0xe0: 2}

# ----------------------------------------------------------------------------------------- XMIDI


def _iff(d, p, end):
    while p + 8 <= end:
        cid, size = d[p:p + 4], struct.unpack_from(">I", d, p + 4)[0]
        yield cid, p + 8, min(p + 8 + size, end)
        p += 8 + size + (size & 1)


def xmi_sequences(d):
    """the EVNT data of every sequence of an XMIDI file"""
    out = []

    def walk(p, end):
        for cid, a, b in _iff(d, p, end):
            if cid in (b"FORM", b"CAT ") and d[a:a + 4] == b"XMID":
                if cid == b"FORM":
                    for c2, a2, b2 in _iff(d, a + 4, b):
                        if c2 == b"EVNT":
                            out.append(d[a2:b2])
                else:
                    walk(a + 4, b)
            elif cid == b"FORM" and d[a:a + 4] == b"XDIR":
                continue
    walk(0, len(d))
    return out


def xmi_to_midi(evnt):
    """one XMIDI sequence -> MIDI file bytes"""
    tr, t, p, offs = Track(), 0, 0, []
    while p < len(evnt):
        b = evnt[p]
        if b < 0x80:                       # delay: sum of bytes below 0x80
            t += b
            p += 1
            continue
        while offs and offs[0][0] <= t:
            ot, _, data = heapq.heappop(offs)
            tr.add(ot, data)
        st = b & 0xf0
        if b == 0xff:
            typ = evnt[p + 1]
            n, q = _read_vlq(evnt, p + 2)
            if typ == 0x2f:
                break
            if typ != 0x51:                # tempo: baked into the delays, see module doc
                tr.add(t, evnt[p:q + n])
            p = q + n
        elif b in (0xf0, 0xf7):
            n, q = _read_vlq(evnt, p + 1)
            tr.add(t, bytes([b]) + _vlq(n) + evnt[q:q + n])
            p = q + n
        elif st == 0x90:
            note, vel = evnt[p + 1], evnt[p + 2]
            dur, q = _read_vlq(evnt, p + 3)
            tr.add(t, evnt[p:p + 3])
            heapq.heappush(offs, (t + dur, len(tr.events), bytes([0x80 | (b & 0xf), note, 0x40])))
            p = q
        elif st in _DATA_LEN:
            tr.add(t, evnt[p:p + 1 + _DATA_LEN[st]])
            p += 1 + _DATA_LEN[st]
        else:
            raise ValueError("XMIDI: unexpected byte 0x%02x at 0x%x" % (b, p))
    while offs:
        ot, _, data = heapq.heappop(offs)
        tr.add(ot, data)
    return midi_file([tr], 60, 500000)        # 60 ticks per quarter at 120 bpm = 120 Hz

# ------------------------------------------------------------------------------------------- HMI


def _midi_events(d, p, end, track, note_durations, hmi_fe=False, delta=_read_vlq, t=0):
    """MIDI events with running status from d[p:end] into track; returns (end time, whether the
    data ended with an end-of-track event)"""
    status, offs, clean = None, [], False
    while p < end:
        dt, p = delta(d, p)
        t += dt
        while offs and offs[0][0] <= t:
            ot, _, data = heapq.heappop(offs)
            track.add(ot, data)
        if p >= end:
            break
        b = d[p]
        if hmi_fe and b == 0xfe:            # HMI's own events (loop and branch markers)
            sub = d[p + 1]
            p += (d[p + 4] + 5 + 4) if sub == 0x10 else 8 if sub == 0x15 else 4
            continue
        if b == 0xff:
            typ = d[p + 1]
            n, q = _read_vlq(d, p + 2)
            if typ == 0x2f:
                clean = True
                break
            track.add(t, d[p:q + n])
            p = q + n
            continue
        if b in (0xf0, 0xf7):
            n, q = _read_vlq(d, p + 1)
            track.add(t, bytes([b]) + _vlq(n) + d[q:q + n])
            p = q + n
            continue
        if b & 0x80:
            status = b
            p += 1
        elif status is None:
            raise ValueError("running status without a status byte at 0x%x" % p)
        st = status & 0xf0
        if st not in _DATA_LEN:
            raise ValueError("unexpected status 0x%02x at 0x%x" % (status, p))
        args = d[p:p + _DATA_LEN[st]]
        p += _DATA_LEN[st]
        track.add(t, bytes([status]) + args)
        if note_durations and st == 0x90 and args[1]:
            dur, p = _read_vlq(d, p)
            heapq.heappush(offs, (t + dur, len(track.events), bytes([0x80 | (status & 0xf), args[0], 0x40])))
    while offs:
        ot, _, data = heapq.heappop(offs)
        track.add(ot, data)
    return t, clean


def hmi_to_midi(d):
    if not d.startswith(b"HMI-MIDISONG"):
        raise ValueError("not an HMI song")
    bpm = d[0xd4] or 120
    n = d[0xe4]
    offs = [struct.unpack_from("<I", d, 0x172 + 4 * i)[0] for i in range(n)]
    tracks = []
    for i, o in enumerate(offs):
        if d[o:o + 13] != b"HMI-MIDITRACK":
            raise ValueError("HMI: no track header at 0x%x" % o)
        end = offs[i + 1] if i + 1 < n else len(d)
        tr = Track()
        _midi_events(d, o + struct.unpack_from("<I", d, o + 0x57)[0], end, tr, True, hmi_fe=True)
        tracks.append(tr)
    return midi_file(tracks, 60, 60000000 // bpm)

# ------------------------------------------------------------------------------------------- HMP


def _hmp_delta(d, p):
    n, shift = 0, 0
    while True:
        b = d[p]
        p += 1
        n |= (b & 0x7f) << shift
        shift += 7
        if b & 0x80:
            return n, p


def hmp_to_midi(d):
    if not d.startswith(b"HMIMIDIP"):
        raise ValueError("not an HMP file")
    newer = d[8:14] == b"013195"
    chunks = struct.unpack_from("<I", d, 0x30)[0]
    bpm = struct.unpack_from("<I", d, 0x38)[0] or 120
    p = 0x388 if newer else 0x308
    tracks = []
    for _ in range(chunks):
        if p + 12 > len(d):
            break
        _, length, _ = struct.unpack_from("<III", d, p)
        tr = Track()
        _midi_events(d, p + 12, min(p + length, len(d)), tr, False, delta=_hmp_delta)
        tracks.append(tr)
        p += length
    return midi_file(tracks, 60, 60000000 // bpm)

# ------------------------------------------------------------------------------------------- VOC


def voc_to_wav(d, out_path):
    """Creative Voice File -> WAV (8-bit unsigned / 16-bit signed PCM; ADPCM blocks are
    reported, not decoded). Returns a short description."""
    if not d.startswith(b"Creative Voice File\x1a"):
        raise ValueError("not a VOC file")
    p = struct.unpack_from("<H", d, 20)[0]
    rate, bits, channels, pcm, notes = None, 8, 1, bytearray(), []
    ext = None
    while p < len(d) and d[p] != 0:
        typ = d[p]
        size = d[p + 1] | d[p + 2] << 8 | d[p + 3] << 16
        body = d[p + 4:p + 4 + size]
        p += 4 + size
        if typ == 1:
            div, codec = body[0], body[1]
            if ext:
                rate, channels = ext
                ext = None
            else:
                rate, channels = 1000000 // (256 - div), 1
            if codec == 0:
                bits = 8
                pcm += body[2:]
            elif codec == 4:
                bits = 16
                pcm += body[2:]
            else:
                notes.append("ADPCM block (codec %d) skipped" % codec)
        elif typ == 2:
            pcm += body
        elif typ == 3:
            n, div = struct.unpack_from("<HB", body, 0)
            rate = rate or 1000000 // (256 - div)
            pcm += (b"\x80" if bits == 8 else b"\0\0") * (n + 1) * channels
        elif typ == 8:
            tc, _, mode = struct.unpack_from("<HBB", body, 0)
            ch = 2 if mode else 1
            ext = (256000000 // (ch * (65536 - tc)), ch)
        elif typ == 9:
            rate, b9, channels, codec = struct.unpack_from("<IBBH", body, 0)
            if codec in (0, 4):
                bits = b9
                pcm += body[12:]
            else:
                notes.append("codec %d block skipped" % codec)
        elif typ in (4, 5, 6, 7):
            pass                            # marker, text, repeat: no samples
    if rate is None:
        raise ValueError("VOC without sound data")
    with wave.open(out_path, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(bits // 8)
        w.setframerate(rate)
        w.writeframes(bytes(pcm))
    return "%d Hz, %d-bit, %d channel(s), %.1f s%s" % (rate, bits, channels, len(pcm) / (rate * channels * bits // 8),
                                                    "; " + "; ".join(notes) if notes else "")

# ------------------------------------------------------------------------------------- dispatch


def kind(head):
    """format of a file from its first bytes, or None"""
    if head[:4] == b"FORM" and head[8:12] in (b"XDIR", b"XMID"):
        return "xmi"
    if head.startswith(b"HMI-MIDISONG"):
        return "hmi"
    if head.startswith(b"HMIMIDIP"):
        return "hmp"
    if head.startswith(b"Creative Voice File"):
        return "voc"
    if head[:4] in (b"SMK2", b"SMK4"):
        return "smk"
    if head[:3] == b"BIK":
        return "bik"
    if len(head) >= 6 and struct.unpack_from("<H", head, 4)[0] in (0xAF11, 0xAF12):
        return "flic"
    return None


VIDEO = ("smk", "bik", "flic")


def convert(path, out_dir, ffmpeg=None):
    """convert one file into out_dir; returns [(output path, description)]"""
    with open(path, "rb") as fh:
        d = fh.read()
    k = kind(d[:32])
    stem = os.path.join(out_dir, os.path.splitext(os.path.basename(path))[0])
    os.makedirs(out_dir, exist_ok=True)
    if k == "xmi":
        seqs = xmi_sequences(d)
        out = []
        for i, ev in enumerate(seqs):
            o = stem + ("_%02d" % i if len(seqs) > 1 else "") + ".mid"
            with open(o, "wb") as fh:
                fh.write(xmi_to_midi(ev))
            out.append((o, "XMIDI sequence %d of %d" % (i + 1, len(seqs))))
        return out
    if k in ("hmi", "hmp"):
        o = stem + ".mid"
        with open(o, "wb") as fh:
            fh.write(hmi_to_midi(d) if k == "hmi" else hmp_to_midi(d))
        return [(o, k.upper())]
    if k == "voc":
        o = stem + ".wav"
        return [(o, "VOC " + voc_to_wav(d, o))]
    if k in VIDEO:
        ff = ffmpeg or shutil.which("ffmpeg")
        if not ff:
            return [(None, "%s video: install FFmpeg to convert it" % k)]
        o = stem + ".mp4"
        r = subprocess.run([ff, "-y", "-loglevel", "error", "-i", path, "-pix_fmt", "yuv420p", o],
                           capture_output=True, text=True)
        if r.returncode:
            return [(None, "%s video: ffmpeg failed: %s" % (k, r.stderr.strip()[:200]))]
        return [(o, "%s video" % k)]
    return []


def scan(root):
    """[(path, kind)] of the convertible files under root (or the single file)"""
    paths = [root] if os.path.isfile(root) else [os.path.join(r, f) for r, _, fs in os.walk(root) for f in fs]
    out = []
    for p in sorted(paths):
        try:
            with open(p, "rb") as fh:
                k = kind(fh.read(32))
        except OSError:
            continue
        if k:
            out.append((p, k))
    return out
