"""Autodesk FLIC (FLI / FLC) decoder for old DOS game movies and sprite animations.

    python flic.py info  <file>
    python flic.py png   <file> <out_dir> [--every N] [--pal6|--pal8]
    python flic.py video <file> <out.ogv|.mp4|.webm> [--fps N] [--scale N] [--ffmpeg PATH] [--pal6|--pal8]

Handles the standard 128-byte header (0xAF11 FLI, 0xAF12 FLC) and the stripped
12-byte header some games use (`u32 12, u16 0xAF12, u16 frames, u16 w, u16 h`,
e.g. intro *.DAT files). Chunk types: 4 COLOR_256, 11 COLOR_64,
7 DELTA_FLC (SS2), 12 DELTA_FLI (LC), 13 BLACK, 15 BYTE_RUN, 16 FLI_COPY;
18 PSTAMP and unknown types are skipped (counted in `info`). The ring frame
(the extra frame after `frames` that loops back to frame 1) is not emitted.

Palette values: FLC stores 0..255, FLI (COLOR_64) 0..63. Some games store VGA
DAC values 0..63 in COLOR_256 chunks: the default `auto` scales a COLOR_256
palette by 255/63 when no entry exceeds 63; force with --pal6 / --pal8.

Pure Python (bytes.translate for the palette lookup); PIL is used for PNG when
installed, otherwise frames are written as binary PPM. `video` pipes raw RGB
frames into ffmpeg. Use `decode_embedded()` for FLIC data inside other files
(sprite banks that animate a bitmap in place).
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from collections import Counter

FRAME = 0xF1FA
PREFIX = 0xF100


class Flic:
    def __init__(self, data: bytes, pal_mode: str = "auto"):
        self.data = data
        self.pal_mode = pal_mode
        size, self.magic = struct.unpack_from("<IH", data, 0)
        self.frames, self.width, self.height = struct.unpack_from("<HHH", data, 6)
        self.speed_ms = 0.0
        if size == 12:                       # stripped header
            self.first = 12
        else:
            if self.magic == 0xAF11:         # FLI: speed in 1/70 s
                self.speed_ms = struct.unpack_from("<H", data, 16)[0] * 1000.0 / 70.0
            else:
                self.speed_ms = float(struct.unpack_from("<I", data, 16)[0])
            oframe1 = struct.unpack_from("<I", data, 80)[0] if self.magic != 0xAF11 else 0
            self.first = oframe1 if oframe1 else 128
        self.pixels = bytearray(self.width * self.height)
        self.palette = bytearray(768)
        self.chunk_counts: Counter = Counter()

    # ------------------------------------------------------------------ chunks
    def _color(self, b: bytes, p: int, six_bit: bool) -> None:
        packets = struct.unpack_from("<H", b, p)[0]
        p += 2
        idx = 0
        vals = []
        for _ in range(packets):
            idx += b[p]
            n = b[p + 1] or 256
            p += 2
            for i in range(n):
                r, g, bb = b[p], b[p + 1], b[p + 2]
                p += 3
                vals.append((idx + i, r, g, bb))
            idx += n
        scale = six_bit
        if not six_bit and self.pal_mode == "auto":
            scale = all(max(v[1:]) <= 63 for v in vals)
        elif self.pal_mode == "6":
            scale = True
        elif self.pal_mode == "8":
            scale = six_bit
        for i, r, g, bb in vals:
            if i < 256:
                if scale:
                    r, g, bb = (r * 255 + 31) // 63, (g * 255 + 31) // 63, (bb * 255 + 31) // 63
                self.palette[i * 3:i * 3 + 3] = bytes((r & 0xFF, g & 0xFF, bb & 0xFF))

    def _delta_flc(self, b: bytes, p: int) -> None:
        w, img = self.width, self.pixels
        lines = struct.unpack_from("<H", b, p)[0]
        p += 2
        y = 0
        while lines > 0:
            while True:
                op = struct.unpack_from("<H", b, p)[0]
                p += 2
                kind = op & 0xC000
                if kind == 0xC000:           # skip lines
                    y += 0x10000 - op
                elif kind == 0x8000:         # last pixel of the line
                    img[y * w + w - 1] = op & 0xFF
                else:
                    break                    # packet count
            x = 0
            row = y * w
            for _ in range(op):
                x += b[p]
                cnt = struct.unpack_from("<b", b, p + 1)[0]
                p += 2
                if cnt > 0:
                    img[row + x:row + x + cnt * 2] = b[p:p + cnt * 2]
                    p += cnt * 2
                    x += cnt * 2
                elif cnt < 0:
                    img[row + x:row + x - cnt * 2] = b[p:p + 2] * (-cnt)
                    p += 2
                    x -= cnt * 2
            y += 1
            lines -= 1

    def _delta_fli(self, b: bytes, p: int) -> None:
        w, img = self.width, self.pixels
        y, lines = struct.unpack_from("<HH", b, p)
        p += 4
        for _ in range(lines):
            packets = b[p]
            p += 1
            x = 0
            row = y * w
            for _ in range(packets):
                x += b[p]
                cnt = struct.unpack_from("<b", b, p + 1)[0]
                p += 2
                if cnt > 0:
                    img[row + x:row + x + cnt] = b[p:p + cnt]
                    p += cnt
                    x += cnt
                elif cnt < 0:
                    img[row + x:row + x - cnt] = bytes([b[p]]) * (-cnt)
                    p += 1
                    x -= cnt
            y += 1

    def _byte_run(self, b: bytes, p: int) -> None:
        w, img = self.width, self.pixels
        o = 0
        for _ in range(self.height):
            p += 1                           # packet count, unreliable - fill the width
            left = w
            while left > 0:
                cnt = struct.unpack_from("<b", b, p)[0]
                p += 1
                if cnt > 0:
                    img[o:o + cnt] = bytes([b[p]]) * cnt
                    p += 1
                    o += cnt
                    left -= cnt
                elif cnt < 0:
                    img[o:o - cnt] = b[p:p - cnt]
                    p -= cnt
                    o -= cnt
                    left += cnt
                else:
                    break

    def _apply_chunks(self, b: bytes, p: int, count: int, end: int) -> None:
        for _ in range(count):
            if p + 6 > end:
                break
            cs, ct = struct.unpack_from("<IH", b, p)
            self.chunk_counts[ct] += 1
            q = p + 6
            if ct == 4:
                self._color(b, q, False)
            elif ct == 11:
                self._color(b, q, True)
            elif ct == 7:
                self._delta_flc(b, q)
            elif ct == 12:
                self._delta_fli(b, q)
            elif ct == 13:
                self.pixels[:] = bytes(len(self.pixels))
            elif ct == 15:
                self._byte_run(b, q)
            elif ct == 16:
                self.pixels[:] = b[q:q + len(self.pixels)]
            if cs < 6:
                break
            p += cs

    # ------------------------------------------------------------------ frames
    def iter_frames(self, include_ring: bool = False):
        """Yield (index, pixels bytes, palette bytes) after each frame."""
        b, o, i = self.data, self.first, 0
        limit = self.frames + (1 if include_ring else 0)
        while o + 6 <= len(b) and i < limit:
            size, magic = struct.unpack_from("<IH", b, o)
            if size < 6:
                break
            if magic == FRAME:
                chunks = struct.unpack_from("<H", b, o + 6)[0]
                self._apply_chunks(b, o + 16, chunks, o + size)
                yield i, bytes(self.pixels), bytes(self.palette)
                i += 1
            o += size

    def rgb(self, pixels: bytes, palette: bytes) -> bytes:
        out = bytearray(len(pixels) * 3)
        out[0::3] = pixels.translate(palette[0::3])
        out[1::3] = pixels.translate(palette[1::3])
        out[2::3] = pixels.translate(palette[2::3])
        return bytes(out)


def decode_embedded(bitmap: bytes, width: int, height: int, data: bytes, offset: int = 0,
                    frames: int | None = None) -> list[bytes]:
    """FLIC frames stored after a bitmap and decoded in place into it: returns the
    bitmap after each frame, starting with the untouched bitmap."""
    f = Flic.__new__(Flic)
    f.data, f.pal_mode = data, "8"
    f.width, f.height = width, height
    f.pixels, f.palette = bytearray(bitmap), bytearray(768)
    f.chunk_counts = Counter()
    f.frames = frames if frames is not None else 1 << 30
    f.first = offset
    return [bytes(bitmap)] + [px for _, px, _ in f.iter_frames()]


# ---------------------------------------------------------------------- CLI
def _save_image(path: str, w: int, h: int, rgb: bytes) -> str:
    try:
        from PIL import Image
        Image.frombytes("RGB", (w, h), rgb).save(path + ".png")
        return path + ".png"
    except ImportError:
        with open(path + ".ppm", "wb") as f:
            f.write(b"P6 %d %d 255\n" % (w, h) + rgb)
        return path + ".ppm"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd, path = argv[0], argv[1]
    opts = argv[2:]
    pal_mode = "6" if "--pal6" in opts else "8" if "--pal8" in opts else "auto"

    def opt(name: str, default):
        return type(default)(opts[opts.index(name) + 1]) if name in opts else default

    fl = Flic(open(path, "rb").read(), pal_mode)
    if cmd == "info":
        n = sum(1 for _ in fl.iter_frames(include_ring=True))
        print("%s: magic %04X, %dx%d, %d frames (+ring: %d decoded), speed %.1f ms, chunks %s" % (
            os.path.basename(path), fl.magic, fl.width, fl.height, fl.frames, n, fl.speed_ms,
            dict(sorted(fl.chunk_counts.items()))))
        return 0
    if cmd == "png":
        out = opts[0] if opts and not opts[0].startswith("--") else os.path.splitext(path)[0]
        os.makedirs(out, exist_ok=True)
        every = opt("--every", 1)
        for i, px, pal in fl.iter_frames():
            if i % every == 0:
                _save_image(os.path.join(out, "%05d" % i), fl.width, fl.height, fl.rgb(px, pal))
        print("%d frames -> %s" % (fl.frames, out))
        return 0
    if cmd == "video":
        out = opts[0]
        fps = opt("--fps", 1000.0 / fl.speed_ms if fl.speed_ms else 15.0)
        scale = opt("--scale", 1)
        ffmpeg = opt("--ffmpeg", shutil.which("ffmpeg") or "ffmpeg")
        vf = ["-vf", "scale=%d:%d:flags=neighbor" % (fl.width * scale, fl.height * scale)] if scale != 1 else []
        codec = ["-c:v", "libtheora", "-q:v", "8"] if out.endswith(".ogv") else []
        proc = subprocess.Popen([ffmpeg, "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                                 "-s", "%dx%d" % (fl.width, fl.height), "-r", str(fps), "-i", "-"]
                                + vf + codec + [out], stdin=subprocess.PIPE)
        for _, px, pal in fl.iter_frames():
            proc.stdin.write(fl.rgb(px, pal))
        proc.stdin.close()
        return proc.wait()
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
