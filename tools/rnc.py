"""Rob Northen Compression (RNC ProPack) method 1 decompressor.

Many DOS-era games store their data files as RNC streams:

    'RNC' 0x01 | ulen BE32 | plen BE32 | ucrc BE16 | pcrc BE16 | leeway | chunks

Some containers prefix the stream with the 8-byte tag "BULLFROG".
Ported from the classic dernc.c (Jon Skeet) semantics, including the
quirk that raw bytes are copied from the bitstream's look-ahead position.
"""
from __future__ import annotations

import struct
import sys

RNC_MAGIC = b"RNC\x01"


class RncError(Exception):
    pass


def crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def _mirror(value: int, bits: int) -> int:
    out = 0
    for _ in range(bits):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


class _BitStream:
    __slots__ = ("data", "pos", "bitbuf", "bitcount")

    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.pos = pos
        self.bitbuf = self._word(pos)
        self.bitcount = 16

    def _word(self, p: int) -> int:
        if p + 1 < len(self.data):
            return self.data[p] | (self.data[p + 1] << 8)
        if p < len(self.data):
            return self.data[p]
        return 0

    def peek(self, mask: int) -> int:
        return self.bitbuf & mask

    def advance(self, n: int) -> None:
        self.bitbuf >>= n
        self.bitcount -= n
        if self.bitcount < 16:
            self.pos += 2
            self.bitbuf |= self._word(self.pos) << self.bitcount
            self.bitcount += 16

    def read(self, n: int) -> int:
        v = self.bitbuf & ((1 << n) - 1)
        self.advance(n)
        return v

    def fix(self) -> None:
        """Re-sync the look-ahead word after raw bytes were consumed at self.pos."""
        self.bitcount -= 16
        self.bitbuf &= (1 << self.bitcount) - 1
        self.bitbuf |= self._word(self.pos) << self.bitcount
        self.bitcount += 16


class _HufTable:
    __slots__ = ("codes", "lengths", "values")

    def __init__(self):
        self.codes: list[int] = []
        self.lengths: list[int] = []
        self.values: list[int] = []

    def read(self, bs: _BitStream) -> None:
        self.codes, self.lengths, self.values = [], [], []
        num = bs.read(5)
        if num == 0:
            return
        leng = [bs.read(4) for _ in range(num)]
        code = 0
        for i in range(1, 17):
            for j in range(num):
                if leng[j] == i:
                    self.codes.append(_mirror(code, i))
                    self.lengths.append(i)
                    self.values.append(j)
                    code += 1
            code <<= 1

    def decode(self, bs: _BitStream) -> int:
        for code, length, value in zip(self.codes, self.lengths, self.values):
            if bs.peek((1 << length) - 1) == code:
                bs.advance(length)
                if value < 2:
                    return value
                value -= 1
                return bs.read(value) | (1 << value)
        raise RncError("bad huffman code")


def is_rnc(data: bytes, offset: int = 0) -> bool:
    return data[offset:offset + 4] == RNC_MAGIC


def header(data: bytes, offset: int = 0) -> tuple[int, int, int, int]:
    """Return (unpacked_len, packed_len, unpacked_crc, packed_crc)."""
    if not is_rnc(data, offset):
        raise RncError("not an RNC stream at offset %d" % offset)
    return struct.unpack_from(">IIHH", data, offset + 4)


def unpack(data: bytes, offset: int = 0, verify: bool = True) -> bytes:
    """Decompress one RNC method-1 stream starting at `offset`."""
    ulen, plen, ucrc, pcrc = header(data, offset)
    start = offset + 18
    packed = data[start:start + plen]
    if len(packed) != plen:
        raise RncError("truncated stream: want %d packed bytes, have %d" % (plen, len(packed)))
    if verify and crc16(packed) != pcrc:
        raise RncError("packed CRC mismatch")

    out = bytearray()
    bs = _BitStream(packed, 0)
    bs.advance(2)
    raw, dist, ln = _HufTable(), _HufTable(), _HufTable()
    while len(out) < ulen:
        raw.read(bs)
        dist.read(bs)
        ln.read(bs)
        count = bs.read(16)
        while True:
            n = raw.decode(bs)
            if n:
                out += packed[bs.pos:bs.pos + n]
                bs.pos += n
                bs.fix()
            count -= 1
            if count <= 0:
                break
            pos = dist.decode(bs) + 1
            n = ln.decode(bs) + 2
            for _ in range(n):
                out.append(out[-pos])
    out = bytes(out[:ulen])
    if verify and crc16(out) != ucrc:
        raise RncError("unpacked CRC mismatch")
    return out


def unpack_file(path: str) -> bytes:
    """Load a file and decompress it if it is RNC (with optional BULLFROG prefix)."""
    data = open(path, "rb").read()
    if data[:8] == b"BULLFROG" and is_rnc(data, 8):
        return unpack(data, 8)
    if is_rnc(data):
        return unpack(data)
    return data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: rnc.py <in.dat> [out.bin]")
        sys.exit(1)
    blob = unpack_file(sys.argv[1])
    if len(sys.argv) > 2:
        open(sys.argv[2], "wb").write(blob)
    print("%d bytes" % len(blob))
