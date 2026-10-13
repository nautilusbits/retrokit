r"""Function starts Ghidra missed in a PE: addresses in the code section not covered by any function of an
ExportDecompiled export that are (1) targets of 32-bit pointers stored in the data sections (handler,
state and vtable tables) or (2) the first instruction after CC/90/00 padding (code reached only
through registers). Output feeds `retrokit reexport WS --entries <file>` (retrokit analyze runs it by itself).

    python -I find_entries.py GAME.EXE <decomp_dir | functions.csv> <out.txt>

Pointers into data that happen to land in code produce a few false starts; Ghidra's
disassembler rejects those that are not code (they show up as "failed" in the entries log).
"""
import bisect
import csv
import os
import sys

if len(sys.argv) != 4:
    raise SystemExit(__doc__)
exe, decomp, out = sys.argv[1:]
data = open(exe, 'rb').read()

PADDING = (0xCC, 0x90, 0x00)
NOT_A_START = (0x00, 0xCC, 0x90, 0xFF)
MIN_GAP = 5

pe = int.from_bytes(data[0x3C:0x40], 'little')
nsec = int.from_bytes(data[pe + 6:pe + 8], 'little')
optsz = int.from_bytes(data[pe + 20:pe + 22], 'little')
image_base = int.from_bytes(data[pe + 24 + 28:pe + 24 + 32], 'little')
IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE = 0x20, 0x40, 0x20000000
sections = []   # (name, va, size, raw offset, characteristics); code is found by flags, not by name
for i in range(nsec):
    s = data[pe + 24 + optsz + 40 * i:pe + 24 + optsz + 40 * (i + 1)]
    name = s[:8].rstrip(b'\0').decode(errors='replace')
    vsize, va, rawsize, raw = (int.from_bytes(s[k:k + 4], 'little') for k in (8, 12, 16, 20))
    flags = int.from_bytes(s[36:40], 'little')
    sections.append((name, image_base + va, min(vsize or rawsize, rawsize), raw, flags))

code = [x for x in sections if x[4] & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)]
if not code:
    raise SystemExit('no code section')
text_name, text_va, text_size, text_raw, _ = code[0]
covered = bytearray(text_size)
fcsv = decomp if decomp.endswith('.csv') else os.path.join(decomp, 'functions.csv')
for r in csv.DictReader(open(fcsv)):
    start = int(r['addr'], 16) - text_va
    if 0 <= start < text_size:
        end = min(start + int(r['size']), text_size)
        covered[start:end] = b'\1' * (end - start)

# (1) pointer tables
found = set()
for name, _, size, raw, flags in sections:
    if not flags & IMAGE_SCN_CNT_INITIALIZED_DATA or flags & IMAGE_SCN_MEM_EXECUTE:
        continue
    buf = data[raw:raw + size]
    for off in range(0, len(buf) - 3, 4):
        v = int.from_bytes(buf[off:off + 4], 'little')
        if text_va <= v < text_va + text_size and not covered[v - text_va]:
            found.add(v)

# (2) gaps after padding
i = 0
while i < text_size:
    if covered[i]:
        i += 1
        continue
    j = i
    while j < text_size and not covered[j]:
        j += 1
    k = i
    while k < j and data[text_raw + k] in PADDING:
        k += 1
    after_pad = k == 0 or data[text_raw + k - 1] in PADDING or (text_va + k) % 16 == 0
    if j - k >= MIN_GAP and after_pad:
        found.add(text_va + k)
    i = j

starts = sorted(v for v in found if data[text_raw + v - text_va] not in NOT_A_START)
with open(out, 'w') as fh:
    fh.write('# %s addresses without' % text_name + ' a function: pointer-table targets and starts after padding\n')
    fh.write('\n'.join('%08x' % v for v in starts) + '\n')
print('candidates:', len(starts), '->', out)
