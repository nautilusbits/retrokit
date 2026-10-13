"""Find function-pointer / string-pointer tables in the data object from a DumpFixups dump.

    python find_tables.py [--data-base 0x100000] [decomp/fixups.txt]

The data object start is taken from --data-base, else from memory_blocks.txt next to
fixups.txt (written by ExportDecompiled.java: the largest .objectN block without any
function), else 0x90000.
"""
import os
import sys

args = sys.argv[1:]
data_base = None
if len(args) >= 2 and args[0] == "--data-base":
    data_base = int(args[1], 16)
    args = args[2:]
path = args[0] if args else "decomp/fixups.txt"
if data_base is None:
    blocks = os.path.join(os.path.dirname(os.path.abspath(path)), "memory_blocks.txt")
    if os.path.exists(blocks):
        cands = []
        for line in open(blocks, encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 6 and f[0].startswith(".object") and f[5] == "0":
                cands.append((int(f[2], 16) - int(f[1], 16), int(f[1], 16)))
        if cands:
            data_base = max(cands)[1]
if data_base is None:
    data_base = 0x90000
print("data object base: 0x%x" % data_base)
rows = [l.rstrip("\n").split("\t", 5) for l in open(path, encoding="utf-8", errors="replace")]
rows = [r for r in rows if len(r) == 6]


def runs(items):
    """Group (addr, ...) tuples into runs of consecutive 4-byte slots."""
    out, cur = [], []
    for p in sorted(items):
        if cur and p[0] == cur[-1][0] + 4:
            cur.append(p)
        else:
            if cur:
                out.append(cur)
            cur = [p]
    if cur:
        out.append(cur)
    return sorted(out, key=lambda t: -len(t))


ptrs = [(int(r[0], 16), int(r[1], 16), r[3], r[5]) for r in rows
        if r[3] in ("FUNC", "INFUNC", "CODE?") and int(r[0], 16) >= data_base]
tables = runs(ptrs)
print("function pointers in data: %d, contiguous tables: %d" % (len(ptrs), len(tables)))
for t in tables[:30]:
    kinds = {}
    for p in t:
        kinds[p[2]] = kinds.get(p[2], 0) + 1
    print("table @%08x n=%-4d %-40s first: %s" % (t[0][0], len(t), kinds, " ".join("%x" % p[1] for p in t[:6])))

strs = [(int(r[0], 16), r[5]) for r in rows
        if r[3] == "DATA" and int(r[0], 16) >= data_base and r[5].startswith('"')]
st = runs(strs)
print("\nstring pointer tables: %d" % len(st))
for t in st[:10]:
    print("  @%08x n=%-4d %s" % (t[0][0], len(t), " | ".join(p[1][:24] for p in t[:5])))
