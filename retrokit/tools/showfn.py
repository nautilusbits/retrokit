"""Print decompiled functions by name/address from an ExportDecompiled dump.

    python showfn.py [--dir decomp] FUN_00012345 00023456 ...

--dir may be absolute or relative to the kit root; the .c file is the first
*decompiled.c in that directory (game_decompiled.c, ...).
"""
import glob
import os
import re
import sys

args = sys.argv[1:]
d = "decomp"
if args and args[0] == "--dir":
    d = args[1]
    args = args[2:]
d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", d)
found = sorted(glob.glob(os.path.join(d, "*decompiled.c")))
if not found:
    raise SystemExit("no *decompiled.c in " + os.path.abspath(d))
path = found[0]
text = open(path, encoding="utf-8", errors="replace").read()
blocks = re.split(r"^// =+\n(?=// \S+ @ )", text, flags=re.M)
by_name = {}
for b in blocks:
    m = re.match(r"// (\S+) @ ([0-9a-f]+)", b)
    if m:
        by_name[m.group(1)] = b
        by_name[m.group(2)] = b
        by_name["FUN_" + m.group(2)] = b
for a in args:
    key = a.lower() if not a.startswith("FUN_") else a
    b = by_name.get(a) or by_name.get(key) or by_name.get(key.lstrip("0"))
    if b is None:
        print("// %s: not found" % a)
    else:
        print(b.rstrip() + "\n")
