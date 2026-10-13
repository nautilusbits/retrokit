r"""Guess the Watcom calling convention of an LE (DOS/4GW) EXE before importing it.

    python detect_cc.py GAME.EXE

Linear-sweeps the first (code) object with capstone (pip install capstone) and counts
call sites:
  * stack convention (-3s/-5s, cspec "watcom"):     PUSH args; CALL; ADD ESP,n
  * register convention (-3r/-5r, cspec "watcomreg"): MOV EAX/EDX/EBX/ECX,...; CALL; callee RET n
A wrong default cspec makes the decompiler drop call arguments everywhere.
"""
import collections
import os
import sys

if len(sys.argv) < 2:
    raise SystemExit(__doc__)
os.environ["LE_EXE"] = sys.argv[1]
sys.argv = sys.argv[:1]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import le  # noqa: E402  (reads LE_EXE at import)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    raise SystemExit("capstone missing: pip install capstone")

code_idx = next(i for i, o in enumerate(le.objs) if o[2] & 0x4)  # first executable object
vsize, base = le.objs[code_idx][0], le.objs[code_idx][1]
code = le.obj_bytes(code_idx)
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.skipdata = True
ins = list(md.disasm(code, base))

calls = add_esp = reg_setup = push_setup = 0
rets = collections.Counter()
for k, i in enumerate(ins):
    if i.mnemonic == "ret":
        rets["ret " + (i.op_str or "")] += 1
    elif i.mnemonic == "call" and i.op_str.startswith("0x"):
        calls += 1
        if k + 1 < len(ins) and ins[k + 1].mnemonic == "add" and ins[k + 1].op_str.startswith("esp,"):
            add_esp += 1
        prev = ins[max(0, k - 3):k]
        if any(p.mnemonic in ("mov", "xor", "lea") and p.op_str.split(",")[0] in ("eax", "edx", "ebx", "ecx")
               for p in prev):
            reg_setup += 1
        if prev and prev[-1].mnemonic == "push":
            push_setup += 1

print("code object %d @0x%x size 0x%x, %d instructions" % (code_idx + 1, base, vsize, len(ins)))
print("direct calls:                %6d" % calls)
print("  followed by ADD ESP,n:     %6d  (%.0f%%)" % (add_esp, 100.0 * add_esp / max(calls, 1)))
print("  preceded by PUSH:          %6d  (%.0f%%)" % (push_setup, 100.0 * push_setup / max(calls, 1)))
print("  preceded by MOV/LEA/XOR into EAX/EDX/EBX/ECX: %d  (%.0f%%)" % (reg_setup, 100.0 * reg_setup / max(calls, 1)))
print("returns:", ", ".join("%s x%d" % kv for kv in rets.most_common(6)))
if add_esp > 0.4 * calls:
    print("=> stack convention: -Cspec watcom")
else:
    print("=> register convention: -Cspec watcomreg")
