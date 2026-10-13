r"""Guess the Watcom calling convention of an LE (DOS/4GW) EXE before importing it.

    python detect_cc.py GAME.EXE        (same as: retrokit info GAME.EXE)

Linear-sweeps the first (code) object with capstone (pip install capstone) and counts
call sites:
  * stack convention (-3s/-5s, cspec "watcom"):     PUSH args; CALL; ADD ESP,n
  * register convention (-3r/-5r, cspec "watcomreg"): MOV EAX/EDX/EBX/ECX,...; CALL; callee RET n
A wrong default cspec makes the decompiler drop call arguments everywhere.
"""
import os
import sys

if len(sys.argv) < 2:
    raise SystemExit(__doc__)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from retrokit.detect import format_convention, watcom_convention  # noqa: E402

try:
    print(format_convention(watcom_convention(sys.argv[1])))
except RuntimeError as e:
    raise SystemExit(str(e))
