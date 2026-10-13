"""Watcom calling convention of an LE/LX executable, decided before import.

Linear-sweeps the code object with capstone and counts call sites:
  stack convention (-3s/-5s, cspec "watcom"):       PUSH args; CALL; ADD ESP,n
  register convention (-3r/-5r, cspec "watcomreg"): MOV EAX/EDX/EBX/ECX,...; CALL; callee RET n
A wrong default cspec makes the decompiler drop call arguments everywhere.
"""
import collections

from .formats import LinearExecutable


def watcom_convention(path=None, le=None):
    """dict with the call-site statistics and "cspec": "watcom" | "watcomreg"."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    except ImportError:
        raise RuntimeError("capstone missing: pip install capstone")
    le = le or LinearExecutable(path)
    idx = le.code_object()
    vsize, base = le.objects[idx][0], le.objects[idx][1]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    ins = list(md.disasm(le.object_bytes(idx), base))

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
    return {
        "code_object": idx + 1, "code_base": base, "code_size": vsize, "instructions": len(ins),
        "calls": calls, "add_esp": add_esp, "push_setup": push_setup, "reg_setup": reg_setup,
        "returns": rets.most_common(6),
        "cspec": "watcom" if add_esp > 0.4 * calls else "watcomreg",
    }


def format_convention(r):
    pct = lambda n: 100.0 * n / max(r["calls"], 1)  # noqa: E731
    return "\n".join([
        "code object %d @0x%x size 0x%x, %d instructions" % (r["code_object"], r["code_base"], r["code_size"],
                                                            r["instructions"]),
        "direct calls:                %6d" % r["calls"],
        "  followed by ADD ESP,n:     %6d  (%.0f%%)" % (r["add_esp"], pct(r["add_esp"])),
        "  preceded by PUSH:          %6d  (%.0f%%)" % (r["push_setup"], pct(r["push_setup"])),
        "  preceded by MOV/LEA/XOR into EAX/EDX/EBX/ECX: %d  (%.0f%%)" % (r["reg_setup"], pct(r["reg_setup"])),
        "returns: " + ", ".join("%s x%d" % kv for kv in r["returns"]),
        ("=> stack convention: -Cspec watcom" if r["cspec"] == "watcom"
         else "=> register convention: -Cspec watcomreg"),
    ])
