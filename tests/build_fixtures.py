"""Build the synthetic test binaries with Open Watcom (dev/CI dependency only).

    python tests/build_fixtures.py [--watcom DIR] [--out DIR] [variant ...]

Open Watcom is found via --watcom or $WATCOM. Every variant is written to
<out>/<variant>/ (default tests/fixtures/build) as engine.exe + engine.map (the
linker map is the ground truth for tests/evaluate.py) + variant.json.
"""
import argparse
import glob
import json
import os
import platform
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "fixtures", "dos", "src")

OPT = "-oneatx"   # the usual release switches of the period
VARIANTS = {
    # name: (wlink system, compiler switches, expected -Cspec, post-processing)
    "dos4g_s": ("dos4g", ["-5s", OPT], "watcom", None),
    "dos4g_r": ("dos4g", ["-5r", OPT], "watcomreg", None),
    "dos32a_r": ("dos32a", ["-5r", OPT], "watcomreg", None),
    "pmodew_s": ("pmodew", ["-5s", OPT], "watcom", None),
    "dos4g_s_od": ("dos4g", ["-5s", "-od"], "watcom", None),
    "nt_s": ("nt", ["-5s", OPT], None, None),          # Win32 PE console program, PE pipeline
    "os2_r": ("os2v2", ["-5r", OPT], "watcomreg", None),  # OS/2 LX: imports from DOSCALLS, 16-bit thunk object
    "dos4g_r_bw": ("dos4g", ["-5r", OPT], "watcomreg", "bwbind"),  # LE behind a DOS/4G-style BW chain
    # TODO: PMODE/W compressed pages (pmwlite is a DOS program, needs DOSBox to run)
}


def host_bin(watcom):
    sysname = platform.system()
    cands = {"Windows": ["binnt64", "binnt"], "Linux": ["binl64", "binl"]}.get(sysname, [])
    for c in cands:
        if os.path.exists(os.path.join(watcom, c, "wcl386" + (".exe" if sysname == "Windows" else ""))):
            return os.path.join(watcom, c)
    sys.exit("no Open Watcom host binaries for %s under %s" % (sysname, watcom))


def build(watcom, out, name):
    system, cflags, cspec, post = VARIANTS[name]
    vdir = os.path.join(out, name)
    shutil.rmtree(vdir, ignore_errors=True)
    os.makedirs(vdir)
    hb = host_bin(watcom)
    target = {"nt": "nt", "os2v2": "os2"}.get(system, "dos")
    inc = [os.path.join(watcom, "h")] + ([os.path.join(watcom, "h", target)] if target != "dos" else [])
    env = dict(os.environ, WATCOM=watcom, INCLUDE=os.pathsep.join(inc))
    env["PATH"] = hb + os.pathsep + os.path.join(watcom, "binw") + os.pathsep + env.get("PATH", "")
    srcs = sorted(glob.glob(os.path.join(SRC, "*.c")))
    cmd = [os.path.join(hb, "wcl386"), "-q", "-bt=" + target, "-l=" + system, "-fe=engine.exe",
           "-fm=engine.map", "-i=" + SRC] + cflags + srcs
    subprocess.run(cmd, cwd=vdir, env=env, check=True)
    if post == "bwbind":
        bw_bind(os.path.join(vdir, "engine.exe"))
    if post == "pmwlite":
        subprocess.run([os.path.join(watcom, "binw", "pmwlite"), "/c4", "engine.exe"],
                       cwd=vdir, env=env, check=True, stdout=subprocess.DEVNULL)
    for o in glob.glob(os.path.join(vdir, "*.obj")):
        os.remove(o)
    with open(os.path.join(vdir, "variant.json"), "w") as fh:
        json.dump({"name": name, "system": system, "cflags": cflags, "cspec": cspec,
                   "post": post}, fh, indent=1)
    print("built %-14s %s" % (name, " ".join([system] + cflags + ([post] if post else []))))


def bw_bind(path):
    """Wrap an MZ+LE program the way DOS/4G binds it: an old-style MZ stub (no e_lfanew), a "BW"
    header whose dword at 0x1c points to the next header, then the original program, whose LE
    offsets (data pages, ...) are relative to its own MZ - the case the loaders must handle."""
    with open(path, "rb") as fh:
        prog = fh.read()
    stub = bytearray(0x1f0)
    stub[0:2] = b"MZ"
    struct.pack_into("<HHHHHH", stub, 2, 0x1f0, 1, 0, 2, 0, 0xffff)   # 1 page, 0x1f0 bytes used, 2-para header
    struct.pack_into("<H", stub, 0x18, 0x1c)                      # e_lfarlc != 0x40: no e_lfanew
    bw = bytearray(0x100)
    bw[0:2] = b"BW"
    struct.pack_into("<I", bw, 0x1c, len(stub) + len(bw))
    with open(path, "wb") as fh:
        fh.write(bytes(stub) + bytes(bw) + prog)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watcom", default=os.environ.get("WATCOM"))
    ap.add_argument("--out", default=os.path.join(HERE, "fixtures", "build"))
    ap.add_argument("variants", nargs="*")
    a = ap.parse_args()
    if not a.watcom:
        sys.exit("set WATCOM or pass --watcom")
    for v in a.variants or VARIANTS:
        if v not in VARIANTS:
            sys.exit("unknown variant %s (have: %s)" % (v, ", ".join(VARIANTS)))
        build(os.path.abspath(a.watcom), os.path.abspath(a.out), v)


if __name__ == "__main__":
    main()
