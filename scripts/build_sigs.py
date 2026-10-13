"""Rebuild the signature files shipped in retrokit/sigs/ (maintainers only).

    python scripts/build_sigs.py --ow2 DIR [--ow19 DIR] [--src NAME=DIR ...] [--out DIR] [only ...]

--ow2/--ow19: Open Watcom 2.0 / 1.9 installations. Their run-time libraries (clib + math3,
math387, the C++ run-time plib) give watcom-<tag>-*.sig.gz.
--src: open-source libraries to compile with Open Watcom 2.0 (both calling conventions, the
usual release switches), e.g. --src zlib-1.1.4=path/to/zlib-1.1.4 --src jpeg-6b=path/to/jpeg-6b.
Known names: zlib-<version>, jpeg-6b. Sources are not downloaded by this script; take them
from the projects' release archives (zlib.net/fossils, ijg.org/files).
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KIT)
from retrokit import sigs  # noqa: E402

CONVENTIONS = {"r": "register", "s": "stack"}
# switch sets games of the period were built with: CPU target x optimisation x stack checks
VARIANTS = [[cpu + conv] + opt + chk for cpu in ("-3", "-5") for opt in (["-ox"], ["-oneatx"])
            for chk in ([], ["-s"]) for conv in CONVENTIONS]

# library sources: files that are not part of the library
ZLIB_SKIP = {"example.c", "minigzip.c", "maketree.c", "infback9.c", "inftree9.c", "enough.c"}
JPEG_LIB = ("jcapimin jcapistd jctrans jcparam jdatadst jcinit jcmaster jcmarker jcmainct jcprepct "
            "jccoefct jccolor jcsample jchuff jcphuff jcdctmgr jfdctfst jfdctflt jfdctint jdapimin "
            "jdapistd jdtrans jdatasrc jdmaster jdinput jdmarker jdhuff jdphuff jdmainct jdcoefct "
            "jdpostct jddctmgr jidctfst jidctflt jidctint jidctred jdsample jdcolor jquant1 jquant2 "
            "jdmerge jcomapi jutils jerror jmemmgr jmemnobs").split()


def host_bin(watcom):
    for c in ("binnt64", "binnt", "binl64", "binl"):
        if glob.glob(os.path.join(watcom, c, "wcc386*")):
            return os.path.join(watcom, c)
    sys.exit("no wcc386 under %s" % watcom)


def env_for(watcom):
    env = dict(os.environ, WATCOM=watcom, INCLUDE=os.path.join(watcom, "h"))
    env["PATH"] = host_bin(watcom) + os.pathsep + os.path.join(watcom, "binw") + os.pathsep + env.get("PATH", "")
    return env


def write(out, found, label):
    sigs.write(out, found, ["label: %s" % label, "built by scripts/build_sigs.py"])
    print("%5d  %s" % (len(found), os.path.basename(out)))


def watcom_runtime(watcom, tag, version, out_dir, only):
    lib = os.path.join(watcom, "lib386")
    sets = {
        "dos-clib3%s": (["dos/clib3%s.lib", "math3%s.lib"], "clib3%s + math3%s, DOS"),
        "math387%s": (["math387%s.lib"], "math387%s (8087 math)"),
        "plib3%s": (["plib3%s.lib"], "plib3%s (C++ run-time)"),
    }
    for key, (libs, what) in sets.items():
        name = "watcom-%s-%s.sig.gz" % (tag, key.replace("%s", ""))
        if only and not any(o in name for o in only):
            continue
        found = []
        for c in CONVENTIONS:
            paths = [os.path.join(lib, l % c) for l in libs]
            if not all(os.path.exists(p) for p in paths):
                continue
            with tempfile.TemporaryDirectory() as tmp:
                exe, mp = sigs.link_reference(watcom, paths, tmp)
                found += sigs.extract(exe, mp)
        if found:
            write(os.path.join(out_dir, name), found,
                  "Open Watcom %s %s, register + stack convention" % (version, what.replace("%s", "")))


def compile_lib(watcom, sources, includes, switches, tmp, defines=()):
    """compile the sources with the switches into one OMF library; returns its path"""
    env = env_for(watcom)
    hb = host_bin(watcom)
    objs = []
    for src in sources:
        obj = os.path.join(tmp, os.path.splitext(os.path.basename(src))[0] + ".obj")
        cmd = [os.path.join(hb, "wcc386"), "-q", "-bt=dos", "-zl", "-fo=" + obj] + switches + \
              ["-i=" + i for i in includes] + ["-d" + d for d in defines] + [src]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=tmp)   # .err files go there
        if r.returncode:
            sys.exit("compile failed: %s\n%s%s" % (src, r.stdout, r.stderr))
        objs.append(obj)
    lib = os.path.join(tmp, "lib%s.lib" % "".join(switches).replace("-", ""))
    subprocess.run([os.path.join(hb, "wlib"), "-q", "-n", lib] + ["+" + o for o in objs], env=env, check=True,
                   capture_output=True)
    return lib


def source_lib(watcom, name, src, out_dir):
    if name.startswith("zlib-"):
        sources = [f for f in sorted(glob.glob(os.path.join(src, "*.c"))) if os.path.basename(f) not in ZLIB_SKIP]
        includes, prep = [src], None
    elif name.startswith("jpeg-"):
        sources = [os.path.join(src, f + ".c") for f in JPEG_LIB]
        includes, prep = [src], ("jconfig.wat", "jconfig.h")
    else:
        sys.exit("unknown source library %s (zlib-<version>, jpeg-6b)" % name)
    found = []
    with tempfile.TemporaryDirectory() as tmp:
        if prep:
            work = os.path.join(tmp, "src")
            shutil.copytree(src, work)
            shutil.copy(os.path.join(work, prep[0]), os.path.join(work, prep[1]))
            sources = [os.path.join(work, os.path.basename(s)) for s in sources]
            includes = [work]
        seen = set()
        for switches in VARIANTS:
            lib = compile_lib(watcom, sources, includes, switches, tmp)
            with tempfile.TemporaryDirectory() as ltmp:
                exe, mp = sigs.link_reference(watcom, [lib], ltmp)
                for sg in sigs.extract(exe, mp):
                    key = (sg.name, tuple(sg.pattern))
                    if key not in seen:      # several switch sets often give the same code
                        seen.add(key)
                        sg.module += " " + "".join(switches)
                        found.append(sg)
    write(os.path.join(out_dir, "%s-ow2.sig.gz" % name), found,
          "%s compiled with Open Watcom 2.0, switches -3/-5 x -ox/-oneatx x stack checks on/off, "
          "register + stack convention" % name)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ow2", required=True)
    ap.add_argument("--ow19")
    ap.add_argument("--src", action="append", default=[], metavar="NAME=DIR")
    ap.add_argument("--out", default=os.path.join(KIT, "retrokit", "sigs"))
    ap.add_argument("only", nargs="*", help="build only files whose name contains one of these")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    watcom_runtime(a.ow2, "ow2", "2.0", a.out, a.only)
    if a.ow19:
        watcom_runtime(a.ow19, "ow19", "1.9", a.out, a.only)
    for spec in a.src:
        name, _, d = spec.partition("=")
        if not a.only or any(o in name for o in a.only):
            source_lib(a.ow2, name, d, a.out)


if __name__ == "__main__":
    main()
