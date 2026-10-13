"""Check the LE/LX loader: import every built LE/LX fixture with retrokit-le-loader (no analysis),
dump what it produced (ghidra_scripts/DumpLoadedImage.java: blocks + SHA-1 of their bytes,
relocations with the value now at the address, entry point, imports) and compare it with the
independent Python model of the same image (retrokit.formats.LinearExecutable.loaded_image_lines).

    python tests/check_loader.py [--ghidra DIR] [--against LOADER] [--keep DIR] [variant ...]

--against LOADER compares with another installed loader instead of the Python model (e.g. the
legacy LeLoader). Exit code 1 on any difference.
"""
import argparse
import glob
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from retrokit import formats  # noqa: E402
from retrokit import ghidra as gh  # noqa: E402
from retrokit import paths  # noqa: E402

BUILD = os.path.join(HERE, "fixtures", "build")


def ghidra_dump(ghidra, exe, loader, work):
    proj = os.path.join(work, loader)
    os.makedirs(proj, exist_ok=True)
    out = os.path.join(work, loader + ".txt")
    gh.run_headless(ghidra, proj, ["-import", exe, "-loader", loader, "-processor", "x86:LE:32:default",
                                   "-cspec", "watcom", "-noanalysis", "-scriptPath", paths.GHIDRA_SCRIPTS,
                                   "-postScript", "DumpLoadedImage.java", out],
                    os.path.join(work, loader + ".log"), os.path.join(work, loader + "_stdout.log"))
    if not os.path.isfile(out):
        raise gh.GhidraError("%s did not load %s, see %s" % (loader, exe, os.path.join(work, loader + ".log")))
    with open(out) as fh:
        return fh.read().splitlines()


def counts(lines):
    return " ".join("%s %d" % (k, sum(1 for l in lines if l.startswith(k + " ")))
                    for k in ("block", "reloc", "entry", "external"))


def le_variants(names=None):
    for spec_path in sorted(glob.glob(os.path.join(BUILD, "*", "variant.json"))):
        with open(spec_path) as fh:
            spec = json.load(fh)
        if spec.get("cspec") and (not names or spec["name"] in names):
            yield spec["name"], os.path.join(os.path.dirname(spec_path), "engine.exe")


def check(ghidra, names=None, against=None, keep=None, out=print):
    """returns the number of variants with differences"""
    bad = 0
    for name, exe in le_variants(names):
        work = tempfile.mkdtemp(prefix="retrokit-loader-")
        try:
            got = ghidra_dump(ghidra, exe, gh.LOADER_CLASS, work)
            ref = ghidra_dump(ghidra, exe, against, work) if against else \
                formats.LinearExecutable(exe).loaded_image_lines()
            only_got, only_ref = sorted(set(got) - set(ref)), sorted(set(ref) - set(got))
            out("%-12s %s  %s" % (name, counts(got), "== %s" % (against or "python model") if not only_got and
                                  not only_ref else "DIFFERS from %s" % (against or "python model")))
            for l in only_got[:12]:
                out("   loader: " + l)
            for l in only_ref[:12]:
                out("   %s: %s" % (against or "model", l))
            bad += bool(only_got or only_ref)
            if keep:
                dst = os.path.join(keep, name)
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(work, dst)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    ap.add_argument("--against", help="another installed loader instead of the Python model")
    ap.add_argument("--keep", help="keep the dumps in this directory")
    ap.add_argument("variants", nargs="*")
    a = ap.parse_args()
    return 1 if check(gh.find(a.ghidra), a.variants, a.against, a.keep) else 0


if __name__ == "__main__":
    sys.exit(main())
