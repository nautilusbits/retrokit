"""End-to-end regression test: build the fixtures, run the pipeline, score, compare.

    python tests/run_tests.py [--ghidra DIR] [--watcom DIR] [--no-build] [--no-analyze]
                              [--jobs N] [--update-baseline] [-v] [variant ...]

Ghidra comes from --ghidra or $GHIDRA_INSTALL_DIR (with the LE loader installed),
Open Watcom from --watcom or $WATCOM (only needed to build). Scores are compared
with tests/baseline.json: a metric that gets worse fails the run, one that gets
better is reported so the baseline can be raised with --update-baseline.
"""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import build_fixtures  # noqa: E402
import check_loader  # noqa: E402
import evaluate  # noqa: E402

BUILD = os.path.join(HERE, "fixtures", "build")
BASELINE = os.path.join(HERE, "baseline.json")
HIGHER = ["own_found", "lib_found", "lib_named", "expect_found", "own_params_ok", "calls_args_ok", "strings_found"]
LOWER = ["own_truncated", "extraout", "unaff", "undefined8", "in_reg", "warnings",
         "extraout_own", "unaff_own", "undefined8_own", "in_reg_own", "warnings_own"]
TOTALS = ["own_total", "lib_total", "calls_total", "strings_total", "expect_total"]


def analyze(ghidra, variant):
    """retrokit analyze with automatic format and calling-convention detection; the detected
    cspec must be the one the variant was compiled for."""
    vdir = os.path.join(BUILD, variant)
    with open(os.path.join(vdir, "variant.json")) as fh:
        spec = json.load(fh)
    out = os.path.join(vdir, "analysis")
    log = os.path.join(vdir, "analyze.log")
    cmd = [sys.executable, "-m", "retrokit", "analyze", os.path.join(vdir, "engine.exe"), "-o", out,
           "--ghidra", ghidra]
    with open(log, "w") as fh:
        r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=KIT)
    if r.returncode:
        raise RuntimeError("%s: retrokit analyze failed (exit %d), see %s" % (variant, r.returncode, log))
    with open(os.path.join(out, "retrokit.json")) as fh:
        detected = json.load(fh).get("cspec")
    if spec["cspec"] and detected != spec["cspec"]:
        raise RuntimeError("%s: detected cspec %s, expected %s" % (variant, detected, spec["cspec"]))
    return variant


def compare(m, base):
    """-> (regressions, improvements)"""
    reg, imp = [], []
    if base is None:
        return ["no baseline"], []
    for k in TOTALS:
        if k not in base and k == "expect_total" and not m[k]:
            continue
        if m[k] != base.get(k):
            reg.append("%s changed %s -> %s (fixture changed? run --update-baseline)" % (k, base.get(k), m[k]))
    for k in HIGHER:
        if k not in base:
            continue
        if m[k] < base[k]:
            reg.append("%s %d -> %d" % (k, base[k], m[k]))
        elif m[k] > base[k]:
            imp.append("%s %d -> %d" % (k, base[k], m[k]))
    for k in LOWER:
        if k not in base:
            continue
        if m[k] > base[k]:
            reg.append("%s %d -> %d" % (k, base[k], m[k]))
        elif m[k] < base[k]:
            imp.append("%s %d -> %d" % (k, base[k], m[k]))
    return reg, imp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    ap.add_argument("--watcom", default=os.environ.get("WATCOM"))
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--no-analyze", action="store_true")
    ap.add_argument("--no-loader-check", action="store_true", help="skip tests/check_loader.py")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("variants", nargs="*")
    a = ap.parse_args()
    variants = a.variants or list(build_fixtures.VARIANTS)

    if not a.no_build:
        if not a.watcom:
            sys.exit("set WATCOM / --watcom, or use --no-build with prebuilt fixtures")
        for v in variants:
            build_fixtures.build(os.path.abspath(a.watcom), BUILD, v)
    failed = False
    if not a.no_analyze and not a.no_loader_check:
        if not a.ghidra:
            sys.exit("set GHIDRA_INSTALL_DIR / --ghidra")
        print("loader check (retrokit-le-loader vs the Python model):")
        failed |= bool(check_loader.check(a.ghidra, variants, out=lambda s: print("  " + s)))
    if not a.no_analyze:
        if not a.ghidra:
            sys.exit("set GHIDRA_INSTALL_DIR / --ghidra")
        with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
            for v in ex.map(lambda v: analyze(a.ghidra, v), variants):
                print("analyzed", v)

    base = {}
    if os.path.exists(BASELINE):
        with open(BASELINE) as fh:
            base = json.load(fh)
    for v in variants:
        m = evaluate.evaluate(os.path.join(BUILD, v))
        print(evaluate.format_metrics(m))
        if a.verbose:
            for i in m["issues"]:
                print("   " + i)
        reg, imp = compare(m, base.get(v))
        for r in reg:
            print("   REGRESSION " + r)
        for i in imp:
            print("   improved   " + i)
        failed |= bool(reg)
        base[v] = {k: m[k] for k in TOTALS + HIGHER + LOWER} if a.update_baseline else base.get(v)
    if a.update_baseline:
        with open(BASELINE, "w") as fh:
            json.dump(base, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print("baseline updated:", BASELINE)
        return 0
    print("FAILED" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
