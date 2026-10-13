"""retrokit doctor: check everything the pipelines need and say how to fix what is missing."""
import importlib.util
import os
import shutil
import sys

from . import ghidra as gh
from . import paths

OK, WARN, FAIL = "ok", "warn", "FAIL"


def checks(ghidra_dir=None):
    """yields (status, what, detail)"""
    v = sys.version_info
    yield (OK if v >= (3, 10) else FAIL), "Python", "%d.%d.%d%s" % (
        v.major, v.minor, v.micro, "" if v >= (3, 10) else " - need 3.10+")

    if importlib.util.find_spec("capstone"):
        import capstone
        yield OK, "capstone", getattr(capstone, "__version__", "installed")
    else:
        yield FAIL, "capstone", "missing (calling-convention detection, match): pip install capstone"

    try:
        ghidra = gh.find(ghidra_dir)
    except gh.GhidraError as e:
        yield FAIL, "Ghidra", "%s (download 12.x from https://github.com/NationalSecurityAgency/ghidra/releases)" % e
        return
    props = gh.properties(ghidra)
    gv = props.get("application.version", "?")
    yield OK, "Ghidra", "%s at %s" % (gv, ghidra)

    need = int(props.get("application.java.min", "21") or 21)
    java = gh.java_tool("java")
    jv = gh.java_version(java) if java else None
    if jv is None:
        yield FAIL, "Java", "not found: install a JDK %d+ and set JAVA_HOME" % need
    elif jv < need:
        yield FAIL, "Java", "%d at %s - Ghidra %s needs %d+" % (jv, java, gv, need)
    else:
        yield OK, "Java", "%d at %s" % (jv, java)
    javac = gh.java_tool("javac")
    yield (OK if javac else WARN), "JDK (javac, jar)", javac or "missing - needed by install-loader (a JRE is not enough)"

    st = gh.loader_status(ghidra)
    if not st["installed"]:
        yield FAIL, "LE/LX loader", "not installed: retrokit install-loader --ghidra \"%s\"" % ghidra
    elif st["version"] != gv:
        yield FAIL, "LE/LX loader", "built for Ghidra %s, this is %s: retrokit install-loader" % (st["version"], gv)
    else:
        yield OK, "LE/LX loader", "installed for %s" % gv
    if gh.loader_status(ghidra, gh.LEGACY_EXT_NAME)["installed"]:
        yield WARN, "legacy loader", "ghidra-lx-loader is installed but no longer used (remove %s)" % os.path.join(
            ghidra, "Ghidra", "Extensions", gh.LEGACY_EXT_NAME)
    missing = [cid for _, cid, _ in gh.CSPECS if cid not in st["cspecs"]]
    yield (FAIL if missing else OK), "Watcom cspecs", (
        "missing %s: retrokit install-loader" % ", ".join(missing) if missing else ", ".join(st["cspecs"]))

    if os.name != "nt":
        # an unzip that drops the executable bits (Python's zipfile, some file managers) leaves
        # the decompiler and the demangler unrunnable; headless runs then fail at import
        native = [os.path.join(r, f) for r, _, fs in os.walk(os.path.join(ghidra, "Ghidra")) if "%sos%s" % (os.sep, os.sep)
                  in r + os.sep for f in fs if not f.endswith((".txt", ".md", ".html"))]
        bad = [p for p in native if not os.access(p, os.X_OK)]
        support = [os.path.join(ghidra, "support", f) for f in ("analyzeHeadless", "launch.sh")]
        bad += [p for p in support if os.path.exists(p) and not os.access(p, os.X_OK)]
        yield (FAIL if bad else OK), "Ghidra native", (
            "%d files not executable (e.g. %s): chmod +x \"%s\"/support/* and "
            "find \"%s\" -path '*/os/*' -type f -exec chmod +x {} +" % (len(bad), os.path.relpath(bad[0], ghidra), ghidra, ghidra)
            if bad else "%d helpers executable" % len(native))

    scripts = [f for f in os.listdir(paths.GHIDRA_SCRIPTS) if f.endswith(".java")]
    yield (OK if scripts else FAIL), "Ghidra scripts", "%d in %s" % (len(scripts), paths.GHIDRA_SCRIPTS)

    yield (OK if shutil.which("ffmpeg") else WARN), "ffmpeg", shutil.which("ffmpeg") or \
        "not found - only needed for 'retrokit flic video'"
    yield (OK if importlib.util.find_spec("PIL") else WARN), "Pillow", "installed" if importlib.util.find_spec("PIL") \
        else "not installed - PNG output falls back to PPM"


def run(ghidra_dir=None, out=print):
    worst = OK
    for status, what, detail in checks(ghidra_dir):
        out("[%-4s] %-17s %s" % (status, what, detail))
        if status == FAIL:
            worst = FAIL
        elif status == WARN and worst == OK:
            worst = WARN
    out("")
    out({OK: "all good", WARN: "usable (optional parts missing)", FAIL: "fix the FAIL lines first"}[worst])
    return 1 if worst == FAIL else 0
