"""Locating Ghidra and Java, running analyzeHeadless, checking its logs."""
import os
import re
import shutil
import subprocess

from . import paths

EXT_NAME = "ghidra-lx-loader"
CSPECS = [  # file, id, display name
    ("x86watcom.cspec", "watcom", "Watcom C"),
    ("x86watcom_reg.cspec", "watcomreg", "Watcom C (register)"),
]
LOG_ERRORS = re.compile(r"REPORT SCRIPT ERROR|SCRIPT ERROR|\berror: |GhidraScriptLoadException|Unable to lock")


class GhidraError(Exception):
    pass


def headless_name():
    return "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"


def is_ghidra(d):
    return bool(d) and os.path.isfile(os.path.join(d, "support", headless_name())) and \
        os.path.isfile(os.path.join(d, "Ghidra", "application.properties"))


def find(explicit=None, near=None):
    """Ghidra install dir: explicit, $GHIDRA_INSTALL_DIR, then ghidra*/ next to the kit or the
    target (e.g. <game>\\ghidra beside <game>\\GAME.EXE)."""
    cands = [explicit, os.environ.get("GHIDRA_INSTALL_DIR")]
    for base in filter(None, [near, paths.KIT_ROOT, os.path.dirname(paths.KIT_ROOT)]):
        for parent in (base, os.path.dirname(base)):
            cands.append(os.path.join(parent, "ghidra"))
            try:
                cands += sorted((os.path.join(parent, n) for n in os.listdir(parent)
                                 if n.lower().startswith("ghidra_")), reverse=True)
            except OSError:
                pass
    for c in cands:
        if c and is_ghidra(c):
            return os.path.abspath(c)
    if explicit:
        raise GhidraError("not a Ghidra install (no support/%s): %s" % (headless_name(), explicit))
    raise GhidraError("Ghidra not found: pass --ghidra DIR or set GHIDRA_INSTALL_DIR")


def properties(ghidra):
    props = {}
    with open(os.path.join(ghidra, "Ghidra", "application.properties"), encoding="utf-8") as fh:
        for line in fh:
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
    return props


def version(ghidra):
    return properties(ghidra).get("application.version", "?")


def java_tool(name):
    """Path of a JDK tool (java, javac, jar): $JAVA_HOME/bin first, then PATH."""
    exe = name + (".exe" if os.name == "nt" else "")
    home = os.environ.get("JAVA_HOME")
    if home and os.path.isfile(os.path.join(home, "bin", exe)):
        return os.path.join(home, "bin", exe)
    return shutil.which(name)


def java_version(java):
    try:
        out = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=30).stderr
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r'version "(\d+)(?:\.(\d+))?', out)
    if not m:
        return None
    major = int(m.group(1))
    return int(m.group(2)) if major == 1 and m.group(2) else major


def loader_status(ghidra):
    """dict: installed (bool), version (extension.properties) and registered cspec ids."""
    ext = os.path.join(ghidra, "Ghidra", "Extensions", EXT_NAME)
    st = {"installed": os.path.isdir(ext), "version": None, "cspecs": []}
    props = os.path.join(ext, "extension.properties")
    if os.path.isfile(props):
        with open(props, encoding="utf-8") as fh:
            m = re.search(r"(?m)^version=(.*)$", fh.read())
            st["version"] = m.group(1).strip() if m else None
    lang = os.path.join(ghidra, "Ghidra", "Processors", "x86", "data", "languages")
    try:
        with open(os.path.join(lang, "x86.ldefs"), encoding="utf-8") as fh:
            ldefs = fh.read()
        st["cspecs"] = [cid for f, cid, _ in CSPECS
                        if 'id="%s"' % cid in ldefs and os.path.isfile(os.path.join(lang, f))]
    except OSError:
        pass
    return st


def check_log(log, returncode):
    errs = []
    if os.path.isfile(log):
        with open(log, encoding="utf-8", errors="replace") as fh:
            errs = [l.rstrip() for l in fh if LOG_ERRORS.search(l)]
    if errs or returncode:
        raise GhidraError("headless Ghidra failed (exit %s), see %s\n%s" % (returncode, log, "\n".join(errs[:10])))


def run_headless(ghidra, project_dir, args, log, stdout_log, quiet=False):
    """analyzeHeadless <project_dir> Game <args> -log <log>; raises GhidraError on script errors."""
    cmd = [os.path.join(ghidra, "support", headless_name()), project_dir, "Game"] + list(args) + ["-log", log]
    with open(stdout_log, "w", encoding="utf-8", errors="replace") as out:
        r = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    check_log(log, r.returncode)
    return r.returncode


def log_lines(log, pattern):
    if not os.path.isfile(log):
        return []
    rx = re.compile(pattern)
    with open(log, encoding="utf-8", errors="replace") as fh:
        return [re.sub(r"^.*?\(GhidraScript\)\s*", "", l.rstrip()) for l in fh if rx.search(l)]
