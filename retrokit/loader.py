"""Build the LE/LX loader extension against a Ghidra install and install it, together with
the Watcom compiler specs.

Needs only a JDK (javac and jar from $JAVA_HOME/bin or PATH), no Gradle. The classes are
compiled against the jars of the given Ghidra, so running it again after a Ghidra update
is all a new version needs.

The extension is retrokit-le-loader (retrokit/le-loader).
"""
import glob
import os
import re
import shutil
import subprocess
import tempfile

from . import ghidra as gh
from . import paths

# the Watcom specs are inserted after this entry of x86:LE:32:default in x86.ldefs
LDEFS_MARKER = '<compiler name="Borland C++" spec="x86borland.cspec" id="borlandcpp"/>'
EXTENSIONS = {gh.EXT_NAME: paths.LE_LOADER}


def _run(cmd, what):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise gh.GhidraError("%s failed:\n%s%s" % (what, r.stdout, r.stderr))


def build(ghidra, out_dir, name=gh.EXT_NAME, log=print):
    """Build the extension directory <out_dir>/<name>; returns its path."""
    src = EXTENSIONS[name]
    props = gh.properties(ghidra)
    version, release = props.get("application.version"), props.get("application.java.compiler", "21")
    javac, jar = gh.java_tool("javac"), gh.java_tool("jar")
    if not javac or not jar:
        raise gh.GhidraError("javac/jar not found: install a JDK %s+ and set JAVA_HOME" % release)
    log("Ghidra %s (java %s) at %s, building %s" % (version, release, ghidra, name))

    cp = [j for top in ("Framework", "Features")
          for j in glob.glob(os.path.join(ghidra, "Ghidra", top, "**", "lib", "*.jar"), recursive=True)]
    libs = [j for j in glob.glob(os.path.join(src, "lib", "*.jar")) if not os.path.basename(j).startswith(name)]
    classes = os.path.join(out_dir, "classes")
    os.makedirs(classes)
    sources = glob.glob(os.path.join(src, "src", "main", "java", "**", "*.java"), recursive=True)
    argfile = os.path.join(out_dir, "sources.txt")
    with open(argfile, "w", encoding="utf-8") as fh:   # javac @argfiles split on whitespace: quote
        fh.write("\n".join('"%s"' % s.replace("\\", "/") for s in sources))
    log("Compiling %d sources..." % len(sources))
    _run([javac, "--release", release, "-encoding", "UTF-8", "-cp", os.pathsep.join(cp + libs), "-d", classes,
          "@" + argfile], "javac")
    resources = os.path.join(src, "src", "main", "resources")
    if os.path.isdir(resources):
        shutil.copytree(resources, classes, dirs_exist_ok=True)
    jar_path = os.path.join(out_dir, name + ".jar")
    _run([jar, "--create", "--file", jar_path, "-C", classes, "."], "jar")

    ext = os.path.join(out_dir, name)
    os.makedirs(os.path.join(ext, "lib"))
    for j in [jar_path] + libs:
        shutil.copy2(j, os.path.join(ext, "lib"))
    for f in ("Module.manifest", "LICENSE", "README.md"):
        if os.path.isfile(os.path.join(src, f)):
            shutil.copy2(os.path.join(src, f), ext)
    for d in ("ghidra_scripts", "data"):
        if os.path.isdir(os.path.join(src, d)):
            shutil.copytree(os.path.join(src, d), os.path.join(ext, d))
    with open(os.path.join(src, "extension.properties"), encoding="utf-8") as fh:
        ep = re.sub(r"(?m)^version=.*$", "version=%s" % version, fh.read())
    with open(os.path.join(ext, "extension.properties"), "w", encoding="utf-8") as fh:
        fh.write(ep)
    return ext


def register_cspecs(ghidra, log=print):
    """Copy the Watcom cspecs next to the x86 language files and register them (idempotent):
    watcom = stack convention default (-3s/-5s), watcomreg = register convention (-3r/-5r)."""
    lang = os.path.join(ghidra, "Ghidra", "Processors", "x86", "data", "languages")
    ldefs = os.path.join(lang, "x86.ldefs")
    with open(ldefs, encoding="utf-8", newline="") as fh:
        xml = fh.read()
    nl = "\r\n" if "\r\n" in xml else "\n"
    for f, cid, cname in gh.CSPECS:
        shutil.copy2(os.path.join(paths.CSPECS, f), lang)
        if 'id="%s"' % cid in xml:
            log("%s compiler spec already registered" % cid)
            continue
        i = xml.find(LDEFS_MARKER)
        if i < 0:
            raise gh.GhidraError("no Borland entry of x86:LE:32:default in %s" % ldefs)
        indent = xml[xml.rfind(nl, 0, i) + len(nl):i]
        entry = '%s%s<compiler name="%s" spec="%s" id="%s"/>' % (nl, indent, cname, f, cid)
        xml = xml[:i + len(LDEFS_MARKER)] + entry + xml[i + len(LDEFS_MARKER):]
        log("registered %s compiler spec in %s" % (cid, ldefs))
    with open(ldefs, "w", encoding="utf-8", newline="") as fh:
        fh.write(xml)


def install(ghidra, build_only=None, name=gh.EXT_NAME, log=print):
    """Build + install into <ghidra>/Ghidra/Extensions; build_only=DIR keeps the build there instead."""
    if build_only:
        if os.path.exists(build_only):
            shutil.rmtree(build_only)
        os.makedirs(build_only)
        ext = build(ghidra, build_only, name, log)
        log("built %s" % ext)
        return ext
    with tempfile.TemporaryDirectory(prefix="retrokit-loader-") as tmp:
        ext = build(ghidra, tmp, name, log)
        target = os.path.join(ghidra, "Ghidra", "Extensions", name)
        if os.path.exists(target):
            shutil.rmtree(target)
        shutil.copytree(ext, target)
        log("installed to %s" % target)
    register_cspecs(ghidra, log)
    return target
