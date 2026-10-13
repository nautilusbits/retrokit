"""Locations of the files the kit ships next to its Python code."""
import os
import sys

PACKAGE = os.path.dirname(os.path.abspath(__file__))
KIT_ROOT = os.path.dirname(PACKAGE)          # repository checkout (or site-packages)
GHIDRA_SCRIPTS = os.path.join(PACKAGE, "ghidra_scripts")
TOOLS = os.path.join(PACKAGE, "tools")
LE_LOADER = os.path.join(PACKAGE, "le-loader")              # our LE/LX loader extension
CSPECS = os.path.join(LE_LOADER, "data", "languages")       # Watcom compiler specs
KNOWLEDGE = os.path.join(PACKAGE, "knowledge")             # library prototypes (C headers)
SIGS = os.path.join(PACKAGE, "sigs")                       # shipped library signatures


def tool(name):
    return os.path.join(TOOLS, name)


def tool_cmd(name):
    """Command line running a bundled tool with this interpreter. -E ignores PYTHON* variables;
    not -I, which also drops the user site-packages where `pip install --user` put capstone."""
    return [sys.executable, "-E", tool(name)]
