"""Locations of the files the kit ships next to its Python code."""
import os

PACKAGE = os.path.dirname(os.path.abspath(__file__))
KIT_ROOT = os.path.dirname(PACKAGE)          # repository checkout (or site-packages)
GHIDRA_SCRIPTS = os.path.join(PACKAGE, "ghidra_scripts")
TOOLS = os.path.join(PACKAGE, "tools")
LOADER = os.path.join(PACKAGE, "ghidra-lx-loader")


def tool(name):
    return os.path.join(TOOLS, name)
