"""MSVC C++ run-time type information (RTTI) of a 32-bit PE: classes, their vtables and
base classes, read directly from the executable (no Ghidra needed).

    retrokit classes GAME.EXE|WORKSPACE [--json] [--names OUT.csv]

MSVC compiles, for every polymorphic class with RTTI enabled (/GR):
  TypeDescriptor            { void *pVFTable; void *spare; char name[] }      name ".?AVClass@@"
  CompleteObjectLocator     { 0, offset, cdOffset, TypeDescriptor *, ClassHierarchyDescriptor * }
  ClassHierarchyDescriptor  { 0, attributes, numBaseClasses, BaseClassDescriptor **array }
  BaseClassDescriptor       { TypeDescriptor *, numContainedBases, PMD (3 ints), attributes }
and the vtable is preceded by a pointer to the class's CompleteObjectLocator. The class
names are recovered from the decorated names (".?AVCPlayer@@" -> CPlayer,
".?AVInner@Outer@@" -> Outer::Inner); templates keep their decorated form.
"""
import re
import struct

from . import formats


class Image:
    """sections of a PE mapped at their virtual addresses"""

    def __init__(self, data):
        if data[:2] != b"MZ" or len(data) < 0x40:
            raise formats.FormatError("not a PE file")
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise formats.FormatError("not a PE file")
        nsec, opt = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        if struct.unpack_from("<H", data, pe + 24)[0] != 0x10b:
            raise formats.FormatError("only 32-bit PE (PE32)")
        self.base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
        self.sections = []      # (va, bytes, executable)
        for i in range(nsec):
            s = pe + 24 + opt + i * 40
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
            flags = struct.unpack_from("<I", data, s + 36)[0]
            body = data[raw:raw + min(rsize, vsize or rsize)].ljust(vsize or rsize, b"\0")
            self.sections.append((self.base + va, body, bool(flags & 0x20000020)))

    def find(self, va):
        for start, body, x in self.sections:
            if start <= va < start + len(body):
                return start, body, x
        return None

    def u32(self, va):
        s = self.find(va)
        if s is None or va + 4 > s[0] + len(s[1]):
            return None
        return struct.unpack_from("<I", s[1], va - s[0])[0]

    def cstr(self, va, limit=512):
        s = self.find(va)
        if s is None:
            return None
        o = va - s[0]
        e = s[1].find(b"\0", o, o + limit)
        return s[1][o:e].decode("latin-1") if e > o else None

    def is_code(self, va):
        s = self.find(va)
        return s is not None and s[2]

    def is_data(self, va):
        s = self.find(va)
        return s is not None and not s[2]


def class_name(decorated):
    """'.?AVCPlayer@@' -> 'CPlayer', '.?AVInner@Outer@@' -> 'Outer::Inner'"""
    m = re.match(r"^\.\?A[VU](.*)@@$", decorated)
    if not m:
        return decorated
    body = m.group(1)
    if body.startswith("?$"):
        return decorated[4:]              # template: keep it readable but undecorated by hand
    return "::".join(reversed(body.split("@")))


def scan(data):
    """{name: {"type_descriptor", "vtables": [(address, offset, [method addresses])],
    "bases": [names, most derived first, without the class itself]}}"""
    img = Image(data)
    tds = {}
    for start, body, x in img.sections:
        if x:
            continue
        for m in re.finditer(rb"\.\?A[VU][^\x00]{1,400}?@@\x00", body):
            td = start + m.start() - 8
            if img.u32(td + 4) == 0:
                tds[td] = m.group(0)[:-1].decode("latin-1")
    if not tds:
        return {}
    cols = {}
    for start, body, x in img.sections:
        if x:
            continue
        for o in range(0, len(body) - 20, 4):
            sig, off, cd, td, chd = struct.unpack_from("<IIIII", body, o)
            if sig == 0 and td in tds and img.is_data(chd) and img.u32(chd) == 0:
                cols[start + o] = (off, td, chd)
    classes = {}
    for col, (off, td, chd) in cols.items():
        name = class_name(tds[td])
        c = classes.setdefault(name, {"type_descriptor": "%08x" % td, "decorated": tds[td], "vtables": [],
                                      "bases": []})
        if not c["bases"]:
            n, arr = img.u32(chd + 8) or 0, img.u32(chd + 12)
            for i in range(min(n, 64)):
                bcd = img.u32(arr + 4 * i) if arr else None
                btd = img.u32(bcd) if bcd else None
                if btd in tds and btd != td:
                    c["bases"].append(class_name(tds[btd]))
    # vtables: the word before the first entry points at the CompleteObjectLocator
    for start, body, x in img.sections:
        if x:
            continue
        for o in range(0, len(body) - 4, 4):
            v = struct.unpack_from("<I", body, o)[0]
            if v in cols:
                vt = start + o + 4
                methods = []
                a = vt
                while img.is_code(img.u32(a) or 0):     # ends at the next vtable's locator (data)
                    methods.append(img.u32(a))
                    a += 4
                if methods:
                    off, td, _ = cols[v]
                    classes[class_name(tds[td])]["vtables"].append(("%08x" % vt, off, ["%08x" % m for m in methods]))
    return classes


def format_report(classes):
    if not classes:
        return "no MSVC RTTI found (not C++, built without /GR, or not MSVC)"
    out = ["%d classes with RTTI" % len(classes)]
    for name in sorted(classes):
        c = classes[name]
        out.append("%s%s" % (name, " : " + ", ".join(c["bases"]) if c["bases"] else ""))
        for vt, off, methods in c["vtables"]:
            out.append("    vftable %s%s: %d methods  %s" % (vt, " (at +%d)" % off if off else "", len(methods),
                                                           " ".join(methods[:8]) + (" ..." if len(methods) > 8 else "")))
    return "\n".join(out)


def name_proposals(classes, functions=None):
    """[(address, name, confidence, comment)]: vftable labels (V) and names for virtual methods
    that have none yet (G, Class_vfunc_N; a method shared by several classes is named after the
    class with the fewest bases, i.e. the one that introduced it)"""
    functions = functions or {}
    out, owner = [], {}
    for name, c in classes.items():
        ident = re.sub(r"\W", "_", name.replace("::", "__"))
        for vt, off, methods in c["vtables"]:
            out.append((int(vt, 16), "vftable_%s%s" % (ident, "_%d" % off if off else ""), "V",
                        "RTTI vtable of %s" % name))
            for i, m in enumerate(methods):
                a = int(m, 16)
                key = (len(c["bases"]), name)
                if a not in owner or key < owner[a][0]:
                    owner[a] = (key, ident, i, name)
    for a, (_, ident, i, name) in sorted(owner.items()):
        current = functions.get(a, "")
        if current and not re.match(r"(FUN|thunk_FUN)_", current):
            continue
        out.append((a, "%s_vfunc_%d" % (ident, i), "G", "virtual method %d of %s (RTTI)" % (i, name)))
    return out
