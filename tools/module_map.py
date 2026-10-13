r"""Map decompiled functions to the original source files and modules using assert/log strings
that embed source paths (".\ui\menu.cpp" plus a line number), common in MSVC-era release builds.

    python -I module_map.py <decomp_dir> <out_dir> [--rules rules.tsv]

<decomp_dir> is an ExportDecompiled output (*_decompiled.c, strings.txt).
--rules: lines "regex<TAB>module" matched against the path with forward slashes, first match
wins, '#' starts a comment. Without rules the module is the path's first directory.

Writes:
  <out>/module_map.csv      addr,name,module,file,minline,maxline,nrefs,size,callers,callees
  <out>/modules_summary.md  per-module function counts and address ranges
Functions without a path reference inherit the module when both address neighbours agree
(linkers place object files contiguously); such rows end in "~".
"""
import csv
import os
import re
import sys
from collections import Counter, defaultdict

args = sys.argv[1:]
rules_path = None
if '--rules' in args:
    i = args.index('--rules')
    rules_path = args[i + 1]
    del args[i:i + 2]
if len(args) != 2:
    raise SystemExit(__doc__)
decomp, out = args
os.makedirs(out, exist_ok=True)

rules = []
if rules_path:
    for line in open(rules_path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        rx, module = line.split('\t', 1)
        rules.append((re.compile(rx), module.strip()))


def norm(p):
    return p.replace('\\\\', '\\').replace('\\', '/')


def module_of(path):
    for rx, module in rules:
        if rx.search(path):
            return module
    if rules:
        return '?'
    parts = [p for p in path.split('/') if p not in ('.', '..', '')]
    return parts[0] if len(parts) > 1 else '?'


def num(s):
    try:
        return int(s, 16) if s.lower().startswith('0x') else int(s)
    except ValueError:
        return None


cfile = [f for f in os.listdir(decomp) if f.endswith('decompiled.c')][0]
text = open(os.path.join(decomp, cfile), encoding='utf-8', errors='replace').read()

# string address -> path (Ghidra names string labels s_<text>_<addr>)
addr2path = {}
for line in open(os.path.join(decomp, 'strings.txt'), encoding='utf-8', errors='replace'):
    parts = line.rstrip('\n').split('\t', 2)
    if len(parts) == 3 and re.search(r'\.(cpp|CPP|c|h)\b', parts[2]):
        addr2path[parts[0].lower()] = norm(parts[2])

NUM = r'(?<![A-Za-z0-9_])(0x[0-9a-fA-F]+|\d+)'
hdr = re.compile(r'// (\S+) @ ([0-9a-f]+)\s+size=(\d+)\s+callers=(\d+)\s+callees=(\d+)')
# "line, path" or "path, line"
lit = re.compile(r'(?:' + NUM + r'\s*,\s*)?"((?:[^"\\]|\\.)*\.(?:cpp|CPP|c|h))"\s*(?:,\s*' + NUM + r')?')
sym = re.compile(r'(?:' + NUM + r'\s*,\s*)?\bs_[A-Za-z0-9_.]*?_([0-9a-f]{8})\b\s*(?:,\s*' + NUM + r')?')

rows = []
for b in re.split(r'^// =+\n(?=// \S+ @ )', text, flags=re.M):
    m = hdr.match(b)
    if not m:
        continue
    refs = [(norm(mm.group(2)), mm.group(1) or mm.group(3)) for mm in lit.finditer(b)]
    for mm in sym.finditer(b):
        p = addr2path.get(mm.group(2))
        if p:
            refs.append((p, mm.group(1) or mm.group(3)))
    files = Counter(p for p, _ in refs)
    # inline asserts in headers lose against the .cpp file
    cpps = [p for p, _ in files.most_common() if not p.lower().endswith('.h')]
    f = cpps[0] if cpps else (files.most_common(1)[0][0] if files else '')
    lines = [n for n in (num(l) for p, l in refs if l and p == f) if n is not None]
    rows.append(dict(addr=m.group(2), name=m.group(1), module=module_of(f) if f else '', file=f,
                     minline=min(lines) if lines else '', maxline=max(lines) if lines else '',
                     nrefs=len(refs), size=int(m.group(3)), callers=int(m.group(4)), callees=int(m.group(5))))

rows.sort(key=lambda r: r['addr'])
known = [i for i, r in enumerate(rows) if r['module']]
for a, b in zip(known, known[1:]):
    if rows[a]['module'] != rows[b]['module']:
        continue
    for i in range(a + 1, b):
        rows[i]['module'] = rows[a]['module'] + '~'
        if rows[a]['file'] == rows[b]['file']:
            rows[i]['file'] = rows[a]['file']

with open(os.path.join(out, 'module_map.csv'), 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

per = defaultdict(list)
for r in rows:
    per[r['module'].rstrip('~') or '(unknown)'].append(r)
with open(os.path.join(out, 'modules_summary.md'), 'w', encoding='utf-8') as fh:
    fh.write('# Module map (from source-path strings)\n\n')
    fh.write('"direct" = the function references its source path; "inherited" = between two functions of the module.\n\n')
    fh.write('| module | functions direct / inherited | code range | files |\n|---|---|---|---|\n')
    ordered = sorted(per.items(), key=lambda kv: kv[1][0]['addr'])
    for name, lst in ordered:
        direct = sum(1 for r in lst if not r['module'].endswith('~'))
        nfiles = len(set(r['file'] for r in lst if r['file']))
        fh.write('| %s | %d / %d | 0x%s..0x%s | %d |\n' % (name, direct, len(lst) - direct, lst[0]['addr'], lst[-1]['addr'], nfiles))
    for name, lst in ordered:
        fh.write('\n## %s\n\n' % name)
        byfile = defaultdict(list)
        for r in lst:
            byfile[r['file'] or '(no path ref)'].append(r)
        for fn, l in sorted(byfile.items(), key=lambda kv: kv[1][0]['addr']):
            fh.write('- `%s`: %d functions, 0x%s..0x%s\n' % (fn, len(l), l[0]['addr'], l[-1]['addr']))

print('functions:', len(rows), 'with a path reference:', sum(1 for r in rows if r['nrefs']),
      'with a module:', sum(1 for r in rows if r['module']))
