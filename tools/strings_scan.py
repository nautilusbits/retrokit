"""Quick string inventory of a PE without Ghidra: ASCII + UTF-16LE strings,
source-path/assert strings, .txt table names, file extensions.
    python -I strings_scan.py Game.exe out_dir
"""
import re, sys, collections, os
exe, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
data = open(exe, 'rb').read()
base = 0x400000
# section table for VA mapping
pe = int.from_bytes(data[0x3c:0x40], 'little')
nsec = int.from_bytes(data[pe+6:pe+8], 'little')
optsz = int.from_bytes(data[pe+20:pe+22], 'little')
secs = []
for i in range(nsec):
    s = data[pe+24+optsz+40*i: pe+24+optsz+40*(i+1)]
    name = s[:8].rstrip(b'\0').decode()
    va, rawsz, rawp = int.from_bytes(s[12:16],'little'), int.from_bytes(s[16:20],'little'), int.from_bytes(s[20:24],'little')
    secs.append((name, va, rawsz, rawp))
def off2va(o):
    for name, va, rawsz, rawp in secs:
        if rawp <= o < rawp+rawsz: return base+va+(o-rawp)
    return None
asc = [(m.start(), m.group().decode()) for m in re.finditer(rb'[\x20-\x7e]{5,}', data)]
uni = [(m.start(), m.group().decode('utf-16le')) for m in re.finditer(rb'(?:[\x20-\x7e]\x00){5,}', data)]
with open(os.path.join(out, 'strings_raw.txt'), 'w', encoding='utf-8') as f:
    for kind, lst in (('A', asc), ('U', uni)):
        for o, s in lst:
            va = off2va(o)
            f.write('%s\t%s\t%s\n' % (kind, '0x%08x' % va if va else 'off%08x' % o, s))
print('ascii>=5:', len(asc), 'utf16>=5:', len(uni))
src = [(o, s) for o, s in asc if re.search(r'\.(cpp|c|h)\b', s, re.I)]
print('source-path strings:', len(src))
with open(os.path.join(out, 'strings_sourcepaths.txt'), 'w') as f:
    for o, s in src: f.write('0x%08x\t%s\n' % (off2va(o) or o, s))
txt = sorted(set(s for o, s in asc+uni if re.search(r'\.txt$', s, re.I)))
with open(os.path.join(out, 'strings_txt_tables.txt'), 'w') as f: f.write('\n'.join(txt))
print('txt names:', len(txt))
ext = collections.Counter()
for o, s in asc+uni:
    m = re.search(r'\.([a-z0-9]{2,4})$', s, re.I)
    if m and len(s) < 60: ext[m.group(1).lower()] += 1
print(ext.most_common(45))
