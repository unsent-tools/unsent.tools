#!/usr/bin/env python3
"""Generate data.js for the unicode tool from UCD data files.

Usage: python3 build-data.py /path/to/ucd-dir > data.js
where the dir holds UnicodeData.txt and Scripts.txt from the SAME Unicode
version as the local Python's unicodedata (checked below); the committed
data.js was built from UCD 15.0.0.

Encoding: one flat string per table, chars from a 64-char alphabet carrying
5 bits each (chars 32..63 are continuations). Names are word-index lists
terminated by 0, over a frequency-sorted dictionary; codepoints are stored
as deltas. Category and script tables are boundary lists (delta + index).
"""
import sys, unicodedata, collections

UCD = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ucd"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def varint(v):
    assert v >= 0
    out = []
    while v >= 32:
        out.append(ALPHABET[32 + (v & 31)])
        v >>= 5
    out.append(ALPHABET[v])
    return "".join(out)

# --- Parse UnicodeData.txt ------------------------------------------------
named = []            # (cp, name) for individually named codepoints
cat_points = {}       # cp -> category (for individually listed)
ranges = []           # (first, last, marker_name, category) for First/Last pairs
pending = None
for line in open(f"{UCD}/UnicodeData.txt"):
    f = line.split(";")
    cp, name, cat = int(f[0], 16), f[1], f[2]
    if name.endswith(", First>"):
        pending = (cp, name[1:-8], cat)
        continue
    if name.endswith(", Last>"):
        first, marker, fcat = pending
        assert marker == name[1:-7] and fcat == cat
        ranges.append((first, cp, marker, cat))
        pending = None
        continue
    if name.startswith("<"):  # <control>
        cat_points[cp] = cat
        continue
    named.append((cp, name))
    cat_points[cp] = cat

# --- Algorithmic name ranges: verify the rule against Python ---------------
# Hangul syllables get the composed-jamo name (implemented in JS); other
# non-surrogate, non-private-use ranges are NAME-%04X per Python.
algo_ranges = []
for first, last, marker, cat in ranges:
    if marker == "Hangul Syllable":
        algo_ranges.append((first, last, "HANGUL"))
        continue
    if "Surrogate" in marker or "Private Use" in marker:
        algo_ranges.append((first, last, None))  # unnamed
        for probe in (first, last):
            assert unicodedata.name(chr(probe), None) is None, marker
        continue
    base = marker
    # "CJK Ideograph Extension A" etc. all yield CJK UNIFIED IDEOGRAPH-XXXX;
    # "Tangut Ideograph Supplement" yields TANGUT IDEOGRAPH-XXXX.
    if base.startswith("CJK Ideograph"):
        base = "CJK Unified Ideograph"
    if base.endswith(" Supplement"):
        base = base[: -len(" Supplement")]
    prefix = base.upper().replace(",", "")
    for probe in (first, last, (first + last) // 2):
        expect = "%s-%04X" % (prefix, probe)
        got = unicodedata.name(chr(probe), None)
        # Python's unicodedata only implements the CJK algorithmic range;
        # for Tangut/Khitan/Nushu it returns None. We follow the standard.
        if got is None and not marker.startswith("CJK"):
            sys.stderr.write("note: Python has no name for %s (%s)\n"
                             % (hex(probe), marker))
        else:
            assert got == expect, (marker, hex(probe), got, expect)
    algo_ranges.append((first, last, prefix))

# --- Verify every individual name/category against Python ------------------
for cp, name in named:
    assert unicodedata.name(chr(cp), None) == name, hex(cp)
for cp, cat in cat_points.items():
    assert unicodedata.category(chr(cp)) == cat, hex(cp)

# --- Tokenize names -------------------------------------------------------
def tokenize(cp, name):
    suffix = "-%04X" % cp
    if name.endswith(suffix):
        name = name[: -len(suffix)] + "-#"   # '#' = own codepoint in hex
    return name.split(" ")

freq = collections.Counter()
tokenized = []
for cp, name in named:
    words = tokenize(cp, name)
    tokenized.append((cp, words))
    freq.update(words)
WORDS = [w for w, _ in freq.most_common()]
windex = {w: i for i, w in enumerate(WORDS)}

parts = []
prev = 0
for cp, words in tokenized:
    parts.append(varint(cp - prev))
    prev = cp
    for w in words:
        parts.append(varint(windex[w] + 1))
    parts.append(varint(0))
NAMES = "".join(parts)

# --- Category boundary table ----------------------------------------------
CATS = sorted({*cat_points.values(), *(c for *_, c in ranges), "Cn"})
cindex = {c: i for i, c in enumerate(CATS)}
def cat_of(cp):
    if cp in cat_points:
        return cat_points[cp]
    for first, last, _, cat in ranges:
        if first <= cp <= last:
            return cat
    return "Cn"

bounds = []
prevcat = None
for cp in range(0x110000):
    c = cat_of(cp) if (cp in cat_points) or any(f <= cp <= l for f, l, *_ in ranges) else "Cn"
    if c != prevcat:
        bounds.append((cp, c))
        prevcat = c
# The loop above is O(ranges) per cp; fine for a build script but slow in
# pure form — build a flat array instead for speed.
flat = ["Cn"] * 0x110000
for cp, c in cat_points.items():
    flat[cp] = c
for first, last, _, cat in ranges:
    for cp in range(first, last + 1):
        flat[cp] = cat
bounds = []
prevcat = None
for cp, c in enumerate(flat):
    if c != prevcat:
        bounds.append((cp, c))
        prevcat = c
parts = []
prev = 0
for cp, c in bounds:
    parts.append(varint(cp - prev))
    parts.append(varint(cindex[c]))
    prev = cp
CATBOUNDS = "".join(parts)

# --- Script ranges --------------------------------------------------------
script_flat = {}
for line in open(f"{UCD}/Scripts.txt"):
    line = line.split("#")[0].strip()
    if not line:
        continue
    rng, script = [p.strip() for p in line.split(";")]
    if ".." in rng:
        a, b = [int(x, 16) for x in rng.split("..")]
    else:
        a = b = int(rng, 16)
    for cp in range(a, b + 1):
        script_flat[cp] = script
SCRIPTS = sorted({*script_flat.values(), "Unknown"})
sindex = {s: i for i, s in enumerate(SCRIPTS)}
sbounds = []
prevs = None
for cp in range(0x110000):
    s = script_flat.get(cp, "Unknown")
    if s != prevs:
        sbounds.append((cp, s))
        prevs = s
parts = []
prev = 0
for cp, s in sbounds:
    parts.append(varint(cp - prev))
    parts.append(varint(sindex[s]))
    prev = cp
SCRIPTBOUNDS = "".join(parts)

# --- Emit -----------------------------------------------------------------
import json
out = sys.stdout
out.write("// Generated by build-data.py from UCD %s — do not edit.\n"
          % unicodedata.unidata_version)
out.write('export const UNICODE_VERSION = "%s";\n' % unicodedata.unidata_version)
out.write("export const WORDS = %s;\n" % json.dumps(WORDS, separators=(",", ":")))
out.write('export const NAMES = "%s";\n' % NAMES)
out.write("export const ALGO_RANGES = %s;\n"
          % json.dumps([[f, l, p] for f, l, p in algo_ranges], separators=(",", ":")))
out.write("export const CATS = %s;\n" % json.dumps(CATS, separators=(",", ":")))
out.write('export const CATBOUNDS = "%s";\n' % CATBOUNDS)
out.write("export const SCRIPTS = %s;\n" % json.dumps(SCRIPTS, separators=(",", ":")))
out.write('export const SCRIPTBOUNDS = "%s";\n' % SCRIPTBOUNDS)
sys.stderr.write("named=%d words=%d ranges=%d catbounds=%d scriptbounds=%d\n"
                 % (len(named), len(WORDS), len(algo_ranges), len(bounds), len(sbounds)))
