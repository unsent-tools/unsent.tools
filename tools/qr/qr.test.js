// Tests for qr.js. Three independent oracles:
//
//  - segno (Python): exact full-matrix differentials, forced and automatic
//    version/mask. One deviation is patched in the prelude below: segno's
//    write_padding_bits unconditionally appends `8 - len % 8` zero bits, so
//    a data stream that already ends on a codeword boundary gets a spurious
//    0x00 pad codeword. ISO/IEC 18004 §7.4.10 pads "if the bit stream
//    length is such that it does not end at a codeword boundary" — i.e. not
//    when aligned (the reference qrcodegen appends (8 - len % 8) % 8).
//    Decoders ignore padding, so segno's symbols still scan; but for
//    bit-identical comparison the patch restores the ISO behaviour.
//  - zbar (C): every generated symbol must actually scan, and must decode
//    to the exact input bytes. zbar shares no code or tables with segno.
//  - qrencode (C): a third independent generator; its symbols and ours must
//    decode identically.
//
// Plus pinned ISO vectors (RS generator polynomial, version-info code) and
// intrinsic code properties (BCH minimum distances).

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  encode, toSvg, toText, chooseMode, countBits, capacityBits, penalty,
  rsGeneratorPoly, rsRemainder, formatInfoBits, versionInfoBits,
  QrError, EC_BLOCKS, ALIGN_POS, LEVELS,
} from "./qr.js";

const PY_PRELUDE = `
import json, sys
import segno
from segno import encoder

_orig_wpb = encoder.write_padding_bits
def _iso_wpb(buff, version, length):
    if length % 8:
        _orig_wpb(buff, version, length)
encoder.write_padding_bits = _iso_wpb

def matrix_str(q):
    return '\\n'.join(''.join('#' if v else '.' for v in row) for row in q.matrix)
`;

const py = (script, input) =>
  execFileSync("python3", ["-c", PY_PRELUDE + script], {
    encoding: "utf8",
    input: input === undefined ? "" : JSON.stringify(input),
    maxBuffer: 64 * 1024 * 1024,
  });

// Deterministic PRNG so failures reproduce.
function makeRng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s;
  };
}

// ---------------------------------------------------------------- helpers

// Render a matrix to a PBM file zbar can read: scale 4, quiet zone 4.
function writePbm(path, matrix) {
  const size = matrix.length, border = 4, scale = 4;
  const dim = (size + 2 * border) * scale;
  const rows = [`P1`, `${dim} ${dim}`];
  for (let y = 0; y < dim; y++) {
    const my = Math.floor(y / scale) - border;
    let line = "";
    for (let x = 0; x < dim; x++) {
      const mx = Math.floor(x / scale) - border;
      line += my >= 0 && my < size && mx >= 0 && mx < size && matrix[my][mx] ? "1" : "0";
    }
    rows.push(line);
  }
  writeFileSync(path, rows.join("\n") + "\n");
}

function zbarDecode(path) {
  // --raw: undecorated output; zbar appends one newline per symbol.
  const out = execFileSync("zbarimg", ["-q", "--raw", path]);
  return out.subarray(0, out.length - 1);
}

const utf8 = (s) => Buffer.from(s, "utf8");

// ------------------------------------------------- structure differential

test("all 40 versions x 4 levels match segno bit for bit (forced mask)", () => {
  // "AB12cd" forces byte mode and its stream ends codeword-aligned, so this
  // also exercises the padding path the segno patch is about, at every
  // version: block splits, interleaving, alignment patterns, version info.
  const out = py(`
res = []
for v in range(1, 41):
    for level in 'lmqh':
        q = segno.make('AB12cd', version=v, error=level, mask=3, boost_error=False, micro=False)
        res.append(matrix_str(q))
print(json.dumps(res))
`);
  const expected = JSON.parse(out);
  let i = 0;
  for (let v = 1; v <= 40; v++) {
    for (const level of LEVELS) {
      const r = encode("AB12cd", { version: v, level, mask: 3 });
      assert.equal(r.version, v);
      assert.equal(toText(r.matrix), expected[i], `version ${v} level ${level}`);
      i++;
    }
  }
});

test("automatic version and mask match segno on random inputs", () => {
  const rng = makeRng(0xc0dec0de);
  const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
  const bytesCs = "abcdefghijklmnop QRSTUV{}~#@!\"'\\\n\t";
  const cases = [];
  for (let i = 0; i < 24; i++) {
    const kind = i % 3;
    const len = (rng() % (kind === 0 ? 900 : 500)) + 1;
    let s = "";
    if (kind === 0) for (let j = 0; j < len; j++) s += rng() % 10;
    else if (kind === 1) for (let j = 0; j < len; j++) s += alnum[rng() % alnum.length];
    else for (let j = 0; j < len; j++) s += bytesCs[rng() % bytesCs.length];
    cases.push({ text: s, level: LEVELS[rng() % 4] });
  }
  const out = py(`
cases = json.load(sys.stdin)
res = []
for c in cases:
    q = segno.make(c['text'], error=c['level'].lower(), boost_error=False, micro=False)
    res.append({'version': q.version, 'mask': q.mask, 'matrix': matrix_str(q)})
print(json.dumps(res))
`, cases);
  const expected = JSON.parse(out);
  cases.forEach((c, i) => {
    const r = encode(c.text, { level: c.level });
    assert.equal(r.version, expected[i].version, `case ${i}: version`);
    assert.equal(r.mask, expected[i].mask, `case ${i}: mask (penalty scoring)`);
    assert.equal(toText(r.matrix), expected[i].matrix, `case ${i}: matrix`);
  });
});

// ------------------------------------------------------ zbar round-trips

test("every symbol scans and round-trips through zbar exactly", () => {
  const dir = mkdtempSync(join(tmpdir(), "qr-test-"));
  try {
    const inputs = [
      ["https://unsent.tools/tools/qr/", "M"],
      ["HELLO WORLD", "Q"],
      ["12345678901234567890", "L"],
      ["héllo wörld — Grüße aus Тбилиси ☂ 日本語 🎉", "M"],
      ["WIFI:T:WPA;S:my net;P:hunter2 hunter2;;", "Q"],
      ["a", "H"],
      ["0", "L"],
      [" ", "M"], // single space: alphanumeric mode
      ["x".repeat(1200), "M"], // deep into the big versions
      ["9".repeat(3000), "Q"], // long numeric
      ["MAILTO:SOMEONE@EXAMPLE.ORG", "H"],
      ["line one\nline two\r\nline three\ttabbed", "M"],
    ];
    inputs.forEach(([text, level], i) => {
      const r = encode(text, { level });
      const path = join(dir, `t${i}.pbm`);
      writePbm(path, r.matrix);
      assert.deepEqual(zbarDecode(path), utf8(text), `input ${i} (v${r.version}${level})`);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("qrencode (independent generator) and we decode identically", () => {
  const dir = mkdtempSync(join(tmpdir(), "qr-test-"));
  try {
    const inputs = [["Compare me: both generators must scan alike.", "M"],
                    ["https://example.org/?a=1&b=2#frag", "H"]];
    inputs.forEach(([text, level], i) => {
      const theirs = join(dir, `q${i}.png`);
      execFileSync("qrencode", ["-8", "-l", level, "-o", theirs, text]);
      const r = encode(text, { level });
      const ours = join(dir, `o${i}.pbm`);
      writePbm(ours, r.matrix);
      assert.deepEqual(zbarDecode(ours), zbarDecode(theirs), `input ${i}`);
      assert.deepEqual(zbarDecode(ours), utf8(text), `input ${i} payload`);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------- pinned vectors

test("RS generator polynomial degree 7 matches the published table", () => {
  // ISO/IEC 18004 Annex A / Thonky table: g7(x) coefficients as integers.
  assert.deepEqual(Array.from(rsGeneratorPoly(7)), [1, 127, 122, 154, 164, 11, 68, 117]);
});

test("RS arithmetic matches an independent GF(256) implementation", () => {
  const rng = makeRng(0x5eed);
  const cases = [];
  for (let i = 0; i < 40; i++) {
    const degree = [7, 10, 13, 15, 16, 17, 18, 20, 22, 24, 26, 28, 30][rng() % 13];
    const len = (rng() % 60) + 1;
    const data = Array.from({ length: len }, () => rng() % 256);
    cases.push({ degree, data });
  }
  const out = py(`
cases = json.load(sys.stdin)
# Independent GF(256) Reed-Solomon: plain polynomial long division.
def gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11d
        b >>= 1
    return r
def gen_poly(degree):
    g = [1]
    alpha = 1
    for _ in range(degree):
        # multiply g by (x + alpha)
        ng = [0] * (len(g) + 1)
        for i, c in enumerate(g):
            ng[i] ^= c
            ng[i + 1] ^= gf_mul(c, alpha)
        g = ng
        alpha = gf_mul(alpha, 2)
    return g
def gf_div_leadinv(lead):
    # find multiplicative inverse of lead by brute force (256 candidates)
    for x in range(256):
        if gf_mul(lead, x) == 1:
            return x
def remainder(data, g):
    msg = list(data) + [0] * (len(g) - 1)
    for i in range(len(data)):
        f = msg[i]
        if f:
            for j, c in enumerate(g):
                msg[i + j] ^= gf_mul(c, f)
    return msg[len(data):]
res = []
for c in cases:
    g = gen_poly(c['degree'])
    res.append({'gen': g, 'rem': remainder(c['data'], g)})
print(json.dumps(res))
`, cases);
  const expected = JSON.parse(out);
  cases.forEach((c, i) => {
    const g = rsGeneratorPoly(c.degree);
    assert.deepEqual(Array.from(g), expected[i].gen, `case ${i}: generator`);
    assert.deepEqual(Array.from(rsRemainder(c.data, g)), expected[i].rem, `case ${i}: remainder`);
  });
});

test("format info: pinned mask constant, BCH differential, min distance 7", () => {
  // The XOR mask 0x5412 (§8.9): format info for level M (bits 00), mask 0
  // is BCH remainder only, so the on-wire value must equal 0x5412 ^ rem.
  const out = py(`
def bch15_5(data):
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412
print(json.dumps([bch15_5(d) for d in range(32)]))
`);
  const expected = JSON.parse(out);
  const seen = [];
  for (const level of LEVELS) {
    for (let mask = 0; mask < 8; mask++) {
      const bits = formatInfoBits(level, mask);
      const data = { L: 1, M: 0, Q: 3, H: 2 }[level] * 8 + mask;
      assert.equal(bits, expected[data], `level ${level} mask ${mask}`);
      seen.push(bits);
    }
  }
  assert.equal(new Set(seen).size, 32);
  // BCH(15,5) has minimum Hamming distance 7 (it corrects 3 bit errors).
  let min = 15;
  for (let i = 0; i < 32; i++) {
    for (let j = i + 1; j < 32; j++) {
      let d = 0, x = seen[i] ^ seen[j];
      while (x) { d += x & 1; x >>>= 1; }
      min = Math.min(min, d);
    }
  }
  assert.equal(min, 7);
});

test("version info: pinned v7 vector, min distance 8", () => {
  // Version 7's info block, ISO/IEC 18004 Annex D example: 000111110010010100.
  assert.equal(versionInfoBits(7), 0b000111110010010100);
  const all = [];
  for (let v = 7; v <= 40; v++) {
    const bits = versionInfoBits(v);
    assert.equal(bits >>> 12, v, `top 6 bits carry the version (v${v})`);
    all.push(bits);
  }
  let min = 18;
  for (let i = 0; i < all.length; i++) {
    for (let j = i + 1; j < all.length; j++) {
      let d = 0, x = all[i] ^ all[j];
      while (x) { d += x & 1; x >>>= 1; }
      min = Math.min(min, d);
    }
  }
  // BCH(18,6) minimum distance is 8.
  assert.equal(min, 8);
});

// ---------------------------------------------------------- unit checks

test("mode selection", () => {
  assert.equal(chooseMode("0123456789"), "numeric");
  assert.equal(chooseMode("HELLO WORLD 123 $%*+-./:"), "alphanumeric");
  assert.equal(chooseMode("hello"), "byte"); // lowercase is not alphanumeric-mode
  assert.equal(chooseMode("ÄB"), "byte");
  assert.equal(chooseMode("123,456"), "byte"); // comma is not in the charset
  assert.equal(chooseMode(" "), "alphanumeric");
});

test("capacity boundaries at the ISO Table 7 corner values", () => {
  // Version 40 maxima: 7089 numeric, 4296 alphanumeric, 2953 bytes;
  // version 1-L holds 17 bytes.
  const fits = (text, level) => encode(text, { level });
  assert.equal(fits("9".repeat(7089), "L").version, 40);
  assert.throws(() => fits("9".repeat(7090), "L"), QrError);
  assert.equal(fits("A".repeat(4296), "L").version, 40);
  assert.throws(() => fits("A".repeat(4297), "L"), QrError);
  assert.equal(fits("x".repeat(2953), "L").version, 40);
  assert.throws(() => fits("x".repeat(2954), "L"), QrError);
  assert.equal(fits("x".repeat(17), "L").version, 1);
  assert.equal(fits("x".repeat(18), "L").version, 2);
});

test("multi-byte characters count as their UTF-8 length", () => {
  // 17 bytes fit version 1-L: "☂" is 3 bytes, so 5 of them (15 bytes) plus
  // "aa" is exactly 17, plus one more byte is not.
  assert.equal(encode("☂".repeat(5) + "aa", { level: "L" }).version, 1);
  assert.equal(encode("☂".repeat(5) + "aaa", { level: "L" }).version, 2);
});

test("penalty of an all-light matrix, computed by hand", () => {
  // 10x10 all light: N1 = 20 lines x (10-2) = 160; N2 = 9*9*3 = 243;
  // N3 = 0 (no dark core anywhere); N4 = |0-50|/5 -> 10 steps x 10 = 100.
  const m = Array.from({ length: 10 }, () => new Uint8Array(10));
  assert.equal(penalty(m), 503);
});

test("input validation", () => {
  assert.throws(() => encode(""), QrError);
  assert.throws(() => encode("hi", { level: "X" }), QrError);
  assert.throws(() => encode("hi", { mask: 8 }), QrError);
  assert.throws(() => encode("hi", { version: 41 }), QrError);
  assert.throws(() => encode("x".repeat(20), { version: 1, level: "L" }), QrError);
});

test("result metadata is consistent", () => {
  const r = encode("HELLO WORLD", { level: "Q" });
  assert.equal(r.size, r.version * 4 + 17);
  assert.equal(r.matrix.length, r.size);
  assert.equal(r.counts.dataCodewords * 8, capacityBits(r.version, "Q"));
  const [ecPer, groups] = EC_BLOCKS[r.version][LEVELS.indexOf("Q")];
  const blocks = groups.reduce((n, [c]) => n + c, 0);
  assert.equal(r.counts.ecCodewords, ecPer * blocks);
  assert.equal(r.counts.totalCodewords, r.counts.dataCodewords + r.counts.ecCodewords);
});

test("tables are internally consistent", () => {
  // Total codewords per version is level-independent and follows the
  // module-count arithmetic of the standard; alignment grids are symmetric.
  for (let v = 1; v <= 40; v++) {
    const totals = new Set();
    for (let l = 0; l < 4; l++) {
      const [ecPer, groups] = EC_BLOCKS[v][l];
      let words = 0;
      let blocks = 0;
      for (const [n, data] of groups) { words += n * data; blocks += n; }
      totals.add(words + ecPer * blocks);
    }
    assert.equal(totals.size, 1, `v${v}: total codewords equal across levels`);
    if (v >= 2) {
      const pos = ALIGN_POS[v];
      assert.equal(pos[0], 6, `v${v}: first alignment coordinate`);
      assert.equal(pos[pos.length - 1], v * 4 + 17 - 7, `v${v}: last alignment coordinate`);
    }
  }
});

test("toSvg geometry", () => {
  const r = encode("SVG TEST", { level: "M" });
  const svg = toSvg(r.matrix, { scale: 10, border: 4, dark: "#123456", light: "#fedcba" });
  const dim = r.size + 8;
  assert.ok(svg.includes(`viewBox="0 0 ${dim} ${dim}"`));
  assert.ok(svg.includes(`width="${dim * 10}"`));
  assert.ok(svg.includes('fill="#123456"'));
  // The path's horizontal runs must add up to the matrix's dark-module count.
  let dark = 0;
  for (const row of r.matrix) for (const v of row) dark += v;
  let sum = 0;
  for (const m of svg.matchAll(/h(\d+)v1/g)) sum += Number(m[1]);
  assert.equal(sum, dark);
});
