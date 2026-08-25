// Tests for base.js. The differential oracle is Python: int(s, base) for
// parsing, format()/str() for formatting, and struct.pack for the
// two's-complement patterns — all independent of the BigInt code paths the
// module uses, unlike a Node-vs-Node comparison would be.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  parseNumber, toBase, grouped, bitLength, popcount, fits, twos, signedRead, bytes,
} from "./base.js";

const py = (script) => execFileSync("python3", ["-c", script], { encoding: "utf8" }).trim();

// Deterministic PRNG so failures reproduce.
function makeRng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s;
  };
}
function randBigInt(rng, maxBits) {
  const bits = rng() % maxBits + 1;
  let v = 0n;
  for (let got = 0; got < bits; got += 24) v = (v << 24n) | BigInt(rng() % 0x1000000);
  v &= (1n << BigInt(bits)) - 1n;
  return rng() % 2 ? -v : v;
}

test("parse: prefixes, separators, signs, explicit bases", () => {
  assert.equal(parseNumber("0xdead_beef").value, 0xdeadbeefn);
  assert.equal(parseNumber("0b1010 1010").value, 170n);
  assert.equal(parseNumber("0o755").value, 493n);
  assert.equal(parseNumber("-42").value, -42n);
  assert.equal(parseNumber("+7").value, 7n);
  assert.equal(parseNumber("ff", 16).value, 255n);
  assert.equal(parseNumber("0xff", 16).value, 255n, "matching prefix tolerated");
  assert.equal(parseNumber("z", 36).value, 35n);
  assert.equal(parseNumber("10", 2).value, 2n);
  // "0b1" under base 16: b is a hex digit, not a prefix.
  assert.equal(parseNumber("0b1", 16).value, 0xb1n);
  // "0o1" under base 25: o is digit 24, not a prefix.
  assert.equal(parseNumber("0o1", 25).value, 24n * 25n + 1n);
});

test("parse: rejections carry positions and reasons", () => {
  assert.throws(() => parseNumber(""), /Enter a number/);
  assert.throws(() => parseNumber("12g8"), /"g" is not a base-10 digit \(position 3\)/);
  assert.throws(() => parseNumber("0x"), /No digits after the prefix/);
  assert.throws(() => parseNumber("0b12"), /"2" is not a base-2 digit/);
  assert.throws(() => parseNumber("0xff", 10), /Prefix 0x means base 16/);
  assert.throws(() => parseNumber("_12"), /between digits/);
  assert.throws(() => parseNumber("2", 2), /not a base-2 digit/);
});

test("parse differential vs Python int(s, base): 300 random (value, base) pairs", () => {
  const rng = makeRng(0xba5e);
  const cases = [];
  for (let i = 0; i < 300; i++) {
    const v = randBigInt(rng, 200);
    const base = rng() % 35 + 2;
    cases.push([toBase(v, base), base]);
  }
  const script = `
import sys, json
for s, b in json.load(sys.stdin):
    print(int(s, b))
`;
  const out = execFileSync("python3", ["-c", script], {
    input: JSON.stringify(cases), encoding: "utf8",
  }).trim().split("\n");
  cases.forEach(([s, base], i) => {
    assert.equal(parseNumber(s, base).value.toString(), out[i], `"${s}" base ${base}`);
  });
});

test("format differential vs Python format(): hex/oct/bin/dec of random values", () => {
  const rng = makeRng(0xf0f0);
  const values = [];
  for (let i = 0; i < 100; i++) values.push(randBigInt(rng, 260).toString());
  const script = `
import sys, json
for s in json.load(sys.stdin):
    v = int(s)
    print(format(v, 'x'), format(v, 'o'), format(v, 'b'), v)
`;
  const out = execFileSync("python3", ["-c", script], {
    input: JSON.stringify(values), encoding: "utf8",
  }).trim().split("\n");
  values.forEach((s, i) => {
    const v = BigInt(s);
    const [x, o, b, d] = out[i].split(" ");
    assert.equal(toBase(v, 16), x);
    assert.equal(toBase(v, 8), o);
    assert.equal(toBase(v, 2), b);
    assert.equal(toBase(v, 10), d);
  });
});

test("round-trip property: parse(format(v, base), base) === v, all bases", () => {
  const rng = makeRng(0x1007);
  for (let base = 2; base <= 36; base++) {
    for (let i = 0; i < 10; i++) {
      const v = randBigInt(rng, 128);
      assert.equal(parseNumber(toBase(v, base), base).value, v, `base ${base}`);
    }
  }
});

test("two's complement differential vs Python struct.pack", () => {
  const rng = makeRng(0x2c2c);
  const cases = [];
  for (const [width, code] of [[8, "b"], [16, "h"], [32, "i"], [64, "q"]]) {
    const W = BigInt(width);
    const lo = -(1n << (W - 1n)), hi = (1n << (W - 1n)) - 1n;
    const vals = [lo, -1n, 0n, 1n, hi];
    for (let i = 0; i < 20; i++) {
      const span = hi - lo + 1n;
      vals.push(lo + ((randBigInt(rng, width + 8) % span) + span) % span);
    }
    for (const v of vals) cases.push([v.toString(), width, code]);
  }
  const script = `
import sys, json, struct
for s, w, code in json.load(sys.stdin):
    print(struct.pack('>' + code, int(s)).hex())
`;
  const out = execFileSync("python3", ["-c", script], {
    input: JSON.stringify(cases), encoding: "utf8",
  }).trim().split("\n");
  cases.forEach(([s, width], i) => {
    const t = twos(BigInt(s), width);
    assert.equal(t.hex, out[i], `${s} as int${width}`);
    assert.equal(BigInt("0b" + t.bin).toString(16).padStart(width / 4, "0"), t.hex);
  });
});

test("twos/signedRead: fit boundaries and inversion", () => {
  assert.equal(twos(128n, 8), null, "128 overflows int8");
  assert.notEqual(twos(127n, 8), null);
  assert.equal(twos(-129n, 8), null);
  assert.equal(twos(-128n, 8).hex, "80");
  assert.equal(signedRead(0xffn, 8), -1n);
  assert.equal(signedRead(0x7fn, 8), 127n);
  assert.equal(signedRead(256n, 8), null, "not an 8-bit pattern");
  assert.equal(signedRead(-1n, 8), null, "patterns are non-negative");
  // Inversion: reading the pattern back gives the value.
  const rng = makeRng(0xabcd);
  for (let i = 0; i < 50; i++) {
    const width = [8, 16, 32, 64][rng() % 4];
    const v = randBigInt(rng, width - 1);
    const pattern = BigInt("0x" + twos(v, width).hex);
    assert.equal(signedRead(pattern, width), v, `${v} width ${width}`);
  }
});

test("properties: bitLength, popcount, fits, grouping, bytes", () => {
  assert.equal(bitLength(0n), 0);
  assert.equal(bitLength(255n), 8);
  assert.equal(bitLength(256n), 9);
  assert.equal(bitLength(-256n), 9);
  assert.equal(popcount(255n), 8);
  assert.equal(popcount(0n), 0);
  assert.equal(popcount(-5n), 2);
  assert.deepEqual(fits(255n), { unsigned: 8, signed: 16 });
  assert.deepEqual(fits(127n), { unsigned: 8, signed: 8 });
  assert.deepEqual(fits(-1n), { unsigned: null, signed: 8 });
  assert.deepEqual(fits(1n << 200n), { unsigned: null, signed: null });
  assert.equal(grouped("deadbeef", 16), "dead beef");
  assert.equal(grouped("-1234567", 10), "-1 234 567");
  assert.equal(grouped("101", 2), "101");
  assert.deepEqual(bytes(0xdeadbeefn), ["de", "ad", "be", "ef"]);
  assert.deepEqual(bytes(0n), ["00"]);
  assert.deepEqual(bytes(0xfffn), ["0f", "ff"]);
});

test("python cross-check of bit_length and bit_count on random values", () => {
  const rng = makeRng(0xb17);
  const values = [];
  for (let i = 0; i < 60; i++) values.push(randBigInt(rng, 300).toString());
  const script = `
import sys, json
for s in json.load(sys.stdin):
    v = abs(int(s))
    print(v.bit_length(), bin(v).count('1'))
`;
  const out = execFileSync("python3", ["-c", script], {
    input: JSON.stringify(values), encoding: "utf8",
  }).trim().split("\n");
  values.forEach((s, i) => {
    const [bl, pc] = out[i].split(" ").map(Number);
    assert.equal(bitLength(BigInt(s)), bl);
    assert.equal(popcount(BigInt(s)), pc);
  });
});
