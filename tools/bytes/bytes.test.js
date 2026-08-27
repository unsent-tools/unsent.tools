// Tests for bytes.js. Differential oracles:
//   - humanfriendly (Python) for byte-unit parsing — its case-insensitive
//     reading matches our "sloppy lowercase means bytes" rule, so the pools
//     exclude tokens we deliberately read as bits (kb, Mb, …).
//   - bitmath (Python) for the strict case-sensitive notation, including
//     bit units (kb, Mib) that humanfriendly gets wrong.
//   - Python's fractions.Fraction re-derives the exact rational arithmetic.
// Rendering, durations, and the ambiguity rules are pinned.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  parseSize, parseRate, parseMantissa, rational, rMul, rDiv, rCmp,
  rationalToDecimal, autoUnit, convertTable, transferSeconds, formatDuration,
  SizeError,
} from "./bytes.js";

const py = (script, input) =>
  execFileSync("python3", ["-c", script], {
    input: JSON.stringify(input), encoding: "utf8", maxBuffer: 1 << 24,
  });

function rng(seed) {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];

// ---------------------------------------------------------------------------

test("byte-unit parsing differential vs humanfriendly", () => {
  const r = rng(1);
  // Units both sides read as bytes. "kb"/"Kb" excluded (we read bits there —
  // pinned below); fractional mantissas paired only with units where the
  // result stays integral, since humanfriendly returns rounded ints.
  // P-units excluded: humanfriendly computes through floats, which lose
  // exactness above 2^53 (836.5 PiB came back off by 24 bytes in probing);
  // "1 PiB" is pinned below where the float happens to be exact.
  const units = ["B", "KB", "MB", "GB", "TB", "KiB", "MiB", "GiB", "TiB",
                 "mb", "gb", "tb", "kib", "mib", "gib", "tib",
                 "bytes", "byte", "megabytes", "gigabyte", "kilobytes"];
  const inputs = [];
  for (let i = 0; i < 250; i++) {
    const u = pick(r, units);
    const intOnly = u === "B" || u === "byte" || u === "bytes";
    // Mantissas capped so mantissa × factor stays below 2^53 (oracle floats).
    // ".0625" is only integral against binary factors (0.0625 × 1024 = 64).
    const fracs = /^[kmgt]ib$/i.test(u) ? ["5", "25", "125", "0625"] : ["5", "25", "125"];
    const n = intOnly || r() < 0.5
      ? String(Math.floor(r() * 8000))
      : `${Math.floor(r() * 1000)}.${pick(r, fracs)}`;
    inputs.push(`${n}${r() < 0.5 ? " " : ""}${u}`);
  }
  inputs.push("1024", "0 B", "999999999999 KiB", "1 PiB");
  const expected = JSON.parse(py(`
import sys, json, humanfriendly
print(json.dumps([humanfriendly.parse_size(s) for s in json.load(sys.stdin)]))
`, inputs));
  inputs.forEach((s, i) => {
    const got = parseSize(s);
    assert.equal(got.bytes.den, 1n, `expected integral bytes for ${JSON.stringify(s)}`);
    assert.equal(got.bytes.num.toString(), String(expected[i]), JSON.stringify(s));
  });
});

test("strict case-sensitive notation differential vs bitmath (bits and bytes)", () => {
  const r = rng(2);
  // Everything here is exact-case standard notation; mantissas kept small
  // enough that bitmath's float arithmetic is still exact.
  const units = ["kb", "kB", "Mb", "MB", "Gb", "GB", "Tb", "TB",
                 "Kib", "KiB", "Mib", "MiB", "Gib", "GiB", "Tib", "TiB"];
  const inputs = [];
  for (let i = 0; i < 200; i++) {
    const n = r() < 0.7 ? String(1 + Math.floor(r() * 999)) : `${Math.floor(r() * 99)}.5`;
    inputs.push(`${n} ${pick(r, units)}`);
  }
  const expected = JSON.parse(py(`
import sys, json, bitmath
print(json.dumps([int(bitmath.parse_string(s).bits) for s in json.load(sys.stdin)]))
`, inputs));
  inputs.forEach((s, i) => {
    const got = parseSize(s);
    assert.equal(got.bits.den, 1n, `integral bits for ${JSON.stringify(s)}`);
    assert.equal(got.bits.num.toString(), String(expected[i]), JSON.stringify(s));
    // And the bits/bytes flag itself must match the notation (lowercase b).
    assert.equal(got.isBits, s.endsWith("b"), JSON.stringify(s));
  });
});

test("exact rational arithmetic differential vs Python fractions", () => {
  const r = rng(3);
  const cases = [];
  for (let i = 0; i < 150; i++) {
    const mant = pick(r, [
      String(Math.floor(r() * 1e9)),
      `${Math.floor(r() * 1000)}.${Math.floor(r() * 1e6)}`,
      `${Math.floor(r() * 100)}e${Math.floor(r() * 6)}`,
      `${(r() * 10).toFixed(3)}e-${Math.floor(r() * 4)}`,
    ]);
    const unit = pick(r, [["B", "1", false], ["kB", "1000", false], ["GB", "1000000000", false],
                          ["KiB", "1024", false], ["GiB", "1073741824", false], ["PiB", String(1024 ** 5), false],
                          ["b", "1", true], ["Mb", "1000000", true], ["Kib", "1024", true]]);
    cases.push({ mant, unit: unit[0], factor: unit[1], bits: unit[2] });
  }
  const expected = JSON.parse(py(`
import sys, json
from fractions import Fraction
out = []
for c in json.load(sys.stdin):
    f = Fraction(c["mant"]) * Fraction(c["factor"])
    if c["bits"]: f = f / 8
    out.append([str(f.numerator), str(f.denominator)])
print(json.dumps(out))
`, cases));
  cases.forEach((c, i) => {
    const got = parseSize(`${c.mant} ${c.unit}`);
    assert.equal(got.bytes.num.toString(), expected[i][0], `${c.mant} ${c.unit}`);
    assert.equal(got.bytes.den.toString(), expected[i][1], `${c.mant} ${c.unit}`);
  });
});

test("notation rules: bits vs bytes, sloppy lowercase, ambiguity alternative", () => {
  // Strict notation: lowercase b is bits.
  assert.equal(parseSize("1 kb").bytes.num, 125n);
  assert.equal(parseSize("1 Mb").bytes.num, 125000n);
  assert.equal(parseSize("8 b").bytes.num, 1n);
  assert.equal(parseSize("1 Mbit").bytes.num, 125000n);
  assert.equal(parseSize("2 megabits").bytes.num, 250000n);
  assert.equal(parseSize("1 Kib").bytes.num, 128n);
  // Sloppy all-lowercase with an invalid prefix case reads as bytes, keeps
  // the bits reading as the alternative.
  const mb = parseSize("500 mb");
  assert.equal(mb.sloppy, true);
  assert.equal(mb.bytes.num, 500000000n);
  assert.equal(mb.alt.unit, "Mb");
  assert.equal(mb.alt.bytes.num, 62500000n);
  const kib = parseSize("2 kib");
  assert.equal(kib.bytes.num, 2048n);
  assert.equal(kib.alt.bytes.num, 256n);
  // "KB" is accepted for kB; "kb" is NOT sloppy (valid strict notation).
  assert.equal(parseSize("1 KB").bytes.num, 1000n);
  assert.equal(parseSize("1 kb").sloppy, false);
  // Unknown units and malformed numbers fail loudly.
  assert.throws(() => parseSize("1 XB"), SizeError);
  assert.throws(() => parseSize("1.2.3 MB"), SizeError);
  assert.throws(() => parseSize("-5 MB"), SizeError);
  assert.throws(() => parseSize("GB"), SizeError);
  // Separators and e-notation.
  assert.equal(parseSize("1,500,000").bytes.num, 1500000n);
  assert.equal(parseSize("1_000 kB").bytes.num, 1000000n);
  assert.equal(parseSize("1e3 kB").bytes.num, 1000000n);
  assert.equal(parseSize("2.5e-1 B").bytes.den, 4n);
});

test("rates: bps forms, slash forms, MBps, transfer time", () => {
  assert.equal(parseRate("100 Mbps").bitsPerSec.num, 100000000n);
  assert.equal(parseRate("100 mbps").bitsPerSec.num, 100000000n); // bps pins bits
  assert.equal(parseRate("56 kbps").bitsPerSec.num, 56000n);
  assert.equal(parseRate("1 Gbps").bitsPerSec.num, 1000000000n);
  assert.equal(parseRate("12 MB/s").bytesPerSec.num, 12000000n);
  assert.equal(parseRate("1 Gbit/s").bitsPerSec.num, 1000000000n);
  assert.equal(parseRate("2 MBps").bytesPerSec.num, 2000000n);
  assert.equal(parseRate("4 MiB/s").bytesPerSec.num, 4194304n);
  assert.throws(() => parseRate("100 M"), SizeError);
  assert.throws(() => parseRate("fast"), SizeError);

  // 1 GB at 100 Mbps: 8e9 bits / 1e8 = 80 s exactly.
  const t = transferSeconds(parseSize("1 GB"), parseRate("100 Mbps"));
  assert.equal(t.num, 80n);
  assert.equal(t.den, 1n);
  assert.equal(formatDuration(t), "80 s");
  assert.throws(() => transferSeconds(parseSize("1 GB"), parseRate("0 Mbps")), SizeError);
});

test("decimal rendering: significant digits, rounding, exactness", () => {
  const R = (n, d, sig) => rationalToDecimal(rational(n, d), sig);
  assert.equal(R(1n, 3n, 4), "0.3333");
  assert.equal(R(2n, 3n, 4), "0.6667");
  assert.equal(R(9997n, 10n, 3), "1000");        // rounding overflow bumps magnitude
  assert.equal(R(1n, 8n, 2), "0.13");
  assert.equal(R(1n, 8n, 4), "0.125");            // exact, trailing zeros trimmed
  assert.equal(R(1500000000n, 1n, 4), "1500000000".slice(0, 2) + "0".repeat(8)); // 1.5e9 at 4 sig
  assert.equal(R(1n, 10240n, 4), "0.00009766");
  assert.equal(R(-5n, 2n, 4), "-2.5");
  assert.equal(R(0n, 1n, 4), "0");
  assert.equal(R(1023n, 1n, 4), "1023");
  assert.equal(R(10235n, 10n, 4), "1024");        // half rounds away from zero

  // 500 GB drive shows as 465.66 GiB — the classic marketing gap.
  const gib = rDiv(parseSize("500 GB").bytes, rational(1024n ** 3n));
  assert.equal(rationalToDecimal(gib, 5), "465.66");
});

test("auto unit choice and round-trip property", () => {
  assert.deepEqual(autoUnit(parseSize("1234567 kB").bytes, {}), { unit: "GB", text: "1.235" });
  assert.deepEqual(autoUnit(parseSize("1 GiB").bytes, { binary: true }), { unit: "GiB", text: "1" });
  assert.deepEqual(autoUnit(parseSize("999 B").bytes, {}), { unit: "B", text: "999" });
  assert.deepEqual(autoUnit(parseSize("1 GB").bytes, { bits: true }), { unit: "Gb", text: "8" });

  const r = rng(4);
  for (let i = 0; i < 300; i++) {
    // Random byte counts across 15 orders of magnitude.
    const mag = 1 + Math.floor(r() * 15);
    const bytes = rational(BigInt(Math.floor(r() * 9 * 10 ** 8) + 1) * 10n ** BigInt(mag > 8 ? mag - 8 : 0));
    for (const binary of [false, true]) {
      const a = autoUnit(bytes, { binary });
      const back = parseSize(`${a.text} ${a.unit}`);
      // Display rounds to 4 significant digits → relative error ≤ 5e-4.
      const diff = rational(back.bytes.num * bytes.den - bytes.num * back.bytes.den,
                            back.bytes.den * bytes.den);
      const rel = rDiv({ num: diff.num < 0n ? -diff.num : diff.num, den: diff.den }, bytes);
      assert.ok(rCmp(rel, rational(1n, 1000n)) <= 0, `round trip ${a.text} ${a.unit}`);
    }
  }
});

test("conversion table and durations", () => {
  const rows = convertTable(parseSize("1 GiB").bytes);
  const get = (u) => rows.find((x) => x.unit === u).text;
  assert.equal(get("bytes"), "1073741824");
  assert.equal(get("bits"), "8589934592");
  assert.equal(get("GB"), "1.07374");
  assert.equal(get("MiB"), "1024");
  assert.equal(get("KiB"), "1048576");
  assert.equal(rows.find((x) => x.unit === "bytes").exact, true);

  const frac = convertTable(parseSize("0.5 b").bytes);
  assert.equal(frac.find((x) => x.unit === "bytes").exact, false);

  assert.equal(formatDuration(rational(1n, 2000n)), "500 µs");
  assert.equal(formatDuration(rational(3n, 1000n)), "3 ms");
  assert.equal(formatDuration(rational(1n, 2000000n)), "0.5 µs");
  assert.equal(formatDuration(rational(45n)), "45 s");
  assert.equal(formatDuration(rational(3600n)), "1 h");
  assert.equal(formatDuration(rational(3661n)), "1 h 1 min");
  assert.equal(formatDuration(rational(90061n)), "1 d 1 h");
  assert.equal(formatDuration(rational(0n)), "0 s");
  // 4.7 GB over 56 kbps ≈ 671428 s ≈ 7.77 days.
  assert.equal(formatDuration(transferSeconds(parseSize("4.7 GB"), parseRate("56 kbps"))), "7 d 18 h");
});
