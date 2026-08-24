import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import {
  parseInput, decodeUuid, decodeUlid, encodeUlid,
  buildV4, buildV7, buildUlid, representations,
  hexToBytes, bytesToHex, canonicalUuid,
} from "./uuid.js";

// ------------------------------------------------- RFC 9562 pinned vectors
// All example UUIDs and their field values below are from RFC 9562
// Appendix A (test vectors); timestamps there are 2022-02-22 14:22:22 -05:00.

test("RFC 9562 A.1: v1 vector — timestamp, clock seq, node", () => {
  const d = decodeUuid(parseInput("C232AB00-9414-11EC-B3C8-9F6BDECED846").hex);
  assert.equal(d.version, 1);
  assert.equal(d.variant, "rfc");
  assert.equal(d.timestampMs, 1645557742000); // 2022-02-22T19:22:22Z
  assert.match(d.fields[0].value, /^2022-02-22T19:22:22\.000Z/);
  assert.equal(d.fields[0].detail, "138648505420000000 × 100 ns since 1582-10-15");
  assert.equal(d.fields[1].value, String(0x33c8));
  assert.equal(d.fields[2].value, "9f:6b:de:ce:d8:46");
  assert.match(d.fields[2].detail, /Multicast bit set/); // RFC's node is a random MAC
});

test("RFC 9562 A.5: v6 vector — same instant, sortable layout", () => {
  const d = decodeUuid(parseInput("1EC9414C-232A-6B00-B3C8-9F6BDECED846").hex);
  assert.equal(d.version, 6);
  assert.equal(d.timestampMs, 1645557742000);
});

test("RFC 9562 A.6: v7 vector — unix ms timestamp", () => {
  const d = decodeUuid(parseInput("017F22E2-79B0-7CC3-98C4-DC0C0C07398F").hex);
  assert.equal(d.version, 7);
  assert.equal(d.timestampMs, 1645557742000);
  assert.equal(d.fields[0].detail, "1645557742000 ms since 1970-01-01");
});

test("RFC 9562 A.2/A.3/A.4: v3/v4/v5 versions detected, no timestamp claimed", () => {
  for (const [s, ver] of [
    ["5df41881-3aed-3515-88a7-2f4a814cf09e", 3],
    ["919108f7-52d1-4320-9bac-f847db4148a8", 4],
    ["2ed6657d-e927-568b-95e1-2665a8aea6a2", 5],
  ]) {
    const d = decodeUuid(parseInput(s).hex);
    assert.equal(d.version, ver);
    assert.equal(d.timestampMs, undefined);
    assert.equal(d.fields.length, 0);
  }
});

test("nil and max UUIDs are called out specially", () => {
  assert.equal(decodeUuid(parseInput("00000000-0000-0000-0000-000000000000").hex).special, "nil");
  assert.equal(decodeUuid(parseInput("ffffffff-ffff-ffff-ffff-ffffffffffff").hex).special, "max");
});

// ------------------------------------------------------------ input forms

test("input forms: braces, urn prefix, bare hex, case-insensitive", () => {
  const hex = "c232ab00941411ecb3c89f6bdeced846";
  assert.equal(parseInput("{C232AB00-9414-11EC-B3C8-9F6BDECED846}").hex, hex);
  assert.equal(parseInput("urn:uuid:c232ab00-9414-11ec-b3c8-9f6bdeced846").hex, hex);
  assert.equal(parseInput("C232AB00941411ECB3C89F6BDECED846").hex, hex);
  assert.equal(parseInput("  c232ab00-9414-11ec-b3c8-9f6bdeced846  ").hex, hex);
  for (const p of [parseInput("{C232AB00-9414-11EC-B3C8-9F6BDECED846}")]) assert.equal(p.kind, "uuid");
});

test("malformed inputs fail with specific messages", () => {
  assert.throws(() => parseInput(""), /Enter a UUID/);
  assert.throws(() => parseInput("c232ab00-9414-11ec-b3c8"), /8-4-4-4-12/);
  assert.throws(() => parseInput("zzüuid-nonsense-here-way-too-longx"), /Not recognized/);
  // 26 chars but contains U: invalid Crockford
  assert.throws(() => parseInput("01AN4Z07BU79KA1307SR9X4MV3"), /U is excluded/);
  // 26 chars, first char 8: overflows 128 bits
  assert.throws(() => parseInput("8ZZZZZZZZZZZZZZZZZZZZZZZZZ"), /overflows 128 bits/);
});

// ------------------------------------------------------------------ ULID

test("ULID spec example decodes; value cross-checked against the reference ulid package", () => {
  // decodeTime("01AN4Z07BY79KA1307SR9X4MV3") === 1465824320894 (verified
  // 2026-08-24 against npm ulid; pinned here).
  const p = parseInput("01AN4Z07BY79KA1307SR9X4MV3");
  assert.equal(p.kind, "ulid");
  const d = decodeUlid(p.hex);
  assert.equal(d.timestampMs, 1465824320894);
  assert.equal(d.iso, "2016-06-13T13:25:20.894Z");
  assert.equal(d.canonical, "01AN4Z07BY79KA1307SR9X4MV3");
});

test("ULID decoding folds Crockford ambiguous letters and case", () => {
  const canonical = parseInput("01AN4Z07BY79KA1307SR9X4MV3");
  const folded = parseInput("01an4z07by79ka1307sr9x4mv3"); // lowercase
  assert.equal(folded.hex, canonical.hex);
  // Replace 1→L and 0→O in the time part; must decode identically.
  const sloppy = parseInput("OLAN4Z07BY79KA1307SR9X4MV3");
  assert.equal(sloppy.hex, canonical.hex);
  assert.ok(sloppy.notes.some((n) => /I\/L → 1, O → 0/.test(n)));
});

test("ULID max value accepted, one past it rejected", () => {
  const d = decodeUlid(parseInput("7ZZZZZZZZZZZZZZZZZZZZZZZZZ").hex);
  assert.equal(d.hex, "f".repeat(32));
  assert.equal(d.timestampMs, 2 ** 48 - 1);
});

test("Crockford encode/decode round-trips 1000 random 128-bit values", () => {
  for (let i = 0; i < 1000; i++) {
    const hex = bytesToHex([...randomBytes(16)]);
    const ulid = encodeUlid(hex);
    assert.match(ulid, /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/);
    assert.equal(parseInput(ulid).hex, hex);
  }
});

// ------------------------------------------------------------ generation

test("buildV4 sets exactly the version and variant bits", () => {
  for (let i = 0; i < 200; i++) {
    const bytes = [...randomBytes(16)];
    const hex = buildV4(bytes);
    const d = decodeUuid(hex);
    assert.equal(d.version, 4);
    assert.equal(d.variant, "rfc");
    // All other bits preserved from input.
    const out = hexToBytes(hex);
    for (let j = 0; j < 16; j++) {
      if (j === 6) assert.equal(out[j] & 0x0f, bytes[j] & 0x0f);
      else if (j === 8) assert.equal(out[j] & 0x3f, bytes[j] & 0x3f);
      else assert.equal(out[j], bytes[j]);
    }
  }
});

test("buildV7 embeds the exact timestamp; decode round-trips", () => {
  for (let i = 0; i < 200; i++) {
    const ts = Math.floor(Math.random() * 2 ** 48);
    const hex = buildV7(ts, [...randomBytes(10)]);
    const d = decodeUuid(hex);
    assert.equal(d.version, 7);
    assert.equal(d.timestampMs, ts);
  }
  // RFC vector timestamp reproduces the vector's leading bytes.
  assert.equal(buildV7(1645557742000, new Array(10).fill(0)).slice(0, 12), "017f22e279b0");
  assert.throws(() => buildV7(2 ** 48, [...randomBytes(10)]), /48-bit/);
  assert.throws(() => buildV7(-1, [...randomBytes(10)]), /48-bit/);
});

test("buildUlid embeds the exact timestamp; lexicographic order is time order", () => {
  const tss = Array.from({ length: 200 }, () => Math.floor(Math.random() * 2 ** 48));
  const ids = tss.map((ts) => buildUlid(ts, [...randomBytes(10)]));
  ids.forEach((id, i) => assert.equal(decodeUlid(parseInput(id).hex).timestampMs, tss[i]));
  const byString = [...ids].sort();
  const byTime = [...ids].sort((a, b) =>
    decodeUlid(parseInput(a).hex).timestampMs - decodeUlid(parseInput(b).hex).timestampMs || (a < b ? -1 : 1));
  assert.deepEqual(byString, byTime);
});

test("a v7 UUID and a ULID built from the same instant agree on the timestamp", () => {
  const ts = 1645557742000;
  const v7hex = buildV7(ts, [...randomBytes(10)]);
  // Read the v7 UUID's bits as a ULID: the 48-bit time prefix is the same field.
  assert.equal(decodeUlid(v7hex).timestampMs, ts);
  assert.equal(decodeUuid(v7hex).timestampMs, ts);
});

// --------------------------------------------- differential: node:crypto

test("differential: node crypto.randomUUID() always decodes as v4/rfc", () => {
  for (let i = 0; i < 500; i++) {
    const d = decodeUuid(parseInput(randomUUID()).hex);
    assert.equal(d.version, 4);
    assert.equal(d.variant, "rfc");
  }
});

// -------------------------------------------- differential: python uuid
// Python's uuid module is an independent implementation of the same field
// layout. Requires python3 on PATH (like the chmod suite requires GNU chmod).

test("differential: field extraction matches Python's uuid module", () => {
  // Random v1-layout UUIDs: version nibble forced to 1, variant to 10xx.
  const cases = [];
  for (let i = 0; i < 150; i++) {
    const b = [...randomBytes(16)];
    b[6] = (b[6] & 0x0f) | 0x10;
    b[8] = (b[8] & 0x3f) | 0x80;
    cases.push(bytesToHex(b));
  }
  // Plus fully random bytes to exercise variant classification.
  for (let i = 0; i < 150; i++) cases.push(bytesToHex([...randomBytes(16)]));

  const py = `
import sys, uuid, json
variants = {uuid.RESERVED_NCS: "ncs", uuid.RFC_4122: "rfc",
            uuid.RESERVED_MICROSOFT: "microsoft", uuid.RESERVED_FUTURE: "future"}
out = []
for hx in sys.stdin.read().split():
    u = uuid.UUID(hex=hx)
    rec = {"variant": variants[u.variant]}
    if u.variant == uuid.RFC_4122:
        rec["version"] = u.version
        if u.version == 1:
            rec["time"] = str(u.time)
            rec["clock_seq"] = u.clock_seq
            rec["node"] = "%012x" % u.node
    out.append(rec)
print(json.dumps(out))
`;
  const refs = JSON.parse(execFileSync("python3", ["-c", py], { input: cases.join("\n"), encoding: "utf8" }));
  cases.forEach((hex, i) => {
    const ref = refs[i];
    const d = decodeUuid(hex);
    if (d.special) return; // nil/max cannot occur from randomBytes in practice
    assert.equal(d.variant, ref.variant, hex);
    if (ref.variant !== "rfc") return;
    assert.equal(d.version, ref.version, hex);
    if (ref.version === 1) {
      assert.equal(d.fields[0].detail.split(" ")[0], ref.time, hex);
      assert.equal(d.fields[1].value, String(ref.clock_seq), hex);
      assert.equal(d.fields[2].value.replace(/:/g, ""), ref.node, hex);
    }
  });
});

// -------------------------------------------------------- representations

test("representations are mutually consistent", () => {
  const hex = parseInput("017F22E2-79B0-7CC3-98C4-DC0C0C07398F").hex;
  const r = representations(hex);
  assert.equal(r.uuid, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
  assert.equal(r.hex, hex);
  assert.equal(parseInput(r.ulid).hex, hex);
  assert.equal(BigInt(r.intBE).toString(16).padStart(32, "0"), hex);
  assert.equal(canonicalUuid(hex), r.uuid);
  assert.equal(r.bytes.split(" ").length, 16);
});
