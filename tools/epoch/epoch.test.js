import { test } from "node:test";
import assert from "node:assert/strict";
import { detectEpochUnit, formatOffset, isoAtOffset, relativeTime, parseTimestamp, describe } from "./epoch.js";

// Fixed "current time" for every test: 2026-08-23T12:00:00Z.
const NOW = Date.UTC(2026, 7, 23, 12, 0, 0);

// ---------- unit detection ----------

test("detectEpochUnit boundaries", () => {
  assert.equal(detectEpochUnit(1692800000), "seconds");          // 2023
  assert.equal(detectEpochUnit(99999999999), "seconds");         // just under 1e11
  assert.equal(detectEpochUnit(1e11), "milliseconds");           // 1973 in ms
  assert.equal(detectEpochUnit(1692800000000), "milliseconds");
  assert.equal(detectEpochUnit(1692800000000000), "microseconds");
  assert.equal(detectEpochUnit(1692800000000000000), "nanoseconds");
  assert.equal(detectEpochUnit(-1000000), "seconds");            // pre-1970
});

// ---------- formatting ----------

test("formatOffset", () => {
  assert.equal(formatOffset(0), "Z");
  assert.equal(formatOffset(120), "+02:00");
  assert.equal(formatOffset(-330), "-05:30");
  assert.equal(formatOffset(345), "+05:45");
});

test("isoAtOffset renders the same instant at different offsets", () => {
  const ms = Date.UTC(2026, 7, 23, 14, 30, 0);
  assert.equal(isoAtOffset(ms, 0), "2026-08-23T14:30:00Z");
  assert.equal(isoAtOffset(ms, 120), "2026-08-23T16:30:00+02:00");
  assert.equal(isoAtOffset(ms, -420), "2026-08-23T07:30:00-07:00");
  // offset crossing midnight changes the date
  assert.equal(isoAtOffset(Date.UTC(2026, 7, 23, 23, 30, 0), 120), "2026-08-24T01:30:00+02:00");
  assert.equal(isoAtOffset(Date.UTC(2026, 0, 1, 0, 30, 0), -120), "2025-12-31T22:30:00-02:00");
});

test("isoAtOffset includes milliseconds only when nonzero", () => {
  assert.equal(isoAtOffset(1500, 0), "1970-01-01T00:00:01.500Z");
  assert.equal(isoAtOffset(1000, 0), "1970-01-01T00:00:01Z");
});

// ---------- relative time ----------

test("relativeTime phrases", () => {
  assert.equal(relativeTime(0), "now");
  assert.equal(relativeTime(-45 * 1000), "45 seconds ago");
  assert.equal(relativeTime(90 * 1000), "in 1.5 minutes");
  assert.equal(relativeTime(-3 * 3600000), "3 hours ago");
  assert.equal(relativeTime(2 * 86400000), "in 2 days");
  assert.equal(relativeTime(-40 * 86400000), "1.3 months ago");
  assert.equal(relativeTime(400 * 86400000), "in 1.1 years");
});

// ---------- parsing: epoch numbers ----------

test("parse epoch seconds / ms / µs / ns to the same instant", () => {
  const expect = 1692800000000; // ms
  assert.equal(parseTimestamp("1692800000").ms, expect);
  assert.equal(parseTimestamp("1692800000000").ms, expect);
  assert.equal(parseTimestamp("1692800000000000").ms, expect);
  assert.equal(parseTimestamp("1692800000000000000").ms, expect);
  assert.equal(parseTimestamp("1692800000").unit, "seconds");
  assert.deepEqual(parseTimestamp("1692800000").warnings, []);
  assert.equal(parseTimestamp("1692800000000").warnings.length, 1); // non-default unit noted
});

test("parse decimal epoch as seconds with fraction", () => {
  const r = parseTimestamp("1692800000.25");
  assert.equal(r.unit, "seconds");
  assert.equal(r.ms, 1692800000250);
});

test("parse negative epoch (pre-1970)", () => {
  const r = parseTimestamp("-86400");
  assert.equal(r.ms, -86400000);
  assert.equal(isoAtOffset(r.ms, 0), "1969-12-31T00:00:00Z");
});

test("epoch beyond Date range throws", () => {
  // 1e27 ns ≈ 1e21 ms — far beyond Date's ±8.64e15 ms range.
  assert.throws(() => parseTimestamp("999999999999999999999999999"), /range/);
});

// ---------- parsing: ISO ----------

test("parse ISO with Z and with offsets", () => {
  assert.equal(parseTimestamp("2026-08-23T14:30:00Z").ms, Date.UTC(2026, 7, 23, 14, 30, 0));
  // +02:00 means the instant is 2 hours EARLIER in UTC
  assert.equal(parseTimestamp("2026-08-23T14:30:00+02:00").ms, Date.UTC(2026, 7, 23, 12, 30, 0));
  assert.equal(parseTimestamp("2026-08-23T14:30:00-0700").ms, Date.UTC(2026, 7, 23, 21, 30, 0));
  assert.equal(parseTimestamp("2026-08-23T14:30:00.250Z").ms, Date.UTC(2026, 7, 23, 14, 30, 0) + 250);
});

test("parse ISO without offset assumes the given local offset", () => {
  const r = parseTimestamp("2026-08-23T14:30", { localOffsetMin: 120 });
  assert.equal(r.ms, Date.UTC(2026, 7, 23, 12, 30, 0));
  assert.match(r.note, /assumed your local offset \(\+02:00\)/);
  // and with UTC as local
  const r0 = parseTimestamp("2026-08-23T14:30", { localOffsetMin: 0 });
  assert.equal(r0.ms, Date.UTC(2026, 7, 23, 14, 30, 0));
});

test("parse space-separated datetime and date-only", () => {
  assert.equal(parseTimestamp("2026-08-23 14:30:00Z").ms, Date.UTC(2026, 7, 23, 14, 30, 0));
  const r = parseTimestamp("2026-08-23", { localOffsetMin: -300 });
  assert.equal(r.ms, Date.UTC(2026, 7, 23, 5, 0, 0)); // local midnight at UTC-5
  assert.match(r.note, /date only/);
});

test("parse 'now'", () => {
  assert.equal(parseTimestamp("now", { now: NOW }).ms, NOW);
  assert.equal(parseTimestamp("NOW", { now: NOW }).kind, "now");
});

test("invalid dates and fields throw with specific messages", () => {
  assert.throws(() => parseTimestamp("2026-02-30"), /invalid date/);
  assert.throws(() => parseTimestamp("2026-13-01"), /invalid month/);
  assert.throws(() => parseTimestamp("2026-08-23T24:00"), /invalid hour/);
  assert.throws(() => parseTimestamp("2026-08-23T12:60"), /invalid minute/);
  assert.throws(() => parseTimestamp("2026-08-23T12:00:60Z"), /leap second/);
  assert.throws(() => parseTimestamp("2026-08-23T14:30:00+19:00"), /invalid UTC offset/);
  assert.throws(() => parseTimestamp("yesterday"), /not a recognized/);
  assert.throws(() => parseTimestamp(""), /empty/);
});

test("leap day parses in leap years only", () => {
  assert.equal(parseTimestamp("2028-02-29T00:00Z").ms, Date.UTC(2028, 1, 29));
  assert.throws(() => parseTimestamp("2026-02-29"), /invalid date/);
});

// ---------- describe ----------

test("describe: full picture at a non-UTC offset", () => {
  const ms = Date.UTC(2026, 7, 23, 23, 30, 0); // Sunday 23:30 UTC
  const d = describe(ms, { now: NOW, localOffsetMin: 120 });
  assert.equal(d.epochSeconds, ms / 1000);
  assert.equal(d.epochMillis, ms);
  assert.equal(d.isoUtc, "2026-08-23T23:30:00Z");
  assert.equal(d.isoLocal, "2026-08-24T01:30:00+02:00"); // Monday local
  assert.equal(d.dayOfWeekUtc, "Sunday");
  assert.equal(d.dayOfWeekLocal, "Monday");
  assert.equal(d.relative, "in 12 hours"); // ≥10 units rounds to whole numbers
});

test("round-trip: describe(parse(x)) preserves the instant", () => {
  for (const input of ["1692800000", "2026-08-23T14:30:00+02:00", "2001-01-01 00:00:00Z", "-1"]) {
    const { ms } = parseTimestamp(input, { now: NOW, localOffsetMin: 60 });
    const d = describe(ms, { now: NOW, localOffsetMin: 60 });
    assert.equal(parseTimestamp(d.isoUtc).ms, ms, input);
    assert.equal(parseTimestamp(d.isoLocal).ms, ms, input);
    // epochMillis round-trips only when its magnitude reads back as ms
    if (Math.abs(d.epochMillis) >= 1e11) {
      assert.equal(parseTimestamp(String(d.epochMillis)).ms, ms, input);
    }
  }
});

test("documented ambiguity: small epoch numbers always read as seconds", () => {
  // -1000 as an instant in ms is 1969-12-31T23:59:59Z, but pasted back in it
  // reads as -1000 SECONDS by the magnitude heuristic. Near-1970 epochs are
  // inherently ambiguous; the tool resolves bare numbers < 1e11 as seconds.
  assert.equal(parseTimestamp("-1000").unit, "seconds");
  assert.equal(parseTimestamp("-1000").ms, -1000000);
});
