import { test } from "node:test";
import assert from "node:assert/strict";
import { parse, describe, nextRuns } from "./cron.js";

const at = (iso) => new Date(iso);
const runsUTC = (expr, fromIso, count) =>
  nextRuns(expr, { from: at(fromIso), count, utc: true }).map((d) => d.toISOString());

// --- parsing ---

test("parse expands lists, ranges, and steps", () => {
  const p = parse("5,10-12,*/20 * * * *");
  assert.deepEqual(p.fields.minute.values, [0, 5, 10, 11, 12, 20, 40]);
});

test("parse: N/step means N through max", () => {
  assert.deepEqual(parse("5/10 * * * *").fields.minute.values, [5, 15, 25, 35, 45, 55]);
});

test("parse accepts month and weekday names, case-insensitive, 3-letter or full", () => {
  assert.deepEqual(parse("0 0 1 JAN *").fields.month.values, [1]);
  assert.deepEqual(parse("0 0 * * mon-friday").fields.dow.values, [1, 2, 3, 4, 5]);
  assert.deepEqual(parse("0 0 * March *").fields.month.values, [3]);
});

test("parse: day-of-week 7 is Sunday (normalized to 0)", () => {
  assert.deepEqual(parse("0 0 * * 7").fields.dow.values, [0]);
  assert.deepEqual(parse("0 0 * * 5-7").fields.dow.values, [0, 5, 6]);
});

test("parse: macros expand; @reboot and unknown macros are rejected", () => {
  assert.equal(parse("@weekly").expression, "0 0 * * 0");
  assert.equal(parse("@daily").expression, "0 0 * * *");
  assert.throws(() => parse("@reboot"), /no time schedule/);
  assert.throws(() => parse("@fortnightly"), /unknown macro/);
});

test("parse rejects malformed input with useful errors", () => {
  assert.throws(() => parse(""), /empty/);
  assert.throws(() => parse("* * * *"), /got 4/);
  assert.throws(() => parse("* * * * * *"), /got 6/);
  assert.throws(() => parse("60 * * * *"), /out of range \(0-59\)/);
  assert.throws(() => parse("* 24 * * *"), /out of range \(0-23\)/);
  assert.throws(() => parse("* * 0 * *"), /out of range \(1-31\)/);
  assert.throws(() => parse("* * * * 8"), /out of range \(0-7\)/);
  assert.throws(() => parse("*/0 * * * *"), /step .* positive/);
  assert.throws(() => parse("a * * * *"), /not a valid number/);
  assert.throws(() => parse("* * * * FRI-MON"), /runs backwards/);
  assert.throws(() => parse("1,,2 * * * *"), /empty list item/);
});

// --- describe ---

test("describe: pinned phrasings", () => {
  const cases = [
    ["* * * * *", "At every minute."],
    ["30 4 * * *", "At 04:30."],
    ["*/15 * * * *", "At every 15th minute."],
    ["0 */2 * * *", "At minute 0 past every 2nd hour."],
    ["0 22 * * 1-5", "At 22:00 on Monday through Friday."],
    ["5,35 9-17 * * *", "At minute 5 and 35 past every hour from 9 through 17."],
    ["0 0 1 1 *", "At 00:00 on day-of-month 1 in January."],
    ["0 0 1 * 1", "At 00:00 on day-of-month 1 or on Monday."],
    ["@weekly", "At 00:00 on Sunday."],
    ["0 0 29 2 *", "At 00:00 on day-of-month 29 in February."],
    ["10-30/5 * * * SAT,SUN", "At every 5th minute from 10 through 30 on Saturday and Sunday."],
  ];
  for (const [expr, want] of cases) assert.equal(describe(expr), want, expr);
});

// --- nextRuns ---

test("nextRuns: every minute, strictly after `from`, ascending", () => {
  assert.deepEqual(runsUTC("* * * * *", "2026-01-01T00:00:00.000Z", 3), [
    "2026-01-01T00:01:00.000Z",
    "2026-01-01T00:02:00.000Z",
    "2026-01-01T00:03:00.000Z",
  ]);
  // mid-minute `from` rounds up to the next whole minute
  assert.deepEqual(runsUTC("* * * * *", "2026-01-01T00:00:30.000Z", 1), [
    "2026-01-01T00:01:00.000Z",
  ]);
});

test("nextRuns: daily time, day rollover", () => {
  assert.deepEqual(runsUTC("30 4 * * *", "2026-01-01T05:00:00Z", 2), [
    "2026-01-02T04:30:00.000Z",
    "2026-01-03T04:30:00.000Z",
  ]);
});

test("nextRuns: year rollover", () => {
  assert.deepEqual(runsUTC("0 0 1 1 *", "2026-03-01T00:00:00Z", 1), [
    "2027-01-01T00:00:00.000Z",
  ]);
});

test("nextRuns: leap day only runs in leap years", () => {
  assert.deepEqual(runsUTC("0 0 29 2 *", "2026-01-01T00:00:00Z", 2), [
    "2028-02-29T00:00:00.000Z",
    "2032-02-29T00:00:00.000Z",
  ]);
});

test("nextRuns: day-of-month 31 skips short months", () => {
  assert.deepEqual(runsUTC("0 0 31 * *", "2026-01-31T01:00:00Z", 2), [
    "2026-03-31T00:00:00.000Z",
    "2026-05-31T00:00:00.000Z",
  ]);
});

test("nextRuns: dom and dow both restricted means either matches (Vixie OR)", () => {
  // 2026-01-01 is a Thursday; 2026-01-05 is a Monday.
  assert.deepEqual(runsUTC("0 0 1 * 1", "2025-12-31T12:00:00Z", 3), [
    "2026-01-01T00:00:00.000Z",
    "2026-01-05T00:00:00.000Z",
    "2026-01-12T00:00:00.000Z",
  ]);
});

test("nextRuns: only dow restricted is a plain weekday filter", () => {
  // First Sunday after 2026-01-01 is 2026-01-04.
  assert.deepEqual(runsUTC("0 12 * * 0", "2026-01-01T00:00:00Z", 1), [
    "2026-01-04T12:00:00.000Z",
  ]);
});

test("nextRuns: business-hours schedule resumes Monday morning", () => {
  // 2026-01-03 is a Saturday.
  assert.deepEqual(runsUTC("*/15 9-17 * * MON-FRI", "2026-01-03T10:00:00Z", 2), [
    "2026-01-05T09:00:00.000Z",
    "2026-01-05T09:15:00.000Z",
  ]);
  // Last slot of the day is 17:45, then Tuesday 09:00.
  assert.deepEqual(runsUTC("*/15 9-17 * * MON-FRI", "2026-01-05T17:44:30Z", 2), [
    "2026-01-05T17:45:00.000Z",
    "2026-01-06T09:00:00.000Z",
  ]);
});

test("nextRuns: impossible dates throw", () => {
  assert.throws(() => runsUTC("0 0 31 4 *", "2026-01-01T00:00:00Z", 1), /never matches/);
  assert.throws(() => runsUTC("0 0 30 2 *", "2026-01-01T00:00:00Z", 1), /never matches/);
});

test("nextRuns: rejects bad count", () => {
  assert.throws(() => nextRuns("* * * * *", { count: 0 }), /positive integer/);
});
