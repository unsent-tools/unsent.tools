// epoch.js — timestamp/epoch conversion logic for unsent.tools.
// Pure ES module, no dependencies. All functions take time context (`now`,
// `localOffsetMin`) explicitly so behavior is testable independent of the
// machine's clock and timezone. `localOffsetMin` is minutes east of UTC
// (UTC+2 → 120), i.e. the negation of JS Date's getTimezoneOffset().

const MS = { s: 1000, m: 60000, h: 3600000, d: 86400000 };

// Detect the unit of a bare numeric epoch by magnitude.
//   |v| < 1e11  → seconds      (covers years 1970±3000)
//   |v| < 1e14  → milliseconds
//   |v| < 1e17  → microseconds
//   else        → nanoseconds
export function detectEpochUnit(value) {
  const a = Math.abs(value);
  if (a < 1e11) return "seconds";
  if (a < 1e14) return "milliseconds";
  if (a < 1e17) return "microseconds";
  return "nanoseconds";
}

const UNIT_TO_MS = { seconds: 1000, milliseconds: 1, microseconds: 1e-3, nanoseconds: 1e-6 };

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function pad(n, w = 2) {
  const s = String(Math.trunc(Math.abs(n)));
  return "0".repeat(Math.max(0, w - s.length)) + s;
}

export function formatOffset(offsetMin) {
  if (offsetMin === 0) return "Z";
  const sign = offsetMin < 0 ? "-" : "+";
  const a = Math.abs(offsetMin);
  return `${sign}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
}

// ISO 8601 string for `ms` at the given fixed offset, e.g.
// 2026-08-23T14:30:00+02:00. Milliseconds included only when nonzero.
export function isoAtOffset(ms, offsetMin) {
  const d = new Date(ms + offsetMin * 60000);
  if (isNaN(d.getTime())) throw new Error("timestamp out of range");
  const frac = d.getUTCMilliseconds();
  const y = d.getUTCFullYear();
  const ys = y < 0 ? "-" + pad(-y, 4) : pad(y, 4);
  return (
    `${ys}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` +
    `T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}` +
    (frac ? "." + pad(frac, 3) : "") +
    formatOffset(offsetMin)
  );
}

// Approximate human phrase for a signed delta in ms ("3 days ago", "in 2 hours").
export function relativeTime(deltaMs) {
  const past = deltaMs < 0;
  const a = Math.abs(deltaMs);
  let phrase;
  if (a < 1000) return "now";
  else if (a < MS.m) phrase = `${Math.round(a / MS.s)} seconds`;
  else if (a < MS.h) phrase = unit(a / MS.m, "minute");
  else if (a < MS.d) phrase = unit(a / MS.h, "hour");
  else if (a < 30.44 * MS.d) phrase = unit(a / MS.d, "day");
  else if (a < 365.25 * MS.d) phrase = unit(a / (30.44 * MS.d), "month");
  else phrase = unit(a / (365.25 * MS.d), "year");
  return past ? `${phrase} ago` : `in ${phrase}`;
  function unit(v, name) {
    const r = Math.round(v * 10) / 10;
    const shown = r >= 10 ? Math.round(r) : r;
    return `${shown} ${name}${shown === 1 ? "" : "s"}`;
  }
}

const ISO_RE = new RegExp(
  "^(\\d{4})-(\\d{2})(?:-(\\d{2}))?" + // date
  "(?:[T ](\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.(\\d{1,9}))?)?" + // time
  "\\s*(Z|z|[+-]\\d{2}:?\\d{2})?)?$" // offset (only after a time part)
);

// Parse user input into { ms, kind, note?, warnings: [] }. Throws with a
// specific message on unparseable or invalid input.
//   kind: "epoch" | "iso" | "now"
// For epoch input, `unit` says which unit was assumed.
// For ISO input without an explicit offset, the local offset is assumed and
// noted.
export function parseTimestamp(input, { now, localOffsetMin = 0 } = {}) {
  const s = String(input).trim();
  if (s === "") throw new Error("empty input");

  if (/^now$/i.test(s)) {
    if (typeof now !== "number") throw new Error("no current time available");
    return { ms: now, kind: "now", warnings: [] };
  }

  // Bare number → epoch with unit autodetection.
  if (/^[+-]?\d+(\.\d+)?$/.test(s)) {
    const v = Number(s);
    if (!Number.isFinite(v)) throw new Error("number out of range");
    const hasFraction = s.includes(".");
    // A decimal point means seconds by convention (e.g. 1692800000.123).
    const unit = hasFraction ? "seconds" : detectEpochUnit(v);
    const ms = v * UNIT_TO_MS[unit];
    if (Math.abs(ms) > 8.64e15) throw new Error("timestamp out of representable range");
    const warnings = [];
    if (!hasFraction && unit !== "seconds") {
      warnings.push(`interpreted as epoch ${unit} by magnitude`);
    }
    return { ms: Math.round(ms * 1000) / 1000, kind: "epoch", unit, warnings };
  }

  const m = ISO_RE.exec(s);
  if (!m) {
    throw new Error(
      "not a recognized timestamp — use an epoch number, ISO 8601 (2026-08-23T14:30:00Z), or \"now\""
    );
  }
  const [, ys, mos, ds, hs, mins, secs, fracs, off] = m;
  const y = Number(ys), mo = Number(mos), d = ds ? Number(ds) : 1;
  const hh = hs ? Number(hs) : 0, mi = mins ? Number(mins) : 0, ss = secs ? Number(secs) : 0;
  const frac = fracs ? Number(("0." + fracs)) * 1000 : 0;
  if (mo < 1 || mo > 12) throw new Error(`invalid month ${pad(mo)}`);
  if (hh > 23) throw new Error(`invalid hour ${pad(hh)}`);
  if (mi > 59) throw new Error(`invalid minute ${pad(mi)}`);
  if (ss > 59) throw new Error(`invalid second ${pad(ss)} (leap seconds are not representable in epoch time)`);

  let utc = Date.UTC(y, mo - 1, d, hh, mi, ss);
  // Date.UTC silently rolls invalid dates over (Feb 30 → Mar 2); detect that.
  const chk = new Date(utc);
  if (chk.getUTCFullYear() !== y || chk.getUTCMonth() !== mo - 1 || chk.getUTCDate() !== d) {
    throw new Error(`invalid date ${ys}-${pad(mo)}-${pad(d)}`);
  }
  utc += Math.round(frac);

  const warnings = [];
  let note;
  if (off) {
    if (off === "Z" || off === "z") {
      // already UTC
    } else {
      const sign = off[0] === "-" ? -1 : 1;
      const rest = off.slice(1).replace(":", "");
      const offMin = sign * (Number(rest.slice(0, 2)) * 60 + Number(rest.slice(2)));
      if (Math.abs(offMin) > 18 * 60) throw new Error(`invalid UTC offset ${off}`);
      utc -= offMin * 60000;
    }
  } else {
    utc -= localOffsetMin * 60000;
    note = hs
      ? `no UTC offset given — assumed your local offset (${formatOffset(localOffsetMin) === "Z" ? "UTC" : formatOffset(localOffsetMin)})`
      : `date only — midnight in your local offset assumed`;
  }
  return { ms: utc, kind: "iso", note, warnings };
}

// Everything the UI shows for a resolved instant.
export function describe(ms, { now, localOffsetMin = 0 } = {}) {
  const d = new Date(ms);
  if (isNaN(d.getTime())) throw new Error("timestamp out of range");
  const local = new Date(ms + localOffsetMin * 60000);
  return {
    epochSeconds: ms / 1000,
    epochMillis: ms,
    isoUtc: isoAtOffset(ms, 0),
    isoLocal: isoAtOffset(ms, localOffsetMin),
    dayOfWeekUtc: DAYS[d.getUTCDay()],
    dayOfWeekLocal: DAYS[local.getUTCDay()],
    relative: typeof now === "number" ? relativeTime(ms - now) : null,
  };
}
