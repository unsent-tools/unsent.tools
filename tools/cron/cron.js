// Cron expression parsing, plain-English description, and next-run computation.
//
// Handles standard five-field cron (minute hour day-of-month month day-of-week)
// with Vixie-cron syntax: lists, ranges, steps, `*`, three-letter or full names
// for months and weekdays, 0 or 7 for Sunday, and the @hourly/@daily/@weekly/
// @monthly/@yearly/@annually/@midnight macros. Two Vixie behaviours worth
// knowing: when BOTH day-of-month and day-of-week are restricted (not `*`), a
// day matches if EITHER field matches; and `N/step` means "from N to the
// field's max, every step".
//
// Next-run times are computed on whole minutes in either local or UTC time.
// Local-time results around a DST transition follow JavaScript Date
// normalization (a time in the skipped hour maps forward), which can differ
// from a real cron daemon's DST handling.

const MONTH_NAMES = [
  "january", "february", "march", "april", "may", "june",
  "july", "august", "september", "october", "november", "december",
];
const DAY_NAMES = [
  "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
];

const MONTH_DISPLAY = MONTH_NAMES.map((n) => n[0].toUpperCase() + n.slice(1));
const DAY_DISPLAY = DAY_NAMES.map((n) => n[0].toUpperCase() + n.slice(1));

const FIELDS = [
  { key: "minute", name: "minute", min: 0, max: 59 },
  { key: "hour", name: "hour", min: 0, max: 23 },
  { key: "dom", name: "day-of-month", min: 1, max: 31 },
  { key: "month", name: "month", min: 1, max: 12, names: MONTH_NAMES, nameOffset: 1 },
  { key: "dow", name: "day-of-week", min: 0, max: 7, names: DAY_NAMES, nameOffset: 0 },
];

const MACROS = {
  "@yearly": "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
  "@monthly": "0 0 1 * *",
  "@weekly": "0 0 * * 0",
  "@daily": "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@hourly": "0 * * * *",
};

function parseValue(field, token) {
  if (/^\d+$/.test(token)) {
    const v = Number(token);
    if (v < field.min || v > field.max) {
      throw new Error(`${field.name}: ${v} is out of range (${field.min}-${field.max})`);
    }
    return v;
  }
  if (field.names) {
    const t = token.toLowerCase();
    const idx = field.names.findIndex((n) => n === t || n.slice(0, 3) === t);
    if (idx !== -1) return idx + field.nameOffset;
  }
  throw new Error(
    `${field.name}: "${token}" is not a valid ${field.names ? "number or name" : "number"}`
  );
}

function parseField(field, text) {
  const atoms = [];
  for (const part of text.split(",")) {
    if (!part) throw new Error(`${field.name}: empty list item in "${text}"`);
    let body = part;
    let step = 1;
    let hasStep = false;
    const slash = part.indexOf("/");
    if (slash !== -1) {
      body = part.slice(0, slash);
      const stepStr = part.slice(slash + 1);
      if (!/^\d+$/.test(stepStr) || Number(stepStr) === 0) {
        throw new Error(`${field.name}: step "/${stepStr}" must be a positive integer`);
      }
      step = Number(stepStr);
      hasStep = true;
    }
    if (body === "*") {
      atoms.push({ type: "all", step, hasStep });
    } else if (body.includes("-")) {
      const pieces = body.split("-");
      if (pieces.length !== 2 || !pieces[0] || !pieces[1]) {
        throw new Error(`${field.name}: bad range "${body}"`);
      }
      const lo = parseValue(field, pieces[0]);
      const hi = parseValue(field, pieces[1]);
      if (lo > hi) {
        const hint = field.key === "dow"
          ? ' (use 0 or "SUN" for Sunday at the start of a range, 7 at the end)'
          : "";
        throw new Error(`${field.name}: range "${body}" runs backwards${hint}`);
      }
      atoms.push({ type: "range", lo, hi, step, hasStep });
    } else {
      const v = parseValue(field, body);
      if (hasStep) {
        // Vixie: "N/step" means from N to the field max, every step.
        atoms.push({ type: "range", lo: v, hi: field.max, step, hasStep });
      } else {
        atoms.push({ type: "value", v });
      }
    }
  }

  const set = new Set();
  for (const a of atoms) {
    if (a.type === "value") set.add(a.v);
    else {
      const lo = a.type === "all" ? field.min : a.lo;
      const hi = a.type === "all" ? field.max : a.hi;
      for (let v = lo; v <= hi; v += a.step) set.add(v);
    }
  }
  if (field.key === "dow" && set.has(7)) {
    set.delete(7);
    set.add(0);
  }
  return { atoms, set, values: [...set].sort((x, y) => x - y) };
}

export function parse(expression) {
  let text = String(expression).trim();
  if (!text) throw new Error("empty expression");
  if (text.startsWith("@")) {
    const key = text.toLowerCase();
    if (key === "@reboot") {
      throw new Error("@reboot runs once at daemon startup and has no time schedule");
    }
    if (!MACROS[key]) throw new Error(`unknown macro "${text}"`);
    text = MACROS[key];
  }
  const parts = text.split(/\s+/);
  if (parts.length !== 5) {
    throw new Error(
      `expected 5 fields (minute hour day-of-month month day-of-week), got ${parts.length}`
    );
  }
  const fields = {};
  FIELDS.forEach((f, i) => {
    fields[f.key] = parseField(f, parts[i]);
  });
  return {
    expression: parts.join(" "),
    fields,
    domRestricted: parts[2] !== "*",
    dowRestricted: parts[4] !== "*",
  };
}

function ord(n) {
  const tens = n % 100;
  if (tens >= 11 && tens <= 13) return `${n}th`;
  const last = n % 10;
  return `${n}${last === 1 ? "st" : last === 2 ? "nd" : last === 3 ? "rd" : "th"}`;
}

function joinAnd(items) {
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}

const pad = (n) => String(n).padStart(2, "0");

// `named` fields (month, day-of-week) read naturally without the unit word:
// "Monday through Friday" rather than "every day-of-week from Monday through Friday".
function atomPhrase(atom, unit, fmt, named) {
  if (atom.type === "all") {
    return atom.step > 1 ? `every ${ord(atom.step)} ${unit}` : `every ${unit}`;
  }
  if (atom.type === "range") {
    if (named && atom.step === 1) return `${fmt(atom.lo)} through ${fmt(atom.hi)}`;
    const base = atom.step > 1 ? `every ${ord(atom.step)} ${unit}` : `every ${unit}`;
    return `${base} from ${fmt(atom.lo)} through ${fmt(atom.hi)}`;
  }
  return fmt(atom.v);
}

function fieldPhrase(fld, unit, fmt, named) {
  if (fld.atoms.every((a) => a.type === "value")) {
    const list = joinAnd(fld.atoms.map((a) => fmt(a.v)));
    return named ? list : `${unit} ${list}`;
  }
  const parts = fld.atoms.map((a) => {
    if (a.type === "value" && !named) return `${unit} ${fmt(a.v)}`;
    return atomPhrase(a, unit, fmt, named);
  });
  return joinAnd(parts);
}

export function describe(expr) {
  const p = typeof expr === "object" ? expr : parse(expr);
  const f = p.fields;
  const single = (fld) =>
    fld.atoms.length === 1 && fld.atoms[0].type === "value" ? fld.atoms[0].v : null;
  const isEvery = (fld) =>
    fld.atoms.length === 1 && fld.atoms[0].type === "all" && fld.atoms[0].step === 1;
  const fmtNum = (v) => String(v);
  const fmtMonth = (v) => MONTH_DISPLAY[v - 1];
  const fmtDay = (v) => DAY_DISPLAY[v % 7];

  const m = single(f.minute);
  const h = single(f.hour);
  let time;
  if (m !== null && h !== null) {
    time = `At ${pad(h)}:${pad(m)}`;
  } else {
    time = "At " + fieldPhrase(f.minute, "minute", fmtNum, false);
    if (!isEvery(f.hour)) time += " past " + fieldPhrase(f.hour, "hour", fmtNum, false);
  }

  const parts = [time];
  const domP = p.domRestricted
    ? "on " + fieldPhrase(f.dom, "day-of-month", fmtNum, false)
    : null;
  const dowP = p.dowRestricted
    ? "on " + fieldPhrase(f.dow, "day-of-week", fmtDay, true)
    : null;
  if (domP && dowP) parts.push(`${domP} or ${dowP}`);
  else if (domP) parts.push(domP);
  else if (dowP) parts.push(dowP);
  if (!isEvery(f.month)) parts.push("in " + fieldPhrase(f.month, "month", fmtMonth, true));
  return parts.join(" ") + ".";
}

function accessors(utc) {
  if (utc) {
    return {
      year: (d) => d.getUTCFullYear(),
      month: (d) => d.getUTCMonth(),
      date: (d) => d.getUTCDate(),
      dow: (d) => d.getUTCDay(),
      make: (y, mo, day, h, mi) => new Date(Date.UTC(y, mo, day, h, mi)),
    };
  }
  return {
    year: (d) => d.getFullYear(),
    month: (d) => d.getMonth(),
    date: (d) => d.getDate(),
    dow: (d) => d.getDay(),
    make: (y, mo, day, h, mi) => new Date(y, mo, day, h, mi),
  };
}

// Next `count` run times strictly after `from`, as Date objects in ascending
// order. Scans up to 50 years; returns fewer than `count` only if matches are
// sparser than that, and throws if there are none at all (e.g. February 30).
export function nextRuns(expr, { from = new Date(), count = 5, utc = false } = {}) {
  const p = typeof expr === "object" ? expr : parse(expr);
  if (!Number.isInteger(count) || count < 1) throw new Error("count must be a positive integer");
  const A = accessors(utc);
  const startMs = Math.floor(from.getTime() / 60000) * 60000 + 60000;
  const start = new Date(startMs);
  const { minute, hour, dom, month, dow } = p.fields;
  const eitherDay = p.domRestricted && p.dowRestricted;

  const out = [];
  let y = A.year(start);
  let mo = A.month(start);
  let day = A.date(start);
  const MAX_DAYS = 366 * 50;
  for (let i = 0; i < MAX_DAYS && out.length < count; i++) {
    const d0 = A.make(y, mo, day, 0, 0);
    y = A.year(d0);
    mo = A.month(d0);
    day = A.date(d0);
    const domOk = dom.set.has(day);
    const dowOk = dow.set.has(A.dow(d0));
    const dayOk = month.set.has(mo + 1) && (eitherDay ? domOk || dowOk : domOk && dowOk);
    if (dayOk) {
      for (const hh of hour.values) {
        for (const mi of minute.values) {
          const t = A.make(y, mo, day, hh, mi);
          if (t.getTime() >= startMs) {
            out.push(t);
            if (out.length >= count) break;
          }
        }
        if (out.length >= count) break;
      }
    }
    day += 1;
  }
  if (out.length === 0) {
    throw new Error(`"${p.expression}" never matches (no run in the next 50 years)`);
  }
  return out;
}
