// base.js — integer base conversion at arbitrary precision (BigInt), with
// the views programmers actually reach for: prefixed literals in and out,
// digit grouping, two's-complement representations at fixed widths, byte
// order, bit properties. Pure functions, no DOM.

class BaseError extends Error {}
const fail = (msg) => { throw new BaseError(msg); };

const DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";

// ---------------------------------------------------------------- parsing

// parseNumber(raw, baseSel) → { value: BigInt, base, negative, notes: [] }.
// baseSel is "auto" or 2..36. In auto mode the prefixes 0x/0o/0b select the
// base and bare digits mean decimal. With an explicit base, a matching
// prefix is tolerated (0xff with base 16), a mismatched one is an error.
// Underscores and spaces between digits are ignored, like numeric literals
// in most languages.
export function parseNumber(raw, baseSel = "auto") {
  let s = String(raw).trim();
  if (!s) fail("Enter a number.");
  const notes = [];

  let negative = false;
  if (s[0] === "+" || s[0] === "-") {
    negative = s[0] === "-";
    s = s.slice(1);
  }

  let base = baseSel === "auto" ? 10 : Number(baseSel);
  const m = s.match(/^0([xob])/i);
  if (m) {
    const prefBase = { x: 16, o: 8, b: 2 }[m[1].toLowerCase()];
    if (baseSel === "auto") {
      base = prefBase;
      notes.push(`Prefix 0${m[1].toLowerCase()} → base ${base}.`);
      s = s.slice(2);
    } else if (Number(baseSel) === prefBase) {
      s = s.slice(2); // matching prefix, harmless
    } else if (DIGITS.indexOf(m[1].toLowerCase()) < base) {
      // The letter is itself a valid digit of the selected base ("0b1" in
      // hex, "0o…" in base ≥ 25): not a prefix, leave it alone.
    } else {
      fail(`Prefix 0${m[1].toLowerCase()} means base ${prefBase}, but base ${baseSel} is selected.`);
    }
  }

  const cleaned = s.replace(/[_ ]/g, "");
  if (cleaned !== s && /^[_ ]|[_ ]$/.test(s)) fail("Separators (_ or space) must sit between digits.");
  if (!cleaned) fail("No digits after the prefix.");

  let value = 0n;
  const big = BigInt(base);
  for (let i = 0; i < cleaned.length; i++) {
    const d = DIGITS.indexOf(cleaned[i].toLowerCase());
    if (d < 0 || d >= base) {
      fail(`"${cleaned[i]}" is not a base-${base} digit (position ${i + 1}).`);
    }
    value = value * big + BigInt(d);
  }
  if (negative) value = -value;
  return { value, base, negative, notes };
}

// -------------------------------------------------------------- formatting

// toBase(value, base) → lowercase digits, "-" for negatives, no prefix.
export function toBase(value, base) {
  if (base < 2 || base > 36 || !Number.isInteger(base)) fail("Base must be an integer 2–36.");
  return value.toString(base);
}

// Group digits from the right: 4 for bases 2 and 16, 3 otherwise (thousands
// style). The sign stays attached to the first group.
export function grouped(digits, base, sep = " ") {
  const neg = digits.startsWith("-");
  const d = neg ? digits.slice(1) : digits;
  const n = base === 2 || base === 16 ? 4 : 3;
  const out = [];
  for (let end = d.length; end > 0; end -= n) out.unshift(d.slice(Math.max(0, end - n), end));
  return (neg ? "-" : "") + out.join(sep);
}

// ------------------------------------------------------------- properties

export function bitLength(value) {
  const v = value < 0n ? -value : value;
  return v === 0n ? 0 : v.toString(2).length;
}

export function popcount(value) {
  const v = value < 0n ? -value : value;
  let n = 0;
  for (const c of v.toString(2)) if (c === "1") n++;
  return n;
}

export const WIDTHS = [8, 16, 32, 64, 128];

// Smallest standard width the value fits in, signed and unsigned (null if
// none up to 128).
export function fits(value) {
  const out = { unsigned: null, signed: null };
  for (const w of WIDTHS) {
    const W = BigInt(w);
    if (out.unsigned === null && value >= 0n && value < 1n << W) out.unsigned = w;
    if (out.signed === null && value >= -(1n << (W - 1n)) && value < 1n << (W - 1n)) out.signed = w;
  }
  return out;
}

// ------------------------------------------------------ two's complement

// twos(value, width) → the width-bit two's-complement pattern of value as
// { hex, bin }, or null when the value doesn't fit a signed width-bit int.
export function twos(value, width) {
  const W = BigInt(width);
  if (value < -(1n << (W - 1n)) || value >= 1n << (W - 1n)) return null;
  const pattern = value & ((1n << W) - 1n); // BigInt & is two's-complement by definition
  return {
    hex: pattern.toString(16).padStart(width / 4, "0"),
    bin: pattern.toString(2).padStart(width, "0"),
  };
}

// signedRead(value, width) → what the (non-negative) bit pattern means read
// as a signed width-bit integer, or null if it isn't a width-bit pattern.
export function signedRead(value, width) {
  const W = BigInt(width);
  if (value < 0n || value >= 1n << W) return null;
  return value >= 1n << (W - 1n) ? value - (1n << W) : value;
}

// ----------------------------------------------------------------- bytes

// Big-endian byte list of the magnitude (minimal length, at least one byte).
// Negative values take the bytes of the magnitude; two's-complement byte
// views come from twos().
export function bytes(value) {
  const v = value < 0n ? -value : value;
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(hex.slice(i, i + 2));
  return out;
}
