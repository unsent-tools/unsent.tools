// Data sizes and transfer rates: exact rational arithmetic over BigInt, so
// "1.5 GB" or "0.1 KiB" never loses precision to floating point. The
// notation rules follow the standards (SI prefixes + IEC binary prefixes;
// lowercase b = bits, uppercase B = bytes) with the common sloppy forms
// ("mb", "gb") interpreted charitably and flagged.

export class SizeError extends Error {}

// Exact prefix factors. SI are powers of 10, IEC powers of 2.
const SI = { "": 1n, k: 10n ** 3n, M: 10n ** 6n, G: 10n ** 9n, T: 10n ** 12n, P: 10n ** 15n, E: 10n ** 18n };
const IEC = { Ki: 1024n, Mi: 1024n ** 2n, Gi: 1024n ** 3n, Ti: 1024n ** 4n, Pi: 1024n ** 5n, Ei: 1024n ** 6n };

// Canonical unit table: token → { factor, bits, binary }. Case-sensitive.
const UNITS = new Map();
UNITS.set("B", { factor: 1n, bits: false, binary: false, canon: "B" });
UNITS.set("b", { factor: 1n, bits: true, binary: false, canon: "b" });
for (const [p, f] of Object.entries(SI)) {
  if (!p) continue;
  const P = p === "k" ? ["k", "K"] : [p]; // "KB" is ubiquitous for kB; accept K
  for (const pp of P) {
    UNITS.set(pp + "B", { factor: f, bits: false, binary: false, canon: p + "B" });
    UNITS.set(pp + "b", { factor: f, bits: true, binary: false, canon: p + "b" });
  }
}
for (const [p, f] of Object.entries(IEC)) {
  UNITS.set(p + "B", { factor: f, bits: false, binary: true, canon: p + "B" });
  UNITS.set(p + "b", { factor: f, bits: true, binary: true, canon: p + "b" });
}

const WORDS = new Map([["byte", "B"], ["bytes", "B"], ["bit", "b"], ["bits", "b"], ["octet", "B"], ["octets", "B"]]);
// "megabyte" etc.
const PREFIX_WORDS = { kilo: "k", mega: "M", giga: "G", tera: "T", peta: "P", exa: "E", kibi: "Ki", mebi: "Mi", gibi: "Gi", tebi: "Ti", pebi: "Pi", exbi: "Ei" };

function gcd(a, b) { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; }

export function rational(num, den = 1n) {
  if (den === 0n) throw new SizeError("division by zero");
  if (den < 0n) { num = -num; den = -den; }
  const g = gcd(num, den) || 1n;
  return { num: num / g, den: den / g };
}
export const rMul = (a, b) => rational(a.num * b.num, a.den * b.den);
export const rDiv = (a, b) => { if (b.num === 0n) throw new SizeError("division by zero"); return rational(a.num * b.den, a.den * b.num); };
export const rCmp = (a, b) => { const d = a.num * b.den - b.num * a.den; return d < 0n ? -1 : d > 0n ? 1 : 0; };

// Decimal rendering of an exact rational, rounded (half away from zero) to
// `sig` significant digits; trailing fraction zeros trimmed, so exactly
// representable values print exactly.
export function rationalToDecimal(r, sig = 4) {
  if (r.num === 0n) return "0";
  const neg = r.num < 0n;
  const num = neg ? -r.num : r.num, den = r.den;
  // Decimal exponent e: num/den is in [10^e, 10^(e+1)).
  let e;
  if (num >= den) e = (num / den).toString().length - 1;
  else { e = -1; let x = num * 10n; while (x < den) { x *= 10n; e--; } }
  // q = round(num/den × 10^(sig-1-e)) — an integer with `sig` digits.
  const s = sig - 1 - e;
  let q = s >= 0
    ? (2n * num * 10n ** BigInt(s) + den) / (2n * den)
    : (2n * num + den * 10n ** BigInt(-s)) / (2n * den * 10n ** BigInt(-s));
  if (q.toString().length > sig) { q /= 10n; e += 1; } // 999.7 → 1000 overflow
  let digits = q.toString().padStart(sig, "0");
  let out;
  if (e >= sig - 1) out = digits + "0".repeat(e - sig + 1);
  else if (e >= 0) {
    const fp = digits.slice(e + 1).replace(/0+$/, "");
    out = digits.slice(0, e + 1) + (fp ? "." + fp : "");
  } else {
    const fp = ("0".repeat(-e - 1) + digits).replace(/0+$/, "");
    out = "0" + (fp ? "." + fp : "");
  }
  return (neg ? "-" : "") + out;
}

// Parse a decimal mantissa (digits, optional point, optional e-notation,
// commas/underscores as separators) into an exact rational.
export function parseMantissa(s) {
  const cleaned = s.replace(/[,_\s]/g, "");
  const m = /^([+-]?)(\d+(?:\.\d*)?|\.\d+)(?:[eE]([+-]?\d+))?$/.exec(cleaned);
  if (!m) throw new SizeError(`"${s}" is not a number`);
  const [, sign, body, expStr] = m;
  const [int = "0", frac = ""] = body.split(".");
  let num = BigInt((int + frac).replace(/^$/, "0"));
  let den = 10n ** BigInt(frac.length);
  const exp = expStr ? parseInt(expStr, 10) : 0;
  if (exp > 0) num *= 10n ** BigInt(exp);
  else if (exp < 0) den *= 10n ** BigInt(-exp);
  if (sign === "-") num = -num;
  return rational(num, den);
}

function lookupUnit(tok) {
  if (UNITS.has(tok)) return { unit: UNITS.get(tok), sloppy: false };
  const w = tok.toLowerCase();
  if (WORDS.has(w)) return { unit: UNITS.get(WORDS.get(w)), sloppy: false };
  // Whole words: "megabytes", "gibibits"…
  const pw = /^([a-z]+?)(bytes?|bits?|octets?)$/.exec(w);
  if (pw && PREFIX_WORDS[pw[1]]) {
    const letter = pw[2].startsWith("byte") || pw[2].startsWith("octet") ? "B" : "b";
    return { unit: UNITS.get(PREFIX_WORDS[pw[1]] + letter), sloppy: false };
  }
  // Letter prefix + whole word: "Mbit", "kbyte", "Gibit" — the word makes
  // bits vs bytes explicit, so any prefix case is unambiguous.
  const lb = /^([kKmMgGtTpPeE])(i?)(bits?|bytes?|octets?)$/i.exec(tok);
  if (lb) {
    const letter = lb[3].toLowerCase().startsWith("bit") ? "b" : "B";
    const prefix = lb[2] ? lb[1].toUpperCase() + "i" : lb[1].toLowerCase() === "k" ? "k" : lb[1].toUpperCase();
    return { unit: UNITS.get(prefix + letter), sloppy: false };
  }
  // Sloppy case: "mb", "GB " typed as "gb", "kib"… Assume bytes (the common
  // intent) and let the caller surface the bits alternative.
  const sc = /^([kmgtpe])(i?)b$/.exec(w);
  if (sc) {
    const prefix = (sc[2] ? sc[1].toUpperCase() + "i" : sc[1] === "k" ? "k" : sc[1].toUpperCase());
    return { unit: UNITS.get(prefix + "B"), sloppy: true, altUnit: UNITS.get(prefix + "b") };
  }
  return null;
}

// Parse a size like "1.5 GB", "3 GiB", "1500000", "2 megabytes", "512 Kib".
// Returns { bytes, bits, unit, sloppy, alt } where bytes/bits are exact
// rationals and alt is the bits-reading of a sloppy unit.
export function parseSize(input) {
  const s = input.trim();
  if (!s) throw new SizeError("empty size");
  const m = /^(.*?)\s*([A-Za-z]+)?$/s.exec(s);
  let numText = m[1], unitTok = m[2] ?? "";
  if (!numText && unitTok) throw new SizeError(`"${input}": no number`);
  const value = parseMantissa(numText);
  if (value.num < 0n) throw new SizeError("sizes cannot be negative");
  let unit = UNITS.get("B"), sloppy = false, altUnit = null;
  if (unitTok) {
    const found = lookupUnit(unitTok);
    if (!found) throw new SizeError(`"${unitTok}" is not a recognized unit (B, kB, MB…, KiB, MiB…, bit, kb, Mb…)`);
    unit = found.unit; sloppy = found.sloppy; altUnit = found.altUnit ?? null;
  }
  const scaled = rMul(value, { num: unit.factor, den: 1n });
  const bytes = unit.bits ? rDiv(scaled, { num: 8n, den: 1n }) : scaled;
  const out = {
    input: s, value, unit: unit.canon, isBits: unit.bits, binary: unit.binary, sloppy,
    bytes, bits: rMul(bytes, { num: 8n, den: 1n }),
  };
  if (altUnit) {
    const altScaled = rMul(value, { num: altUnit.factor, den: 1n });
    out.alt = { unit: altUnit.canon, bytes: rDiv(altScaled, { num: 8n, den: 1n }) };
  }
  return out;
}

// Parse a rate: "100 Mbps", "12 MB/s", "1 Gbit/s". Returns bits/second and
// bytes/second as rationals. "…bps"/"…b/s" forms are always bits.
export function parseRate(input) {
  const s = input.trim();
  if (!s) throw new SizeError("empty rate");
  let m = /^(.*?)\s*([A-Za-z]*)bps$/s.exec(s);
  if (m) {
    // "bps" pins bits regardless of prefix case: mbps, Mbps, MBps all common.
    const prefixTok = m[2] ?? "";
    const p = prefixTok === "" ? "" : prefixTok.length <= 2 && /i$/.test(prefixTok)
      ? prefixTok[0].toUpperCase() + "i"
      : prefixTok === "k" || prefixTok.toLowerCase() === "k" ? "k" : prefixTok.toUpperCase();
    const factor = SI[p] ?? IEC[p];
    if (factor === undefined) throw new SizeError(`"${s}": unknown rate prefix "${prefixTok}"`);
    const value = parseMantissa(m[1]);
    const bits = rMul(value, { num: factor, den: 1n });
    return { input: s, bitsPerSec: bits, bytesPerSec: rDiv(bits, { num: 8n, den: 1n }), unit: (p || "") + "bps", isBits: true, sloppy: false };
  }
  m = /^(.*?)\s*([A-Za-z]*)Bps$/s.exec(s);
  if (m) { // "MBps" = megabytes per second
    const size = parseSize(`${m[1]} ${m[2]}B`);
    return { input: s, bitsPerSec: size.bits, bytesPerSec: size.bytes, unit: size.unit + "/s", isBits: false, sloppy: size.sloppy };
  }
  m = /^(.*?)\s*([A-Za-z]+)\s*(?:\/\s*s(?:ec(?:ond)?)?|per\s+s(?:ec(?:ond)?)?)$/s.exec(s);
  if (!m) throw new SizeError(`"${s}" is not a rate — write it like "100 Mbps" or "12 MB/s"`);
  const size = parseSize(`${m[1]} ${m[2]}`);
  return { input: s, bitsPerSec: size.bits, bytesPerSec: size.bytes, unit: size.unit + "/s", isBits: size.isBits, sloppy: size.sloppy, alt: size.alt };
}

// Best display unit: largest unit with value >= 1 (or the smallest).
export function autoUnit(bytes, { binary = false, bits = false } = {}) {
  const prefixes = binary ? ["Ei", "Pi", "Ti", "Gi", "Mi", "Ki"] : ["E", "P", "T", "G", "M", "k"];
  const base = bits ? rMul(bytes, { num: 8n, den: 1n }) : bytes;
  for (const p of prefixes) {
    const f = (binary ? IEC : SI)[p];
    if (rCmp(base, { num: f, den: 1n }) >= 0) {
      return { unit: p + (bits ? "b" : "B"), text: rationalToDecimal(rDiv(base, { num: f, den: 1n }), 4) };
    }
  }
  return { unit: bits ? "b" : "B", text: rationalToDecimal(base, 4) };
}

export function convertTable(bytes) {
  const rows = [];
  const exact = bytes.den === 1n;
  rows.push({ unit: "bytes", text: exact ? bytes.num.toString() : rationalToDecimal(bytes, 20), exact });
  const bits = rMul(bytes, { num: 8n, den: 1n });
  rows.push({ unit: "bits", text: bits.den === 1n ? bits.num.toString() : rationalToDecimal(bits, 20), exact: bits.den === 1n });
  // Exact integers print in full; anything else rounds to 6 significant digits.
  const cell = (r) => r.den === 1n ? r.num.toString() : rationalToDecimal(r, 6);
  for (const p of ["k", "M", "G", "T", "P"]) rows.push({ unit: p + "B", text: cell(rDiv(bytes, { num: SI[p], den: 1n })) });
  for (const p of ["Ki", "Mi", "Gi", "Ti", "Pi"]) rows.push({ unit: p + "B", text: cell(rDiv(bytes, { num: IEC[p], den: 1n })) });
  return rows;
}

// Exact transfer time in seconds for a size over a rate.
export function transferSeconds(size, rate) {
  if (rate.bitsPerSec.num === 0n) throw new SizeError("rate is zero");
  return rDiv(size.bits, rate.bitsPerSec);
}

export function formatDuration(secs) {
  if (secs.num === 0n) return "0 s";
  const asNum = Number(secs.num) / Number(secs.den);
  if (asNum < 1e-3) return rationalToDecimal(rMul(secs, { num: 10n ** 6n, den: 1n }), 3) + " µs";
  if (asNum < 1) return rationalToDecimal(rMul(secs, { num: 10n ** 3n, den: 1n }), 3) + " ms";
  if (asNum < 90) return rationalToDecimal(secs, 3) + " s";
  const total = secs.num / secs.den; // whole seconds
  const d = total / 86400n, h = (total % 86400n) / 3600n, min = (total % 3600n) / 60n, sr = total % 60n;
  const parts = [];
  if (d) parts.push(d + " d");
  if (h) parts.push(h + " h");
  if (min && !d) parts.push(min + " min");
  if (sr && !d && !h) parts.push(sr + " s");
  return parts.join(" ");
}
