// unicode.js — string inspection: codepoint names/categories/scripts,
// normalization, and content warnings (invisibles, bidi controls, mixed
// scripts). Character data is generated from UCD 15.0.0 by build-data.py
// into data.js; names for Tangut ideographs follow the standard even though
// Python's unicodedata (one of our test oracles) returns None for them.

import {
  UNICODE_VERSION, WORDS, NAMES, ALGO_RANGES,
  CATS, CATBOUNDS, SCRIPTS, SCRIPTBOUNDS,
} from "./data.js";

export { UNICODE_VERSION };

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const AIDX = new Map([...ALPHABET].map((c, i) => [c, i]));

// Stream of varints: chars 0..31 terminate a value, 32..63 continue it,
// 5 bits per char, little-endian.
function* varints(s) {
  let acc = 0, shift = 0;
  for (const c of s) {
    const v = AIDX.get(c);
    if (v >= 32) { acc |= (v - 32) << shift; shift += 5; }
    else { yield acc | (v << shift); acc = 0; shift = 0; }
  }
}

let NAME_MAP = null;
function nameMap() {
  if (NAME_MAP) return NAME_MAP;
  NAME_MAP = new Map();
  const it = varints(NAMES);
  let cp = 0;
  for (;;) {
    const delta = it.next();
    if (delta.done) break;
    cp += delta.value;
    const words = [];
    for (;;) {
      const w = it.next().value;
      if (w === 0) break;
      let word = WORDS[w - 1];
      if (word.endsWith("-#")) {
        word = word.slice(0, -1) + cp.toString(16).toUpperCase().padStart(4, "0");
      }
      words.push(word);
    }
    NAME_MAP.set(cp, words.join(" "));
  }
  return NAME_MAP;
}

function boundsTable(packed, labels) {
  const starts = [], values = [];
  const it = varints(packed);
  let cp = 0, first = true;
  for (;;) {
    const d = it.next();
    if (d.done) break;
    cp += first ? d.value : d.value;
    first = false;
    starts.push(cp);
    values.push(labels[it.next().value]);
  }
  return { starts, values };
}
let CAT_TABLE = null, SCRIPT_TABLE = null;

function lookupBounds(table, cp) {
  let lo = 0, hi = table.starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (table.starts[mid] <= cp) lo = mid; else hi = mid - 1;
  }
  return table.values[lo];
}

// Hangul syllable name composition (Unicode ch. 3.12).
const HANGUL_L = ["G","GG","N","D","DD","R","M","B","BB","S","SS","","J","JJ","C","K","T","P","H"];
const HANGUL_V = ["A","AE","YA","YAE","EO","E","YEO","YE","O","WA","WAE","OE","YO","U","WEO","WE","WI","YU","EU","YI","I"];
const HANGUL_T = ["","G","GG","GS","N","NJ","NH","D","L","LG","LM","LB","LS","LT","LP","LH","M","B","BS","S","SS","NG","J","C","K","T","P","H"];

export function codepointName(cp) {
  const m = nameMap();
  if (m.has(cp)) return m.get(cp);
  for (const [first, last, prefix] of ALGO_RANGES) {
    if (cp < first || cp > last) continue;
    if (prefix === null) return null; // surrogates, private use
    if (prefix === "HANGUL") {
      const s = cp - 0xac00;
      return "HANGUL SYLLABLE " + HANGUL_L[Math.floor(s / 588)] +
             HANGUL_V[Math.floor((s % 588) / 28)] + HANGUL_T[s % 28];
    }
    return prefix + "-" + cp.toString(16).toUpperCase().padStart(4, "0");
  }
  return null;
}

export function category(cp) {
  CAT_TABLE ??= boundsTable(CATBOUNDS, CATS);
  return lookupBounds(CAT_TABLE, cp);
}

export function script(cp) {
  SCRIPT_TABLE ??= boundsTable(SCRIPTBOUNDS, SCRIPTS);
  return lookupBounds(SCRIPT_TABLE, cp);
}

export const CATEGORY_NAMES = {
  Lu: "uppercase letter", Ll: "lowercase letter", Lt: "titlecase letter",
  Lm: "modifier letter", Lo: "other letter", Mn: "nonspacing mark",
  Mc: "spacing mark", Me: "enclosing mark", Nd: "decimal digit",
  Nl: "letter number", No: "other number", Pc: "connector punctuation",
  Pd: "dash", Ps: "open punctuation", Pe: "close punctuation",
  Pi: "initial quote", Pf: "final quote", Po: "other punctuation",
  Sm: "math symbol", Sc: "currency symbol", Sk: "modifier symbol",
  So: "other symbol", Zs: "space separator", Zl: "line separator",
  Zp: "paragraph separator", Cc: "control", Cf: "format",
  Cs: "surrogate", Co: "private use", Cn: "unassigned",
};

// ---------------------------------------------------------------------------
// Character classes that deserve a callout

const BIDI_CONTROLS = new Set([0x061c, 0x200e, 0x200f,
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);
const INVISIBLES = new Map([
  [0x00ad, "soft hyphen"], [0x034f, "combining grapheme joiner"],
  [0x180e, "Mongolian vowel separator"], [0x200b, "zero-width space"],
  [0x200c, "zero-width non-joiner"], [0x200d, "zero-width joiner"],
  [0x2060, "word joiner"], [0xfeff, "zero-width no-break space / BOM"],
]);
const SPACE_LOOKALIKES = new Map([
  [0x00a0, "no-break space"], [0x1680, "ogham space mark"],
  [0x202f, "narrow no-break space"], [0x205f, "medium mathematical space"],
  [0x3000, "ideographic space"],
]);
for (let cp = 0x2000; cp <= 0x200a; cp++) SPACE_LOOKALIKES.set(cp, "typographic space");

// The classic Latin-lookalike confusables (a deliberately small, curated
// set: full UTS #39 confusables data is out of scope).
const LOOKALIKES = new Map(Object.entries({
  "а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","ѕ":"s","і":"i",
  "ј":"j","һ":"h","ԁ":"d","ԛ":"q","ԝ":"w","ѵ":"v","ё":"e",
  "А":"A","В":"B","Е":"E","З":"3","К":"K","М":"M","Н":"H","О":"O","Р":"P",
  "С":"C","Т":"T","Х":"X","Ѕ":"S","І":"I","Ј":"J","Ү":"Y","ϲ":"c",
  "ο":"o","ν":"v","Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K",
  "Μ":"M","Ν":"N","Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X","ω":"w",
  "ӏ":"l","Ӏ":"I","ꞅ":"s","ı":"i","ȷ":"j",
}).map(([k, v]) => [k.codePointAt(0), v]));

// ---------------------------------------------------------------------------

export function inspect(str) {
  const s = String(str);
  const cps = [...s];
  const encoder = new TextEncoder();
  const chars = cps.map((ch) => {
    const cp = ch.codePointAt(0);
    return {
      char: ch,
      cp,
      hex: "U+" + cp.toString(16).toUpperCase().padStart(4, "0"),
      name: codepointName(cp),
      category: category(cp),
      script: script(cp),
      utf8: [...encoder.encode(ch)],
      utf16Units: ch.length,
    };
  });

  let graphemes = null;
  if (typeof Intl !== "undefined" && Intl.Segmenter) {
    graphemes = [...new Intl.Segmenter("und", { granularity: "grapheme" }).segment(s)]
      .map((seg) => seg.segment);
  }

  const counts = {
    graphemes: graphemes ? graphemes.length : null,
    codepoints: cps.length,
    utf16Units: s.length,
    utf8Bytes: encoder.encode(s).length,
  };

  const forms = {};
  for (const f of ["NFC", "NFD", "NFKC", "NFKD"]) {
    const n = s.normalize(f);
    forms[f] = { text: n, changed: n !== s };
  }

  const warnings = [], notes = [];
  const found = (pred) => chars.filter((c) => pred(c));

  const bidi = found((c) => BIDI_CONTROLS.has(c.cp));
  if (bidi.length) {
    warnings.push(`Bidirectional control characters (${describeSet(bidi)}). These can visually reorder text — the "Trojan Source" trick; what you see is not the stored order.`);
  }
  const tags = found((c) => c.cp >= 0xe0000 && c.cp <= 0xe007f);
  if (tags.length) {
    warnings.push(`${tags.length} tag character${tags.length > 1 ? "s" : ""} (U+E0000 block) — invisible codepoints sometimes used to smuggle hidden text or watermarks.`);
  }
  const invis = found((c) => INVISIBLES.has(c.cp));
  if (invis.length) {
    warnings.push(`Invisible characters: ${describeSet(invis)}. They survive copy-paste and make visually identical strings compare unequal.`);
  }
  const spaces = found((c) => SPACE_LOOKALIKES.has(c.cp));
  if (spaces.length) {
    notes.push(`Space lookalikes: ${describeSet(spaces)} — these are not an ordinary space (U+0020).`);
  }
  const controls = found((c) => c.category === "Cc" && ![0x09, 0x0a, 0x0d].includes(c.cp));
  if (controls.length) {
    warnings.push(`${controls.length} control character${controls.length > 1 ? "s" : ""}: ${describeSet(controls)}.`);
  }

  const letterScripts = new Set(
    chars.filter((c) => c.category.startsWith("L")).map((c) => c.script)
      .filter((sc) => !["Common", "Inherited", "Unknown"].includes(sc)));
  const lookalikes = found((c) => LOOKALIKES.has(c.cp));
  if (letterScripts.size > 1) {
    let msg = `Mixed scripts: ${[...letterScripts].sort().join(", ")}.`;
    if (lookalikes.length) {
      msg += " Lookalike letters present: " + lookalikes.map((c) =>
        `${c.hex} ${c.script} “${c.char}” (resembles Latin “${LOOKALIKES.get(c.cp)}”)`).join(", ") +
        " — the classic homograph-spoofing setup.";
    }
    warnings.push(msg);
  } else if (lookalikes.length && !chars.some((c) => c.script === "Latin")) {
    notes.push(`Contains ${lookalikes.map((c) => `“${c.char}” (${c.script})`).join(", ")} — visually similar to Latin letters.`);
  }

  const unassigned = found((c) => c.category === "Cn");
  if (unassigned.length) warnings.push(`${unassigned.length} unassigned codepoint${unassigned.length > 1 ? "s" : ""} (not in Unicode ${UNICODE_VERSION}): ${describeSet(unassigned)}.`);
  const pua = found((c) => c.category === "Co");
  if (pua.length) notes.push(`${pua.length} private-use codepoint${pua.length > 1 ? "s" : ""} — meaning depends entirely on the font/application.`);
  const marks = found((c) => c.category.startsWith("M"));
  if (graphemes && graphemes.some((g) => [...g].filter((ch) => category(ch.codePointAt(0)).startsWith("M")).length >= 3)) {
    notes.push("A single grapheme stacks 3+ combining marks (z̴̢̘a̶͚͝l̷̠͋g̸̻̈o̵̯͠-style text does this).");
  } else if (marks.length) {
    notes.push(`${marks.length} combining mark${marks.length > 1 ? "s" : ""} — characters that modify the previous one.`);
  }
  const vs = found((c) => (c.cp >= 0xfe00 && c.cp <= 0xfe0f) || (c.cp >= 0xe0100 && c.cp <= 0xe01ef));
  if (vs.length) notes.push(`${vs.length} variation selector${vs.length > 1 ? "s" : ""} — invisible glyph-variant hints (emoji vs text style, CJK variants).`);

  return { chars, graphemes, counts, forms, warnings, notes };
}

function describeSet(list) {
  const seen = new Map();
  for (const c of list) {
    if (!seen.has(c.cp)) seen.set(c.cp, { c, n: 0 });
    seen.get(c.cp).n++;
  }
  return [...seen.values()].map(({ c, n }) =>
    `${c.hex}${c.name ? " " + c.name : ""}${n > 1 ? ` ×${n}` : ""}`).join(", ");
}
