// Tests for unicode.js. Oracles: Python's unicodedata (names, categories,
// normalization — same UCD 15.0.0 version as our generated data, but an
// independent decoder of it), and Node's own ICU via \p{Script=...} regexes
// for the script table. Known divergence, verified here: Python returns
// None for Tangut ideograph names; we follow the standard's algorithmic
// naming for them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  codepointName, category, script, inspect, UNICODE_VERSION, CATEGORY_NAMES,
} from "./unicode.js";

const py = (script_, input) =>
  execFileSync("python3", ["-c", script_], {
    input: JSON.stringify(input), encoding: "utf8", maxBuffer: 1 << 26,
  });

function rng(seed) {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}

// A deliberately structured sample: every codepoint below 0x300, random
// points across the whole space, and dense samples inside the algorithmic
// ranges (Hangul, CJK, Tangut) and around block edges.
function sampleCodepoints() {
  const r = rng(7);
  const cps = [];
  for (let cp = 0; cp < 0x300; cp++) cps.push(cp);
  for (let i = 0; i < 4000; i++) cps.push(Math.floor(r() * 0x110000));
  for (let i = 0; i < 300; i++) cps.push(0xac00 + Math.floor(r() * 11172)); // Hangul
  for (let i = 0; i < 200; i++) cps.push(0x4e00 + Math.floor(r() * 0x5200)); // CJK
  for (let i = 0; i < 100; i++) cps.push(0x17000 + Math.floor(r() * 0x18f8)); // Tangut
  for (const edge of [0xd800, 0xdfff, 0xe000, 0xf8ff, 0x10ffff, 0xac00, 0xd7a3,
                      0x3400, 0x4dbf, 0x2a6df, 0x323af, 0xe0000, 0xe01ef]) cps.push(edge);
  return [...new Set(cps)].sort((a, b) => a - b);
}

test("codepointName + category differential vs Python unicodedata", () => {
  const cps = sampleCodepoints();
  const expected = JSON.parse(py(`
import sys, json, unicodedata
out = []
for cp in json.load(sys.stdin):
    ch = chr(cp)
    out.append([unicodedata.name(ch, None), unicodedata.category(ch)])
print(json.dumps(out))
`, cps));
  let checked = 0;
  cps.forEach((cp, i) => {
    const [pyName, pyCat] = expected[i];
    assert.equal(category(cp), pyCat, `category of U+${cp.toString(16)}`);
    const mine = codepointName(cp);
    if (pyName === null && cp >= 0x17000 && cp <= 0x18d7f) {
      // Tangut: Python has no algorithmic names here; we follow the standard.
      if (mine !== null) {
        assert.match(mine, /^TANGUT (IDEOGRAPH|COMPONENT)/, `U+${cp.toString(16)}`);
      }
      return;
    }
    assert.equal(mine, pyName, `name of U+${cp.toString(16)}`);
    checked++;
  });
  assert.ok(checked > 4000, `checked ${checked} codepoints`);
});

test("script table differential vs Node's own ICU (\\p{Script=...})", () => {
  // Only for codepoints assigned in our UCD version — ICU here is newer
  // (Unicode 17) and later versions assign new characters, but existing
  // script assignments are stable.
  const cps = sampleCodepoints().filter(
    (cp) => category(cp) !== "Cn" && category(cp) !== "Cs");
  const cache = new Map();
  let checked = 0;
  for (const cp of cps) {
    const sc = script(cp);
    if (sc === "Unknown") continue;
    if (!cache.has(sc)) {
      try { cache.set(sc, new RegExp(`^\\p{Script=${sc}}$`, "u")); }
      catch { cache.set(sc, null); } // script name unknown to this ICU
    }
    const re = cache.get(sc);
    if (!re) continue;
    assert.ok(re.test(String.fromCodePoint(cp)),
              `U+${cp.toString(16)} should be Script=${sc}`);
    checked++;
  }
  assert.ok(checked > 1500, `checked ${checked} codepoints`);
});

test("Hangul syllable names: full-range spot checks vs the standard", () => {
  assert.equal(codepointName(0xac00), "HANGUL SYLLABLE GA");
  assert.equal(codepointName(0xd7a3), "HANGUL SYLLABLE HIH");
  assert.equal(codepointName(0xd55c), "HANGUL SYLLABLE HAN");
  assert.equal(codepointName(0xae00), "HANGUL SYLLABLE GEUL");
  assert.equal(codepointName(0x4e2d), "CJK UNIFIED IDEOGRAPH-4E2D");
  assert.equal(codepointName(0x17000), "TANGUT IDEOGRAPH-17000");
  assert.equal(codepointName(0xd800), null); // surrogate
  assert.equal(codepointName(0xe000), null); // private use
  assert.equal(codepointName(0x10fffe), null); // unassigned/PUA plane
});

test("normalization differential vs Python (15.0-assigned chars only)", () => {
  const r = rng(9);
  const pool = "eaoú̧̀̈ﬁﬂ½㎒Ａｂｃ한글ǅẛϓẛÅ°C√２";
  const cases = [];
  for (let i = 0; i < 150; i++) {
    let s = "";
    const n = 1 + Math.floor(r() * 8);
    for (let j = 0; j < n; j++) s += pool[Math.floor(r() * pool.length)];
    cases.push(s);
  }
  const expected = JSON.parse(py(`
import sys, json, unicodedata
out = [[unicodedata.normalize(f, s) for f in ("NFC","NFD","NFKC","NFKD")]
       for s in json.load(sys.stdin)]
print(json.dumps(out))
`, cases));
  cases.forEach((s, i) => {
    const forms = inspect(s).forms;
    ["NFC", "NFD", "NFKC", "NFKD"].forEach((f, j) => {
      assert.equal(forms[f].text, expected[i][j], `${f} of ${JSON.stringify(s)}`);
      assert.equal(forms[f].changed, expected[i][j] !== s);
    });
  });
});

test("inspect counts: graphemes vs codepoints vs units vs bytes", () => {
  const cases = [
    // [string, graphemes, codepoints, utf16, utf8]
    ["hello", 5, 5, 5, 5],
    ["café", 4, 4, 4, 5],
    ["café", 4, 5, 5, 6],
    ["👍🏽", 1, 2, 4, 8],
    ["👨‍👩‍👧‍👦", 1, 7, 11, 25], // family: 4 people + 3 ZWJ
    ["🇩🇪", 1, 2, 4, 8],        // flag: 2 regional indicators
    ["한", 1, 1, 1, 3],
    ["", 0, 0, 0, 0],
  ];
  const pyBytes = JSON.parse(py(`
import sys, json
print(json.dumps([len(s.encode("utf-8")) for s in json.load(sys.stdin)]))
`, cases.map((c) => c[0])));
  cases.forEach(([s, g, cp, u16, u8], i) => {
    const { counts } = inspect(s);
    assert.deepEqual(
      [counts.graphemes, counts.codepoints, counts.utf16Units, counts.utf8Bytes],
      [g, cp, u16, u8], JSON.stringify(s));
    assert.equal(u8, pyBytes[i], `python utf8 length of ${JSON.stringify(s)}`);
  });
});

test("warnings: bidi controls, invisibles, tag characters, controls", () => {
  const bidi = inspect("user‮ cod.exe");
  assert.ok(bidi.warnings.some((w) => /Trojan Source/.test(w)), bidi.warnings);
  const zw = inspect("pass​word﻿");
  assert.ok(zw.warnings.some((w) => /Invisible characters/.test(w)));
  assert.ok(zw.warnings.some((w) => /ZERO WIDTH SPACE/.test(w)));
  const tag = inspect("hi" + [...`secret`].map((c) =>
    String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join(""));
  assert.ok(tag.warnings.some((w) => /tag character/.test(w)), tag.warnings);
  const ctl = inspect("a\u0007b\u001bc");
  assert.ok(ctl.warnings.some((w) => /2 control characters/.test(w)), ctl.warnings);
  const clean = inspect("just a normal sentence, with punctuation!");
  assert.deepEqual(clean.warnings, []);
  assert.deepEqual(clean.notes, []);
});

test("warnings: mixed-script homograph and space lookalikes", () => {
  const spoof = inspect("pаypal.com"); // Cyrillic а
  const all = spoof.warnings.join("\n");
  assert.match(all, /Mixed scripts: Cyrillic, Latin/);
  assert.match(all, /U\+0430 Cyrillic “а” \(resembles Latin “a”\)/);
  const nbsp = inspect("price: 10 EUR");
  assert.ok(nbsp.notes.some((n) => /no-break space/i.test(n)), nbsp.notes);
  // All-Cyrillic text is NOT flagged as mixed (it isn't spoofing anything).
  const russian = inspect("привет мир");
  assert.deepEqual(russian.warnings, []);
});

test("warnings: unassigned, private use, variation selectors, zalgo", () => {
  const un = inspect(String.fromCodePoint(0x10fffe) + "x" + String.fromCodePoint(0xe000));
  assert.ok(un.warnings.some((w) => /unassigned/.test(w)));
  assert.ok(un.notes.some((n) => /private-use/.test(n)));
  const emoji = inspect("snow ☃️");
  assert.ok(emoji.notes.some((n) => /variation selector/.test(n)), emoji.notes);
  const zalgo = inspect("z̴̢̘a̶͚̝o");
  assert.ok(zalgo.notes.some((n) => /combining marks/.test(n)), zalgo.notes);
});

test("per-char details are coherent", () => {
  const { chars } = inspect("A€👍");
  assert.deepEqual(chars.map((c) => c.hex), ["U+0041", "U+20AC", "U+1F44D"]);
  assert.deepEqual(chars.map((c) => c.name),
    ["LATIN CAPITAL LETTER A", "EURO SIGN", "THUMBS UP SIGN"]);
  assert.deepEqual(chars.map((c) => c.category), ["Lu", "Sc", "So"]);
  assert.deepEqual(chars.map((c) => c.script), ["Latin", "Common", "Common"]);
  assert.deepEqual(chars[1].utf8, [0xe2, 0x82, 0xac]);
  assert.equal(chars[2].utf16Units, 2);
  assert.equal(UNICODE_VERSION, "15.0.0");
  assert.equal(CATEGORY_NAMES.Sc, "currency symbol");
});
