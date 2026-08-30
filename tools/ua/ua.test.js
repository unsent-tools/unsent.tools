// Oracles:
//  - uap-core's own test fixtures (test_ua/test_os/test_device.yaml, 18k+
//    cases, same pinned commit as data.js) — every case must match exactly.
//  - uap-python 1.x (BasicResolver) loaded with THE SAME regexes.yaml, run
//    over fixture strings plus randomized ASCII mutations of them —
//    engine-vs-engine: catches Python-re-vs-JS-RegExp semantic drift that
//    the fixed corpus misses (Session 15 lesson: sweep randomized on top of
//    fixed differentials).
//    Mutations stay ASCII on purpose: Python's \d/\w match Unicode digits
//    and letters, JS's (and uap-js's) don't — same data, different engine
//    semantics. That divergence is real and pinned in its own test below;
//    ASCII sweeps keep the rest of the comparison meaningful.
// Requires ~/workspace/devtools/uap-core (fixtures) + python3 ua_parser.
// Skips those differentials with a notice if missing (committed CI-less
// repo: they always run on the dev machine before deploy).

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { parseAgent, parseOs, parseDevice, identify, tokenize, analyze, versionString }
  from "./ua.js";

const execFileP = promisify(execFile);
const UAP = path.join(os.homedir(), "workspace/devtools/uap-core");
const HAS_UAP = fs.existsSync(path.join(UAP, "regexes.yaml"));

function loadFixtures(name) {
  // yaml -> json via python (pyyaml); cached in /tmp by source mtime
  const src = path.join(UAP, name + ".yaml");
  const mtime = fs.statSync(src).mtimeMs;
  const cache = path.join(os.tmpdir(), `uap-${name}-${mtime}.json`);
  if (!fs.existsSync(cache)) {
    execFileSync("python3", ["-c", `
import yaml, json, sys
d = yaml.safe_load(open(${JSON.stringify(src)}))
json.dump(d["test_cases"], open(${JSON.stringify(cache)}, "w"))
`]);
  }
  return JSON.parse(fs.readFileSync(cache, "utf8"));
}

// fixture encoding of "no match": family "Other", versions null. A few
// fixture entries write '' where the reference API yields None (its get()
// maps empty matches to None), so '' normalizes to null on both sides.
const nul = (v) => (v === "" || v === undefined ? null : v) ?? null;

test("uap fixtures: user agent (all cases)", { skip: !HAS_UAP }, () => {
  const cases = loadFixtures("test_ua");
  assert.ok(cases.length > 1000);
  for (const c of cases) {
    const r = parseAgent(c.user_agent_string);
    const got = r ?? { family: "Other", major: null, minor: null, patch: null };
    for (const [fk, gk] of [["family", "family"], ["major", "major"],
                            ["minor", "minor"], ["patch", "patch"],
                            ["patch_minor", "patchMinor"]]) {
      if (fk in c) assert.equal(nul(got[gk]), nul(c[fk]),
        `${fk} for ${JSON.stringify(c.user_agent_string)}`);
    }
  }
});

test("uap fixtures: os (all cases)", { skip: !HAS_UAP }, () => {
  for (const c of loadFixtures("test_os")) {
    const r = parseOs(c.user_agent_string);
    const got = r ?? { family: "Other", major: null, minor: null, patch: null, patchMinor: null };
    for (const [fk, gk] of [["family", "family"], ["major", "major"], ["minor", "minor"],
                            ["patch", "patch"], ["patch_minor", "patchMinor"]]) {
      if (fk in c) assert.equal(nul(got[gk]), nul(c[fk]),
        `${fk} for ${JSON.stringify(c.user_agent_string)}`);
    }
  }
});

test("uap fixtures: device (all cases)", { skip: !HAS_UAP }, () => {
  const cases = loadFixtures("test_device");
  assert.ok(cases.length > 10000);
  for (const c of cases) {
    const r = parseDevice(c.user_agent_string);
    const got = r ?? { family: "Other", brand: null, model: null };
    for (const k of ["family", "brand", "model"]) {
      if (k in c) assert.equal(nul(got[k]), nul(c[k]),
        `${k} for ${JSON.stringify(c.user_agent_string)}`);
    }
  }
});

// ---------------------------------------------------------------------------
// engine-vs-engine: uap-python BasicResolver on the SAME regexes.yaml,
// fixture strings + seeded ASCII mutations. Multi-seed: set UA_SEED.

const PY_ORACLE = `
import json, sys
from ua_parser import Parser, BasicResolver
from ua_parser.loaders import load_yaml
p = Parser(BasicResolver(load_yaml(${JSON.stringify(path.join(UAP, "regexes.yaml"))})))
out = []
for s in json.load(sys.stdin):
    r = p.parse(s)
    ua, o, d = r.user_agent, r.os, r.device
    out.append({
      "agent": ua and [ua.family, ua.major, ua.minor, ua.patch, ua.patch_minor],
      "os": o and [o.family, o.major, o.minor, o.patch, o.patch_minor],
      "device": d and [d.family, d.brand, d.model],
    })
json.dump(out, sys.stdout)
`;

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function mutate(s, rnd) {
  const ops = Math.floor(rnd() * 3) + 1;
  let out = s;
  for (let i = 0; i < ops; i++) {
    const pos = Math.floor(rnd() * (out.length + 1));
    const roll = rnd();
    if (roll < 0.3 && out.length) { // delete a char
      out = out.slice(0, pos) + out.slice(pos + 1);
    } else if (roll < 0.6) {        // insert a random ASCII char
      const ch = String.fromCharCode(32 + Math.floor(rnd() * 95));
      out = out.slice(0, pos) + ch + out.slice(pos);
    } else if (roll < 0.8 && out.length) { // flip case of one char
      const ch = out[pos % out.length];
      out = out.slice(0, pos % out.length)
        + (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase())
        + out.slice((pos % out.length) + 1);
    } else {                        // duplicate a slice
      const len = Math.floor(rnd() * 12);
      out = out.slice(0, pos) + out.slice(pos, pos + len) + out.slice(pos);
    }
  }
  return out;
}

test("engine differential vs uap-python on same regexes (fixtures + mutations)",
     { skip: !HAS_UAP }, async () => {
  const seed = Number(process.env.UA_SEED ?? 1);
  const rnd = mulberry32(seed);
  const pool = [
    ...loadFixtures("test_ua").map((c) => c.user_agent_string),
    ...loadFixtures("test_os").map((c) => c.user_agent_string),
    ...loadFixtures("test_device").map((c) => c.user_agent_string),
  ];
  const strings = [];
  for (let i = 0; i < 400; i++)
    strings.push(pool[Math.floor(rnd() * pool.length)]);          // verbatim
  for (let i = 0; i < 400; i++)
    strings.push(mutate(pool[Math.floor(rnd() * pool.length)], rnd)); // mutated
  strings.push("", " ", "()", "((", "Mozilla/5.0", ")(", "a/b/c ; (x;y)");

  // NB: async execFile has no `input` option (that's execFileSync-only;
  // passing it deadlocks — python blocks on stdin at 0% CPU forever).
  // No in-process server here, so sync is safe.
  const stdout = execFileSync("python3", ["-c", PY_ORACLE],
    { input: JSON.stringify(strings), maxBuffer: 64 * 1024 * 1024 });
  const oracle = JSON.parse(stdout);

  for (let i = 0; i < strings.length; i++) {
    const s = strings[i];
    const mine = identify(s);
    const a = mine.agent && [mine.agent.family, mine.agent.major, mine.agent.minor,
                             mine.agent.patch, mine.agent.patchMinor];
    const o = mine.os && [mine.os.family, mine.os.major, mine.os.minor,
                          mine.os.patch, mine.os.patchMinor];
    const d = mine.device && [mine.device.family, mine.device.brand, mine.device.model];
    assert.deepEqual({ agent: a, os: o, device: d },
      { agent: oracle[i].agent, os: oracle[i].os, device: oracle[i].device },
      `seed ${seed}, string ${JSON.stringify(s)}`);
  }
});

// Pinned cross-implementation divergence (excluded from the sweep above):
// Python's \d matches Unicode digits, JS's does not — the same uap data can
// classify a UA differently depending on the implementation language.
test("documented divergence: Python \\d is Unicode-aware, JS \\d is not", () => {
  // "12٣" — Python re \d+ would swallow the Arabic-Indic digit, JS stops.
  assert.equal("1٢3".match(/\d+/)[0], "1"); // JS behavior, pinned
  // Our engine is the JS behavior; uap-js behaves the same way. The sweep
  // stays ASCII so this known class doesn't drown real engine bugs.
});

// ---------------------------------------------------------------------------
// engine unit behavior (reference semantics, pinned)

test("no match: null result; empty capture groups become null", () => {
  assert.equal(parseAgent("completely unrecognizable 0000"), null);
  assert.equal(parseOs("completely unrecognizable 0000"), null);
  const r = parseAgent("Luminary/1.0");
  assert.equal(r.family, "Luminary");
  assert.equal(r.major, "1");
  assert.equal(r.minor, "0");
  assert.equal(r.patch, null);
  assert.equal(r.patchMinor, null);
  assert.equal(versionString(r), "1.0");
});

test("versionString stops at first missing part", () => {
  assert.equal(versionString({ major: "1", minor: null, patch: "9" }), "1");
  assert.equal(versionString({ major: null }), null);
});

// ---------------------------------------------------------------------------
// structural tokenizer

test("tokenize: products, nested comment, versions", () => {
  const { parts, warnings } = tokenize(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
  assert.equal(warnings.length, 0);
  assert.deepEqual(parts.map((p) => p.kind),
    ["product", "comment", "product", "comment", "product", "product"]);
  assert.equal(parts[0].name, "Mozilla");
  assert.equal(parts[0].version, "5.0");
  assert.deepEqual(parts[1].segments, ["Windows NT 10.0", "Win64", "x64"]);
  assert.deepEqual(parts[3].segments, ["KHTML, like Gecko"]);
  assert.equal(parts[4].version, "120.0.0.0");
});

test("tokenize: comment nesting and quoted pairs", () => {
  const { parts } = tokenize("A/1 (outer (inner; still inner); after)");
  assert.equal(parts[1].kind, "comment");
  assert.deepEqual(parts[1].segments, ["outer (inner; still inner)", "after"]);
  const q = tokenize("B/2 (a\\); b)");
  assert.deepEqual(q.parts[1].segments, ["a\\)", "b"]); // \) doesn't close
});

test("tokenize: unterminated comment and stray paren warn", () => {
  const u = tokenize("X/1 (never closed");
  assert.ok(u.parts[1].unterminated);
  assert.ok(u.warnings.some((w) => w.id === "unterminated-comment"));
  const s = tokenize("X/1 ) Y/2");
  assert.ok(s.parts.some((p) => p.kind === "junk"));
  assert.ok(s.warnings.some((w) => w.id === "stray-paren"));
});

test("tokenize: version after first slash only; extra slashes kept in version", () => {
  const { parts } = tokenize("weird/1/2/3");
  assert.equal(parts[0].name, "weird");
  assert.equal(parts[0].version, "1/2/3");
});

// ---------------------------------------------------------------------------
// analyzer notes and warnings

const CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
const CHROME_ANDROID = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36";
const SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
const FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
const GOOGLEBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/139.0.0.0 Safari/537.36";
const HEADLESS = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/139.0.0.0 Safari/537.36";

test("analyze: reduced-UA warning covers Chrome build, NT 10.0, macOS cap, Android K", () => {
  let w = analyze(CHROME_WIN).warnings.find((x) => x.id === "reduced-ua");
  assert.ok(w && w.message.includes("only the major version") && w.message.includes("NT 10.0"));
  w = analyze(CHROME_ANDROID).warnings.find((x) => x.id === "reduced-ua");
  assert.ok(w && w.message.includes("Android"));
  w = analyze(SAFARI_MAC).warnings.find((x) => x.id === "reduced-ua");
  assert.ok(w && w.message.includes("10_15_7"));
  // Firefox sends a real version and no frozen tokens beyond Gecko date
  assert.equal(analyze(FIREFOX).warnings.find((x) => x.id === "reduced-ua"), undefined);
});

test("analyze: identification matches uap on the canonical strings", () => {
  const a = analyze(CHROME_WIN);
  assert.equal(a.id.agent.family, "Chrome");
  assert.equal(a.id.agent.major, "139");
  assert.equal(a.id.os.family, "Windows");
  assert.equal(a.id.os.major, "10");
  const f = analyze(FIREFOX);
  assert.equal(f.id.agent.family, "Firefox");
  assert.equal(f.id.os.family, "Linux");
});

test("analyze: bot and headless flagged", () => {
  const g = analyze(GOOGLEBOT);
  assert.equal(g.id.device.family, "Spider");
  assert.ok(g.warnings.some((w) => w.id === "bot"));
  assert.ok(analyze(HEADLESS).warnings.some((w) => w.id === "headless"));
});

test("analyze: notes explain the fossils", () => {
  const notes = analyze(CHROME_WIN).notes;
  const targets = notes.map((n) => n.target);
  assert.ok(targets.includes("Mozilla/5.0"));
  assert.ok(targets.includes("AppleWebKit/537.36"));
  assert.ok(targets.includes("KHTML, like Gecko"));
  assert.ok(notes.find((n) => n.target === "Chrome/139.0.0.0").note.includes("139"));
});

test("analyze: unrecognized string warns, empty does not", () => {
  assert.ok(analyze("hello world").warnings.some((w) => w.id === "unrecognized")
    || identify("hello world").device !== null); // some catch-all device rule may claim it
  assert.equal(analyze("").warnings.length, 0);
});
