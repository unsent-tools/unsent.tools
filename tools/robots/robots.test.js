// Tests for robots.js. Differential oracle: protego (pip) — Scrapy's
// RFC 9309 robots.txt parser, whose semantics this tool mirrors
// (calibration-probed before implementation):
//   - group selection by case-insensitive substring of the UA, longest
//     token wins, groups sharing the winning token merge, "*" only as
//     fallback (a specific group fully shadows it);
//   - rule precedence by percent-normalized pattern length, allow wins ties;
//   - %XX normalization where %2F stays distinct from "/";
//   - no dot-segment resolution, case-sensitive paths.
// Documented divergence: protego does NOT strip a UTF-8 BOM (the first line
// becomes unrecognizable and a leading "User-agent: *" group is silently
// lost). We strip it like Google's parser and warn; BOM inputs are excluded
// from the differential and pinned in their own test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  normalize, matchPattern, parseRobots, selectGroups, toPath, checkUrl,
} from "./robots.js";

const py = (script, input) =>
  execFileSync("python3", ["-c", script], {
    input: JSON.stringify(input), encoding: "utf8", maxBuffer: 1 << 24,
  });

function rng(seed) {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];

const allowed = (txt, path, ua = "testbot") =>
  checkUrl(parseRobots(txt), ua, path).allowed;

// ---------------------------------------------------------------------------

test("pinned matching vectors (RFC 9309 / google robots.txt spec examples)", () => {
  // Google's documented path-matching table
  const t1 = "User-agent: *\nDisallow: /fish\n";
  for (const p of ["/fish", "/fish.html", "/fish/salmon.html", "/fishheads", "/fish.php?id=anything"]) {
    assert.equal(allowed(t1, p), false, p);
  }
  for (const p of ["/Fish.asp", "/catfish", "/?id=fish"]) {
    assert.equal(allowed(t1, p), true, p);
  }
  const t2 = "User-agent: *\nDisallow: /fish/\n";
  assert.equal(allowed(t2, "/fish"), true);
  assert.equal(allowed(t2, "/fish/"), false);
  assert.equal(allowed(t2, "/fish/salmon.htm"), false);
  const t3 = "User-agent: *\nDisallow: /*.php$\n";
  assert.equal(allowed(t3, "/filename.php"), false);
  assert.equal(allowed(t3, "/folder/filename.php"), false);
  assert.equal(allowed(t3, "/filename.php?parameters"), true);
  assert.equal(allowed(t3, "/filename.php5"), true);
  // RFC 9309 §5.2-style: the longer Allow overrides the shorter Disallow
  const t4 = "User-agent: *\nAllow: /example/page/\nDisallow: /example/\n";
  assert.equal(allowed(t4, "/example/page/"), true);
  assert.equal(allowed(t4, "/example/other/"), false);
});

test("precedence: longest match wins, allow wins ties, normalized length", () => {
  // longest match
  const t = "User-agent: *\nDisallow: /p\nAllow: /page\nDisallow: /page$\n";
  assert.equal(allowed(t, "/page"), false);   // /page$ (6) beats Allow /page (5)
  assert.equal(allowed(t, "/pages"), true);   // Allow /page (5) beats /p (2)
  assert.equal(allowed(t, "/pa"), false);
  // exact-length tie -> allow
  assert.equal(allowed("User-agent: *\nDisallow: /x\nAllow: /x\n", "/x"), true);
  // specificity length is measured on the NORMALIZED pattern: "/café"
  // normalizes to 10 chars and beats "Allow: /caf*" (5) — protego-verified
  assert.equal(allowed("User-agent: *\nDisallow: /café\nAllow: /caf*\n", "/café"), false);
  // no matching rule -> allowed; empty file -> allowed
  assert.equal(allowed("User-agent: *\nDisallow: /priv\n", "/pub"), true);
  assert.equal(allowed("", "/anything"), true);
  // empty Disallow value is valid and matches nothing
  assert.equal(allowed("User-agent: *\nDisallow:\n", "/anything"), true);
});

test("wildcards and anchors", () => {
  assert.equal(matchPattern("/*.pdf$", "/doc.pdf"), true);
  assert.equal(matchPattern("/*.pdf$", "/doc.pdfx"), false);
  assert.equal(matchPattern("/*.pdf$", "/x/y.pdf"), true);
  assert.equal(matchPattern("/a*b", "/a/z/b"), true);
  assert.equal(matchPattern("/a*b", "/ba"), false);
  assert.equal(matchPattern("*", "/x"), true);           // bare * blocks all
  assert.equal(matchPattern("/a$b", "/a$b"), true);      // mid-$ is literal
  assert.equal(matchPattern("/a$b", "/a"), false);
  assert.equal(matchPattern("/c$", "/c"), true);
  assert.equal(matchPattern("/c$", "/cd"), false);
  assert.equal(matchPattern("/$", "/"), true);
  assert.equal(matchPattern("/$", "/x"), false);
  // anchored multi-segment: last segment must sit at the end, after pos
  assert.equal(matchPattern("/a*b$", "/axbyb"), true);
  assert.equal(matchPattern("/a*b$", "/axbyc"), false);
  assert.equal(matchPattern("/ab*ab$", "/abab"), true);  // "*" may match empty
  assert.equal(matchPattern("/ab*ab$", "/abxab"), true);
  assert.equal(matchPattern("/ab*b$", "/ab"), false);    // but segments may not overlap
});

test("percent-encoding normalization; %2F stays distinct from /", () => {
  assert.equal(normalize("/café"), "/caf%C3%A9");
  assert.equal(normalize("/a b"), "/a%20b");
  assert.equal(normalize("/q%2fx"), "/q%2Fx");   // hex uppercased
  assert.equal(normalize("/q%2Fx"), "/q%2Fx");
  assert.equal(normalize("/100%"), "/100%");     // dangling % left literal
  assert.equal(normalize("/a?b=c&d"), "/a?b=c&d"); // reserved chars untouched
  const t = "User-agent: *\nDisallow: /café\nDisallow: /a%20b\nDisallow: /q%2Fx\n";
  assert.equal(allowed(t, "/caf%C3%A9"), false);
  assert.equal(allowed(t, "/café"), false);
  assert.equal(allowed(t, "/a b"), false);
  assert.equal(allowed(t, "/a%20b"), false);
  assert.equal(allowed(t, "/q/x"), true);        // literal / is NOT %2F
  assert.equal(allowed(t, "/q%2fx"), false);
});

test("user-agent group selection: substring, longest token, * shadowed", () => {
  const t = `User-agent: Googlebot-Images
Disallow: /img
User-agent: Googlebot
Disallow: /g
User-agent: *
Disallow: /all
`;
  const p = parseRobots(t);
  // longest matching token wins; only that token's groups apply
  assert.equal(checkUrl(p, "Googlebot-Images/1.0", "/img").allowed, false);
  assert.equal(checkUrl(p, "Googlebot-Images/1.0", "/g").allowed, true);
  assert.equal(checkUrl(p, "Googlebot-Images/1.0", "/all").allowed, true);
  // substring matching (protego-compatible): token found anywhere in the UA
  assert.equal(checkUrl(p, "Mozilla/5.0 (compatible; Googlebot/2.1)", "/g").allowed, false);
  assert.equal(checkUrl(p, "MyGooglebotFork", "/g").allowed, false);
  // shorter strings don't match; fall to *
  assert.equal(checkUrl(p, "Google", "/all").allowed, false);
  assert.equal(checkUrl(p, "randombot", "/all").allowed, false);
  assert.equal(checkUrl(p, "randombot", "/g").allowed, true);
  // case-insensitive
  assert.equal(checkUrl(p, "gOOGLEBOT", "/g").allowed, false);
  // a specific group fully shadows *: crawl-delay + rules never combine
  const t2 = "User-agent: fast\nCrawl-delay: 1\nUser-agent: *\nCrawl-delay: 10\nDisallow: /x\n";
  const p2 = parseRobots(t2);
  const fast = checkUrl(p2, "fast", "/x");
  assert.equal(fast.allowed, true);
  assert.equal(fast.crawlDelay.value, 1);
  assert.equal(checkUrl(p2, "other", "/x").crawlDelay.value, 10);
});

test("group structure: consecutive UA lines share rules; same-token groups merge", () => {
  const shared = parseRobots("User-agent: a\nUser-agent: b\nDisallow: /x\n");
  assert.equal(checkUrl(shared, "a", "/x").allowed, false);
  assert.equal(checkUrl(shared, "b", "/x").allowed, false);
  const merged = parseRobots("User-agent: a\nDisallow: /one\nUser-agent: b\nDisallow: /x\nUser-agent: a\nDisallow: /two\n");
  assert.equal(checkUrl(merged, "a", "/one").allowed, false);
  assert.equal(checkUrl(merged, "a", "/two").allowed, false);
  assert.equal(checkUrl(merged, "a", "/x").allowed, true);
  assert.equal(merged.groups.length, 3);
});

test("group boundaries: what ends a run of user-agent lines (protego-pinned)", () => {
  // blank lines and comments do NOT split a UA run…
  assert.equal(allowed("User-agent: a\n\nUser-agent: b\nDisallow: /x\n", "/x", "a"), false);
  assert.equal(allowed("User-agent: a\n# note\nUser-agent: b\nDisallow: /x\n", "/x", "a"), false);
  // …but a Sitemap or unknown directive DOES (RFC 9309 ABNF: only blanks/
  // comments may sit between a group's UA lines) — "a" ends up an empty group
  assert.equal(allowed("User-agent: a\nSitemap: https://e.com/s.xml\nUser-agent: b\nDisallow: /x\n", "/x", "a"), true);
  assert.equal(allowed("User-agent: a\nFoobar: baz\nUser-agent: b\nDisallow: /x\n", "/x", "a"), true);
  // crawl-delay closes the agent set into a real group; the next UA line
  // starts a fresh group
  const t = "User-agent: a\nCrawl-delay: 5\nUser-agent: b\nDisallow: /x\n";
  assert.equal(allowed(t, "/x", "a"), true);
  assert.equal(allowed(t, "/x", "b"), false);
  // a blank line inside a group does not end its rules
  assert.equal(allowed("User-agent: a\nDisallow: /x\n\nDisallow: /y\n", "/y", "a"), false);
  // an empty group still shadows *: "a" matches its empty group, not *
  const shadow = "User-agent: a\nSitemap: https://e.com/s.xml\nUser-agent: *\nDisallow: /x\n";
  assert.equal(allowed(shadow, "/x", "a"), true);
  assert.equal(allowed(shadow, "/x", "z"), false);
});

test("lexical tolerance: CRLF, comments, indentation, colon spacing", () => {
  assert.equal(allowed("User-agent: *\r\nDisallow: /a\r\n", "/a"), false);
  assert.equal(allowed("User-agent: *\nDisallow: /a # why\n", "/a"), false);
  assert.equal(allowed("User-agent: *\nDisallow: /a#why\n", "/a"), false);
  assert.equal(allowed("  User-agent: *\n\tDisallow: /a\n", "/a"), false);
  assert.equal(allowed("User-agent : *\nDisallow: /a\n", "/a"), false);
  assert.equal(allowed("USER-AGENT: *\nDISALLOW: /a\n", "/a"), false);
  // missing colon: line ignored, warned
  const p = parseRobots("User-agent: *\nDisallow /a\n");
  assert.equal(checkUrl(p, "bot", "/a").allowed, true);
  assert.ok(p.warnings.some((w) => w.code === "no-colon"));
});

test("orphan rules are ignored and warned", () => {
  const p = parseRobots("Disallow: /lost\nUser-agent: *\nDisallow: /x\n");
  assert.equal(checkUrl(p, "bot", "/lost").allowed, true);
  assert.equal(checkUrl(p, "bot", "/x").allowed, false);
  assert.equal(p.orphanRules.length, 1);
  assert.ok(p.warnings.some((w) => w.code === "orphan-rule"));
});

test("BOM: stripped and warned (documented protego divergence)", () => {
  const withBom = "﻿User-agent: *\nDisallow: /a\n";
  const p = parseRobots(withBom);
  assert.equal(p.hadBom, true);
  assert.ok(p.warnings.some((w) => w.code === "bom"));
  // We follow Google's parser: the BOM is stripped, the group survives.
  assert.equal(checkUrl(p, "bot", "/a").allowed, false);
  // protego, by contrast, fails to recognize the first line and allows /a —
  // verified by probe; that is exactly why the warning exists.
});

test("warnings: typos, non-standard directives, footguns", () => {
  const p = parseRobots(`Disalow: /typo
User-agent: *
Noindex: /ni
Crawl-delay: 2.5
Crawl-delay-bogus: x
Disallow: admin
Disallow: /wp-admin/
Sitemap: /relative.xml
Sitemap: https://example.com/s.xml
`);
  const codes = p.warnings.map((w) => w.code);
  assert.ok(codes.includes("typo"), "Disalow flagged");
  assert.ok(codes.includes("nonstandard"), "Noindex flagged");
  assert.ok(codes.includes("crawl-delay"), "crawl-delay note");
  assert.ok(codes.includes("unknown-key"), "unknown directive flagged");
  assert.ok(codes.includes("no-leading-slash"), "admin pattern flagged");
  assert.ok(codes.includes("sensitive-path"), "wp-admin advertisement flagged");
  assert.ok(codes.includes("sitemap-not-absolute"));
  assert.equal(p.sitemaps.length, 2);
  assert.equal(p.sitemaps[1].url, "https://example.com/s.xml");
  // full-site block
  const q = parseRobots("User-agent: *\nDisallow: /\n");
  assert.ok(q.warnings.some((w) => w.code === "full-block"));
  // ...but not when an Allow carves an exception
  const q2 = parseRobots("User-agent: *\nDisallow: /\nAllow: /public/\n");
  assert.ok(!q2.warnings.some((w) => w.code === "full-block"));
});

test("checkUrl: URLs, queries, fragments, dot-segments, /robots.txt note", () => {
  const p = parseRobots("User-agent: *\nDisallow: /*?*sessionid=\nDisallow: /priv\n");
  assert.equal(checkUrl(p, "bot", "https://example.com/page?sessionid=1").allowed, false);
  assert.equal(checkUrl(p, "bot", "/page?sessionid=1").allowed, false);
  assert.equal(checkUrl(p, "bot", "/page").allowed, true);
  // fragment stripped
  const frag = checkUrl(p, "bot", "/priv#section");
  assert.equal(frag.allowed, false);
  assert.ok(frag.notes.some((s) => s.includes("fragment")));
  // dot-segments NOT resolved (textual matching, protego/Google-compatible)
  const dot = checkUrl(p, "bot", "/pub/../priv");
  assert.equal(dot.allowed, true);
  assert.ok(dot.notes.some((s) => s.includes("..")));
  // leading slash added for bare paths
  const bare = checkUrl(p, "bot", "priv");
  assert.equal(bare.path, "/priv");
  assert.equal(bare.allowed, false);
  // paths are case-sensitive
  assert.equal(checkUrl(p, "bot", "/PRIV").allowed, true);
  // /robots.txt itself gets the always-fetchable note when blocked
  const rb = checkUrl(parseRobots("User-agent: *\nDisallow: /\n"), "bot", "/robots.txt");
  assert.equal(rb.allowed, false);
  assert.ok(rb.notes.some((s) => s.includes("robots.txt itself")));
});

test("differential vs protego: generated corpus", () => {
  const r = rng(20260828);
  const tokens = ["alphabot", "betacrawler", "gamma-bot", "deltaspider", "epsilon_bot"];
  const uas = [
    "alphabot", "alphabot/2.0", "Mozilla/5.0 (compatible; betacrawler/1.1)",
    "GAMMA-BOT", "unrelatedbot", "xxalphabotxx", "epsilon", "delta",
  ];
  const pathAtoms = ["/", "/a", "/ab", "/a/b", "/fish", "/fish/", "/x.pdf", "/x.php",
    "/café", "/caf%C3%A9", "/a%20b", "/a b", "/q%2Fx", "/q/x", "/p?id=1&x=2",
    "/p?sessionid=9", "/deep/nested/path/file.html", "/UPPER", "/upper"];
  const patAtoms = ["/", "/a", "/ab", "/a*", "/a*b", "/*.pdf$", "/*.php$", "/fish",
    "/fish/", "/café", "/caf%C3%A9", "/a%20b", "/q%2Fx", "/*?*sessionid=",
    "/deep/*/path", "/UPPER", "/p", "/p?id=", "*", "/a$", "/$", "", "/a*b$"];

  const cases = [];
  for (let i = 0; i < 150; i++) {
    let txt = "";
    const nGroups = 1 + Math.floor(r() * 3);
    for (let g = 0; g < nGroups; g++) {
      const nAgents = 1 + Math.floor(r() * 2);
      for (let a = 0; a < nAgents; a++) {
        txt += `User-agent: ${r() < 0.3 ? "*" : pick(r, tokens)}\n`;
      }
      const nRules = Math.floor(r() * 5);
      for (let k = 0; k < nRules; k++) {
        txt += `${r() < 0.5 ? "Allow" : "Disallow"}: ${pick(r, patAtoms)}\n`;
      }
      if (r() < 0.25) txt += `Crawl-delay: ${(r() * 10).toFixed(1)}\n`;
      if (r() < 0.2) txt += `Sitemap: https://example.com/s${g}.xml\n`;
      if (r() < 0.3) txt += "\n";
    }
    const paths = [];
    for (let k = 0; k < 4; k++) paths.push(pick(r, pathAtoms));
    cases.push({ txt, ua: pick(r, uas), paths });
  }

  const script = `
import sys, json
from protego import Protego
out = []
for c in json.load(sys.stdin):
    rp = Protego.parse(c["txt"])
    verdicts = [rp.can_fetch(p, c["ua"]) for p in c["paths"]]
    d = rp.crawl_delay(c["ua"])
    out.append({"verdicts": verdicts, "delay": d, "sitemaps": list(rp.sitemaps)})
print(json.dumps(out))
`;
  const oracle = JSON.parse(py(script, cases));
  let checked = 0;
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const p = parseRobots(c.txt);
    for (let k = 0; k < c.paths.length; k++) {
      const got = checkUrl(p, c.ua, c.paths[k]);
      assert.equal(
        got.allowed, oracle[i].verdicts[k],
        `case ${i} path ${JSON.stringify(c.paths[k])} ua ${c.ua}\n${c.txt}`
      );
      checked++;
    }
    const ourDelay = selectGroups(p, c.ua).crawlDelay;
    assert.equal(ourDelay ? ourDelay.value : null, oracle[i].delay ?? null, `delay case ${i}\n${c.txt}`);
    assert.deepEqual(p.sitemaps.map((s) => s.url), oracle[i].sitemaps, `sitemaps case ${i}`);
  }
  assert.equal(checked, 600);
});

test("differential vs protego: real-world-shaped fixtures", () => {
  // Shapes seen constantly in the wild (wordpress, e-commerce, media sites)
  const fixtures = [
    `User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /?s=
Disallow: /search/
Sitemap: https://example.com/sitemap_index.xml
`,
    `User-agent: Googlebot
Allow: /

User-agent: GPTBot
User-agent: CCBot
User-agent: anthropic-ai
Disallow: /

User-agent: *
Disallow: /checkout/
Disallow: /cart/
Disallow: /*?add-to-cart=
Crawl-delay: 5
`,
    `User-agent: *
Disallow: /cgi-bin/
Disallow: /tmp/
Disallow: /*.json$
Allow: /api/public/*.json$
`,
  ];
  const uas = ["Googlebot", "GPTBot", "CCBot/2.0", "anthropic-ai", "Bingbot", "somebody"];
  const paths = ["/wp-admin/", "/wp-admin/admin-ajax.php", "/?s=q", "/search/x", "/",
    "/checkout/", "/cart/", "/p?add-to-cart=3", "/x", "/cgi-bin/a", "/tmp/",
    "/data.json", "/api/public/d.json", "/api/private/d.json"];
  const cases = [];
  for (const txt of fixtures) for (const ua of uas) cases.push({ txt, ua, paths });
  const script = `
import sys, json
from protego import Protego
out = []
for c in json.load(sys.stdin):
    rp = Protego.parse(c["txt"])
    out.append([rp.can_fetch(p, c["ua"]) for p in c["paths"]])
print(json.dumps(out))
`;
  const oracle = JSON.parse(py(script, cases));
  cases.forEach((c, i) => {
    const p = parseRobots(c.txt);
    c.paths.forEach((path, k) => {
      assert.equal(checkUrl(p, c.ua, path).allowed, oracle[i][k],
        `fixture ua=${c.ua} path=${path}`);
    });
  });
});
