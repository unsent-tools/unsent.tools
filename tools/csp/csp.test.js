// Tests for csp.js.
//
// Oracles:
//  1. Pinned vectors measured from real headless Chromium (see the probe
//     history in the repo journal): the scheme/port/upgrade matrix, grammar
//     edge cases, path/percent-decoding behavior. These run everywhere, fast.
//  2. Live differential vs csp_evaluator (Google's CSP checker, from the
//     machine-local ../devtools install): exact parser equivalence plus
//     security/syntax findings on a generated corpus.
//  3. Live differential vs headless Chromium via playwright (also from
//     ../devtools): random source lists and URLs, my matcher's verdict must
//     equal the browser's block/allow decision. Skipped with a loud warning
//     if ../devtools is missing (deploy.sh always runs it on the deploy
//     machine).
//
// Documented oracle divergences (verified by probing, not assumed):
//  - csp_evaluator says IP sources "will be ignored by browsers!" — false in
//    Chrome, which enforces them like any host (verified by probe). We warn
//    differently; the differential compares category presence only.
//  - csp_evaluator's parser accepts any garbage as a host source; Chrome
//    drops invalid expressions (user@host, IPv6 literals, mid-string
//    wildcards). Our classifySource follows Chrome.

'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const CSP = require('./csp.js');

const DEVTOOLS = path.join(__dirname, '../../../devtools/node_modules');

// ---------------------------------------------------------------------------
// Pinned Chromium behavior: the scheme x port matrix, measured on a page at
// http://a.localhost:8931 (page scheme http). B = blocked, a = allowed.

const PAGE = 'http://a.localhost:8931';
const MATRIX_URLS = [
  'http://x.example/i', 'https://x.example/i', 'http://x.example:8080/i',
  'https://x.example:8080/i', 'http://x.example:443/i', 'https://x.example:80/i',
];
const CHROME_MATRIX = {
  'x.example':              'aaBBBB',
  'x.example:80':           'aaBBBB',
  'x.example:443':          'BaBBaB',
  'x.example:8080':         'BBaBBB',
  'x.example:*':            'aaaaaa',
  'http://x.example':       'aaBBBB',
  'https://x.example':      'BaBBBB',
  'http://x.example:8080':  'BBaBBB',
  'https://x.example:8080': 'BBBaBB',
  'http://x.example:443':   'BaBBaB',
  'http://x.example:*':     'aaaaaa',
};

test('pinned Chrome scheme/port matrix (upgrade requires port 443)', () => {
  for (const [source, row] of Object.entries(CHROME_MATRIX)) {
    MATRIX_URLS.forEach((url, i) => {
      const { allowed } = CSP.matchesSourceList([source], url, PAGE);
      assert.equal(allowed, row[i] === 'a', `${source} vs ${url}: want ${row[i]}`);
    });
  }
});

test('pinned Chrome grammar and path vectors', () => {
  const m = (list, url, page = PAGE) => CSP.matchesSourceList(list.split(' '), url, page).allowed;
  // wildcards
  assert.equal(m('*.x.example', 'http://x.example/i'), false);
  assert.equal(m('*.x.example', 'http://sub.x.example/i'), true);
  assert.equal(m('*.x.example', 'http://a.b.x.example/i'), true);
  assert.equal(m('*.x.example', 'http://xx.example/i'), false);
  assert.equal(m('*', 'http://x.example/i'), true);
  assert.equal(m('*', 'data:image/gif;base64,R0lGODlh'), false);
  assert.equal(m('*:8080', 'http://x.example:8080/i'), true);
  assert.equal(m('*:8080', 'http://x.example/i'), false);
  assert.equal(m('*/p/', 'http://x.example/p/i.png'), true);
  assert.equal(m('*/p/', 'http://x.example/q/i.png'), false);
  // invalid expressions are dropped, don't kill the rest of the list
  assert.equal(m('x.example ???bad??? y.example', 'http://y.example/i'), true);
  for (const bad of ['sub.*.example', '*x.example', 'user@x.example', 'x_y.example',
                     '[2001:db8::1]', '2001:db8::1', '*.']) {
    assert.equal(CSP.classifySource(bad).kind, 'invalid', bad);
  }
  // "https//x.example" is grammatically a host source (host "https", path
  // "//x.example") — it never matches the intended host, and analyze() warns
  const oops = CSP.classifySource('https//x.example');
  assert.equal(oops.kind, 'host');
  assert.equal(oops.host, 'https');
  assert.equal(m('https//x.example', 'https://x.example/i'), false);
  assert.ok(CSP.analyze(CSP.parseHeader("img-src https//x.example")).some((f) => f.id === 'suspicious-host'));
  assert.equal(m('[2001:db8::1]', 'http://[2001:db8::1]/i.png'), false);
  // paths: prefix vs exact, decoding, case
  assert.equal(m('x.example/img/', 'http://x.example/img/a.png'), true);
  assert.equal(m('x.example/img/', 'http://x.example/img'), false);
  assert.equal(m('x.example/img', 'http://x.example/img'), true);
  assert.equal(m('x.example/img', 'http://x.example/img/'), false);
  assert.equal(m('x.example/img', 'http://x.example/img?x=1'), true);
  assert.equal(m('x.example/img', 'http://x.example/img.png'), false);
  assert.equal(m('x.example/a%20b/', 'http://x.example/a%20b/c.png'), true);
  assert.equal(m('x.example/a%20b/', 'http://x.example/a b/c.png'), true);
  assert.equal(m('x.example/a%2Fb/', 'http://x.example/a/b/c.png'), true); // %2F decodes before compare
  assert.equal(m('x.example/CaseSense/', 'http://x.example/casesense/a.png'), false);
  assert.equal(m('x.example/%zz/', 'http://x.example/%zz/i.png'), true); // invalid escapes literal
  assert.equal(m('x.example//double/', 'http://x.example/double/i.png'), false);
  assert.equal(m('x.example/img/?q=1', 'http://x.example/img/other.png'), true); // query ignored
  // host case, trailing dot, leading-zero port
  assert.equal(m('X.EXAMPLE', 'http://x.example/i'), true);
  assert.equal(m('x.example.', 'http://x.example./i'), true);
  assert.equal(m('x.example.', 'http://x.example/i'), false);
  assert.equal(m('x.example:080', 'http://x.example/i'), true);
  // schemes
  assert.equal(m('ws://x.example', 'ws://x.example/i'), true);
  assert.equal(m('ws://x.example', 'wss://x.example/i'), true); // ws→wss upgrade (default port 443)
  assert.equal(m('ws://x.example', 'wss://x.example:443/i'), true);
  assert.equal(m('ws://x.example', 'http://x.example/i'), false);
  assert.equal(m('http://x.example', 'ws://x.example/i'), false);
  assert.equal(m('data:', 'data:image/gif;base64,R0lGODlh'), true);
  // keywords
  assert.equal(m("'none'", 'http://x.example/i'), false);
  assert.equal(m("'none' x.example", 'http://x.example/i'), true); // 'none' ignored with others
  assert.equal(m("'SELF'", `${PAGE}/i.png`), true); // keywords case-insensitive
  assert.equal(CSP.matchesSourceList([], 'http://x.example/i', PAGE).allowed, false);
  // 'self' rules (page http://a.localhost:8931)
  assert.equal(m("'self'", 'http://a.localhost:8931/i'), true);
  assert.equal(m("'self'", 'https://a.localhost:8931/i'), true);  // https upgrade, same port
  assert.equal(m("'self'", 'wss://a.localhost:8931/i'), true);
  assert.equal(m("'self'", 'http://b.localhost:8931/i'), false);
  assert.equal(m("'self'", 'http://a.localhost:9999/i'), false);
  assert.equal(m("'self'", 'https://a.localhost/i'), false); // 443 vs non-default 8931: no match
  // on a default-port page, 'self' allows default-port https
  assert.equal(m("'self'", 'https://a.localhost/i', 'http://a.localhost'), true);
});

// ---------------------------------------------------------------------------
// Parser & evaluateLoad units

test('parseHeader: header names, commas, report-only, duplicates', () => {
  const parsed = CSP.parseHeader(
    'Content-Security-Policy: default-src \'self\'; img-src a.example, script-src b.example\n' +
    'Content-Security-Policy-Report-Only: default-src *');
  assert.equal(parsed.policies.length, 3);
  assert.deepEqual(parsed.policies[0].map['img-src'], ['a.example']);
  assert.deepEqual(parsed.policies[1].map['script-src'], ['b.example']);
  assert.equal(parsed.policies[2].disposition, 'report-only');

  const dup = CSP.parsePolicy("script-src a.example; SCRIPT-SRC b.example");
  assert.deepEqual(dup.map['script-src'], ['a.example']); // first wins, name lowercased
  assert.equal(dup.directives[1].ignored, true);
});

test('evaluateLoad: fallback chains and combined verdicts', () => {
  const parsed = CSP.parseHeader("default-src 'self'; script-src cdn.example; frame-src frames.example");
  const page = 'https://site.example';
  // img falls back to default-src
  let r = CSP.evaluateLoad(parsed, 'img', 'https://site.example/x.png', page);
  assert.equal(r.verdict, 'allowed');
  assert.equal(r.results[0].directive, 'default-src');
  r = CSP.evaluateLoad(parsed, 'img', 'https://cdn.example/x.png', page);
  assert.equal(r.verdict, 'blocked');
  // script uses script-src (script-src-elem absent)
  r = CSP.evaluateLoad(parsed, 'script', 'https://cdn.example/x.js', page);
  assert.equal(r.verdict, 'allowed');
  assert.equal(r.results[0].directive, 'script-src');
  // worker chain: worker-src > child-src > script-src > default-src
  r = CSP.evaluateLoad(parsed, 'worker', 'https://cdn.example/w.js', page);
  assert.equal(r.results[0].directive, 'script-src');
  // form-action does NOT fall back to default-src
  r = CSP.evaluateLoad(parsed, 'form', 'https://evil.example/steal', page);
  assert.equal(r.verdict, 'allowed');
  assert.equal(r.results[0].directive, null);
  // multiple policies: every enforced policy must allow
  const two = CSP.parseHeader('img-src a.example b.example, img-src b.example');
  assert.equal(CSP.evaluateLoad(two, 'img', 'https://a.example/x.png', page).verdict, 'blocked');
  assert.equal(CSP.evaluateLoad(two, 'img', 'https://b.example/x.png', page).verdict, 'allowed');
  // report-only never blocks
  const ro = CSP.parseHeader('Content-Security-Policy-Report-Only: img-src a.example');
  assert.equal(CSP.evaluateLoad(ro, 'img', 'https://z.example/x.png', page).verdict, 'allowed');
  // strict-dynamic makes script verdicts conditional
  const sd = CSP.parseHeader("script-src 'strict-dynamic' 'nonce-abcdefgh' cdn.example");
  assert.equal(CSP.evaluateLoad(sd, 'script', 'https://cdn.example/x.js', page).verdict, 'conditional');
});

test('analyze: a clean strict policy yields no warnings above info', () => {
  const parsed = CSP.parseHeader(
    "Content-Security-Policy: script-src 'nonce-Xu3jbSZ9pQ' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-uri https://r.example/csp");
  const findings = CSP.analyze(parsed);
  const above = findings.filter((f) => f.level === 'high' || f.level === 'medium' || f.level === 'syntax');
  assert.deepEqual(above, [], JSON.stringify(findings, null, 1));
});

test('analyze: the nasty policy fires every expected finding', () => {
  const parsed = CSP.parseHeader(
    "script-src 'unsafe-inline' 'unsafe-eval' * data: http://cdn.example 1.2.3.4 'nonce-ab' self; " +
    "script-src ignored.example; img-src x.example x.example 'none'; objekt-src 'none'; " +
    "upgrade-insecure-requests now; reflected-xss block; report-uri http://r.example/r");
  const ids = new Set(CSP.analyze(parsed).map((f) => f.id));
  // note: the policy contains a nonce, so 'unsafe-inline' is (correctly)
  // reported as ignored rather than active
  for (const want of ['ignored-unsafe-inline', 'unsafe-eval', 'wildcard', 'plain-scheme', 'src-http',
                      'ip-source', 'nonce-length', 'unquoted-keyword', 'duplicate-directive',
                      'duplicate-value', 'none-with-others', 'unknown-directive',
                      'valueless-directive', 'deprecated-directive', 'missing-object-src',
                      'missing-base-uri']) {
    assert.ok(ids.has(want), `missing finding: ${want}`);
  }
});

test('analyze: nonce/hash silences unsafe-inline; strict-dynamic silences allowlist', () => {
  let f = CSP.analyze(CSP.parseHeader("script-src 'unsafe-inline' 'nonce-abcdefgh'; object-src 'none'; base-uri 'none'"));
  assert.ok(f.some((x) => x.id === 'ignored-unsafe-inline'));
  assert.ok(!f.some((x) => x.id === 'unsafe-inline'));
  f = CSP.analyze(CSP.parseHeader("script-src 'strict-dynamic' 'nonce-abcdefgh' https: 'self'; object-src 'none'; base-uri 'none'"));
  const ignored = f.filter((x) => x.id === 'ignored-strict-dynamic').map((x) => x.value);
  assert.deepEqual(ignored.sort(), ["'self'", 'https:']);
  assert.ok(!f.some((x) => x.id === 'plain-scheme'));
  // strict-dynamic with NO nonce/hash = blocks everything
  f = CSP.analyze(CSP.parseHeader("script-src 'strict-dynamic'; object-src 'none'"));
  assert.ok(f.some((x) => x.id === 'strict-dynamic-alone'));
});

test('analyze: known JSONP/Angular bypass hosts are called out', () => {
  const f = CSP.analyze(CSP.parseHeader("script-src 'self' www.google.com; object-src 'none'"));
  assert.ok(f.some((x) => x.id === 'known-bypass' && x.value === 'www.google.com'));
  // wildcard covering a bypass host
  const g = CSP.analyze(CSP.parseHeader("script-src *.googleapis.com; object-src 'none'"));
  assert.ok(g.some((x) => x.id === 'known-bypass'));
});

test('analyze: meta delivery and report-only footguns', () => {
  let f = CSP.analyze(CSP.parseHeader("frame-ancestors 'none'; sandbox allow-scripts; script-src 'self'; object-src 'none'"), { delivery: 'meta' });
  assert.equal(f.filter((x) => x.id === 'meta-ignored').length, 2);
  f = CSP.analyze(CSP.parseHeader("Content-Security-Policy-Report-Only: script-src 'self'; object-src 'none'"));
  assert.ok(f.some((x) => x.id === 'report-only-no-dest'));
});

test('malformed nonces and hashes are invalid sources (never match, warned)', () => {
  assert.equal(CSP.classifySource("'nonce-'").kind, 'invalid');
  assert.equal(CSP.classifySource("'nonce-a b'").kind, 'invalid');
  assert.equal(CSP.classifySource("'sha256-'").kind, 'invalid');
  assert.equal(CSP.classifySource("'sha1-abc'").kind, 'invalid'); // sha1 not a CSP hash
  const f = CSP.analyze(CSP.parseHeader("script-src 'nonce-a b' x.example; object-src 'none'"));
  assert.ok(f.some((x) => x.id === 'invalid-source'));
});

// ---------------------------------------------------------------------------
// Differential 1: csp_evaluator (parser + findings)

const HAS_ORACLE = fs.existsSync(path.join(DEVTOOLS, 'csp_evaluator'));

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (rnd, arr) => arr[Math.floor(rnd() * arr.length)];

// Corpus pools. Deliberately stays inside the semantic zones where our checks
// and csp_evaluator's were verified to agree (see divergence notes at top;
// e.g. no malformed nonces, no IPs in report-uri, no fenced-frame-src).
const SCRIPT_VALUES = [
  "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
  "'unsafe-hashes'", "'report-sample'", "'nonce-abcdefghijk'", "'nonce-abc'",
  "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
  'https:', 'http:', 'data:', 'blob:', '*', 'x.example', '*.x.example',
  'https://cdn.x.example', 'http://x.example', '1.2.3.4', '127.0.0.1',
  'x.example:8080', 'self', 'unsafe-inline', "'foo'", 'img-src',
];
const PLAIN_VALUES = [
  "'self'", "'none'", '*', 'x.example', '*.x.example', 'https:', 'data:',
  'https://a.x.example/p/', 'http://plain.example', '10.1.2.3',
];
const EXTRA_DIRECTIVES = [
  ['img-src', PLAIN_VALUES], ['style-src', PLAIN_VALUES], ['font-src', PLAIN_VALUES],
  ['connect-src', PLAIN_VALUES], ['object-src', PLAIN_VALUES], ['base-uri', PLAIN_VALUES],
  ['frame-ancestors', PLAIN_VALUES], ['worker-src', PLAIN_VALUES],
  ['report-uri', ['/r', 'https://r.example/csp', 'http://r.example/csp']],
  ['upgrade-insecure-requests', []],
  ['sandbox', ['allow-scripts', 'allow-forms']],
  ['trusted-types', ['tt', "'allow-duplicates'"]],
  ['require-trusted-types-for', ["'script'"]],
  ['webrtc', ["'block'"]],
  ['reflected-xss', ['block']], ['referrer', ['origin']], ['disown-opener', []],
  ['prefetch-src', ['x.example']],
  ['made-up-directive', ['foo']], ['script-src:', ["'self'"]],
];

function generatePolicy(rnd) {
  const parts = [];
  const scriptDir = pick(rnd, ['script-src', 'default-src', 'script-src-elem', null]);
  if (scriptDir) {
    const n = 1 + Math.floor(rnd() * 4);
    const vals = new Set();
    for (let i = 0; i < n; i++) vals.add(pick(rnd, SCRIPT_VALUES));
    parts.push(`${scriptDir} ${[...vals].join(' ')}`);
  }
  const extras = 1 + Math.floor(rnd() * 3);
  for (let i = 0; i < extras; i++) {
    const [name, pool] = pick(rnd, EXTRA_DIRECTIVES);
    // always >= 1 value when the pool has any: csp_evaluator flags an EMPTY
    // object-src as "missing object-src", though an empty source list blocks
    // everything (which is safe) — a documented divergence we don't mirror
    const n = Math.min(pool.length, 1 + Math.floor(rnd() * 2));
    const vals = new Set();
    for (let j = 0; j < n; j++) vals.add(pick(rnd, pool));
    parts.push(`${name}${vals.size ? ' ' + [...vals].join(' ') : ''}`);
  }
  return parts.join('; ');
}

test('differential: parser exactly matches csp_evaluator on 400 generated policies', { skip: !HAS_ORACLE && 'csp_evaluator not installed in ../devtools' }, () => {
  const { CspParser } = require(path.join(DEVTOOLS, 'csp_evaluator/dist/parser.js'));
  const { isKeyword, isUrlScheme } = require(path.join(DEVTOOLS, 'csp_evaluator/dist/csp.js'));
  // project our parse into csp_evaluator's shape: first-occurrence directives,
  // values deduped after their normalization (lowercase keywords and schemes)
  const project = (policy) => {
    const out = {};
    for (const [name, values] of Object.entries(policy.map)) {
      const seen = [];
      for (const v of values) {
        const lower = v.toLowerCase();
        const norm = (isKeyword(lower) || isUrlScheme(v)) ? lower : v;
        if (!seen.includes(norm)) seen.push(norm);
      }
      out[name] = seen;
    }
    return out;
  };
  const rnd = mulberry32(20260830);
  for (let i = 0; i < 400; i++) {
    const policyText = generatePolicy(rnd);
    const theirs = new CspParser(policyText).csp.directives;
    const mine = project(CSP.parsePolicy(policyText));
    assert.deepEqual(mine, { ...theirs }, `policy: ${policyText}`);
  }
});

// Map our finding ids to csp_evaluator types for the comparable categories.
const ID_TO_TYPE = {
  'missing-semicolon': 100, 'unknown-directive': 101, 'unquoted-keyword': 102,
  'missing-object-src': 300, 'missing-script-src': 300, 'missing-base-uri': 300,
  'unsafe-inline': 301, 'unsafe-eval': 302, 'plain-scheme': 303, 'wildcard': 304,
  'nonce-length': 307, 'ip-source': 308, 'deprecated-directive': 309,
  'src-http': 310, 'unsafe-hashes': 317,
  'ignored-unsafe-inline': 405, 'ignored-strict-dynamic': 405,
};
const ORACLE_DEPRECATED = new Set(['reflected-xss', 'referrer', 'disown-opener', 'prefetch-src']);

test('differential: findings match csp_evaluator on 400 generated policies', { skip: !HAS_ORACLE && 'csp_evaluator not installed in ../devtools' }, () => {
  const { CspParser } = require(path.join(DEVTOOLS, 'csp_evaluator/dist/parser.js'));
  const { CspEvaluator } = require(path.join(DEVTOOLS, 'csp_evaluator/dist/evaluator.js'));
  const { isKeyword, isUrlScheme } = require(path.join(DEVTOOLS, 'csp_evaluator/dist/csp.js'));
  const norm = (v) => {
    if (v == null) return null;
    const lower = v.toLowerCase();
    return (isKeyword(lower) || isUrlScheme(v)) ? lower : v;
  };
  const rnd = mulberry32(987654321);
  for (let i = 0; i < 400; i++) {
    const policyText = generatePolicy(rnd);
    const parsed = new CspParser(policyText).csp;
    const theirs = new Set(
      new CspEvaluator(parsed).evaluate()
        // 305/306 are their allowlist-bypass heuristics (curated host DB +
        // per-value nags) — out of scope for a strict set comparison
        .filter((f) => f.type !== 305 && f.type !== 306)
        .map((f) => `${f.type}|${f.directive ?? ''}|${f.value ?? ''}`));
    const myFindings = CSP.analyze(CSP.parseHeader(policyText));
    // csp_evaluator runs value checks on the EFFECTIVE policy: values ignored
    // because of 'strict-dynamic' or a nonce/hash get no further findings
    // from it. We deliberately still warn on the raw values (the user sees
    // both the warning and the "ignored" note), so suppress those pairs here.
    const removed = new Set(
      myFindings.filter((f) => f.id === 'ignored-strict-dynamic' || f.id === 'ignored-unsafe-inline')
        .map((f) => `${f.directive}|${norm(f.value)}`));
    // 'wildcard'/'plain-scheme' are also suppressed for script-ignored values:
    // csp_evaluator's effective-policy transform deletes them from default-src
    // entirely, but 'strict-dynamic' only affects SCRIPT loads in real
    // browsers — `default-src * 'strict-dynamic'` still serves * to img/object
    // fallback, so our analyzer keeps warning about it (ours is the browser-
    // accurate view; verified in the Chromium differential below).
    const VALUE_CHECKS = new Set(['ip-source', 'src-http', 'nonce-length',
      'missing-semicolon', 'unquoted-keyword', 'invalid-source',
      'wildcard', 'plain-scheme']);
    const mine = new Set();
    for (const f of myFindings) {
      let type = ID_TO_TYPE[f.id];
      if (f.id === 'deprecated-directive' && !ORACLE_DEPRECATED.has(f.directive)) continue;
      if (f.id === 'invalid-source' && f.value && f.value.startsWith("'")) type = 102; // quoted junk
      if (type === undefined) continue; // our extra checks, no oracle counterpart
      if (VALUE_CHECKS.has(f.id) && removed.has(`${f.directive}|${norm(f.value)}`)) continue;
      mine.add(`${type}|${f.directive ?? ''}|${norm(f.value) ?? ''}`);
    }
    assert.deepEqual([...mine].sort(), [...theirs].sort(), `policy: ${policyText}`);
  }
});

// ---------------------------------------------------------------------------
// Differential 2: real Chromium. My matcher's verdict must equal the
// browser's on generated (source list, URL) pairs.

const HAS_PLAYWRIGHT = fs.existsSync(path.join(DEVTOOLS, 'playwright'));

const CORPUS_SOURCES = [
  "'self'", "'none'", "'unsafe-inline'", 'x.example', '*.x.example', 'X.EXAMPLE',
  'x.example.', 'sub.x.example', '1.2.3.4', '127.0.0.1', 'localhost',
  'x_y.example', 'user@x.example', 'sub.*.example', '*x.example', '*', '*.',
  'https:', 'http:', 'data:', 'ws:', 'x.example:80', 'x.example:443',
  'x.example:8080', 'x.example:*', '*:8080', '*/p/', 'http://x.example',
  'https://x.example', 'https://*.x.example:8443/p/', 'x.example/p/',
  'x.example/p', 'x.example/P/', 'x.example/a%20b/', 'x.example/img/?q=1',
  "'nonce-abcdefgh'",
];
const CORPUS_URLS = [
  'http://x.example/i.png', 'https://x.example/i.png', 'http://sub.x.example/i.png',
  'https://a.b.x.example:8443/p/i.png', 'http://xx.example/i.png',
  'http://x.example:8080/i.png', 'https://x.example:8080/i.png',
  'http://x.example:443/i.png', 'https://x.example:80/i.png',
  'http://1.2.3.4/i.png', 'http://localhost:9999/i.png', 'http://x.example./i.png',
  'http://x.example/p/i.png', 'http://x.example/p', 'http://x.example/P/i.png',
  'http://x.example/a b/i.png', 'http://x.example/a%20b/i.png',
  'ws://x.example/i', 'wss://x.example/i',
];

test('differential: matcher agrees with real Chromium', { skip: !HAS_PLAYWRIGHT && 'playwright not installed in ../devtools' }, async () => {
  const { chromium } = await import(path.join(DEVTOOLS, 'playwright/index.mjs'));
  const http = require('node:http');

  const TEST_PAGE = `<!doctype html><meta charset=utf-8><body><script nonce="instr">
  window.runTests = (urls) => new Promise((resolve) => {
    const blocked = new Set();
    document.addEventListener('securitypolicyviolation', (e) => blocked.add(e.blockedURI));
    let pending = urls.length;
    const norm = (u) => { try { return new URL(u, location.href).href; } catch { return u; } };
    const key = (u) => u.startsWith('data:') ? 'data' : norm(u);
    const finish = () => resolve(urls.map((u) => blocked.has(key(u))));
    const done = () => setTimeout(finish, 120);
    for (const u of urls) {
      const img = new Image();
      img.onload = img.onerror = () => { if (--pending === 0) done(); };
      img.src = u;
    }
    setTimeout(finish, 1000);
  });
  </scr` + `ipt></body>`;

  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/page') {
      res.writeHead(200, {
        'content-type': 'text/html',
        'content-security-policy': Buffer.from(u.searchParams.get('csp'), 'base64url').toString(),
      });
      res.end(TEST_PAGE);
    } else { res.writeHead(404); res.end('x'); }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const pageOrigin = `http://a.localhost:${port}`;

  const browser = await chromium.launch();
  const page = await browser.newPage();

  async function chromeVerdicts(directiveText, urls) {
    const csp = Buffer.from(directiveText).toString('base64url');
    await page.goto(`${pageOrigin}/page?csp=${csp}`);
    return page.evaluate((u) => window.runTests(u), urls);
  }

  const rnd = mulberry32(424242);
  const nCases = parseInt(process.env.CSP_CHROME_CASES || '30', 10);
  let checked = 0;
  for (let i = 0; i < nCases; i++) {
    const n = 1 + Math.floor(rnd() * 4);
    const list = [...new Set(Array.from({ length: n }, () => pick(rnd, CORPUS_SOURCES)))];
    const urls = [...new Set(Array.from({ length: 6 }, () => pick(rnd, CORPUS_URLS)))];
    urls.push(`${pageOrigin}/self.png`, `https://a.localhost:${port}/self.png`);
    const blocked = await chromeVerdicts(`img-src ${list.join(' ')}`, urls);
    urls.forEach((u, j) => {
      const mine = CSP.matchesSourceList(list, u, pageOrigin);
      assert.equal(!mine.allowed, blocked[j],
        `img-src ${list.join(' ')} vs ${u}: chrome says ${blocked[j] ? 'block' : 'allow'}`);
      checked++;
    });
  }

  // fallback chains, verified live: default-src governs img when img-src is
  // absent; img-src wins when present. ('nonce-instr' keeps our
  // instrumentation script running under default-src policies; nonces are
  // inert for img matching.)
  for (const [policy, url, want] of [
    ["default-src 'nonce-instr' x.example", 'http://x.example/f.png', false],
    ["default-src 'nonce-instr' x.example", 'http://y.example/f.png', true],
    ["default-src 'nonce-instr'; img-src x.example", 'http://x.example/f.png', false],
    ["default-src 'nonce-instr' x.example; img-src y.example", 'http://x.example/f.png', true],
    // 'strict-dynamic' only affects script loads: * in default-src still
    // applies to img fallback (csp_evaluator models this differently; we
    // follow the browser)
    ["default-src 'nonce-instr' * 'strict-dynamic'", 'http://x.example/f.png', false],
  ]) {
    const blocked = await chromeVerdicts(policy, [url]);
    assert.equal(blocked[0], want, `${policy} vs ${url}`);
    const parsed = CSP.parseHeader(policy);
    const mine = CSP.evaluateLoad(parsed, 'img', url, pageOrigin);
    assert.equal(mine.verdict === 'blocked', want, `evaluateLoad: ${policy} vs ${url}`);
    checked++;
  }

  await browser.close();
  server.close();
  assert.ok(checked > 200, `only ${checked} verdicts checked`);
});
