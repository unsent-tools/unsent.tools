// Tests for cookie.js.
//
// Oracles:
//  1. Pinned vectors measured from real headless Chromium (calibration probes
//     over raw-socket HTTP, so control bytes and oversized headers could be
//     tested): acceptance rules, prefix enforcement, limits, date quirks.
//  2. Live differential vs headless Chromium via playwright (machine-local
//     ../devtools): generated Set-Cookie lines served for real; the stored
//     cookie (name, value, domain, path, expiry, flags, SameSite) must match
//     analyzeCookie's prediction. Skipped loudly if ../devtools is missing;
//     deploy.sh always runs it.
//  3. Differential vs curl's cookie engine (libcurl, an independent C
//     implementation) for the RFC 6265 date parser: curl applies no 400-day
//     cap, so it exposes the raw parsed epoch that Chrome's cap hides.
//
// Documented oracle divergences:
//  - curl does not enforce SameSite=None-requires-Secure, does not cap
//    expiry, and allows Domain=localhost (no public-suffix treatment for
//    it) — the curl differential therefore only covers date parsing and
//    size/prefix acceptance, not those rules.
//  - Non-ASCII bytes in values are mangled by Chrome's UTF-8 handling;
//    excluded from the corpus, covered by a warning instead.

'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const net = require('node:net');
const { execFile } = require('node:child_process');
const execFileP = require('node:util').promisify(execFile);
const C = require('./cookie.js');

const DEVTOOLS = path.join(__dirname, '../../../devtools/node_modules');
const HAS_PLAYWRIGHT = fs.existsSync(path.join(DEVTOOLS, 'playwright'));

const PAGE = 'http://a.localhost:8951/set/sub/dir';
const NOW = 1788080000; // fixed "now" for unit tests

function verdict(line, pageUrl = PAGE, now = NOW) {
  return C.analyzeCookie(C.parseSetCookieLine(line), { pageUrl, now });
}

// ---------------------------------------------------------------------------
test('pinned Chrome acceptance vectors', () => {
  // control bytes reject the whole cookie (TAB included)
  for (const bad of ['a=b\x01c', 'd=b\x7fc', 'tab=a\tb']) {
    assert.equal(verdict(bad).accepted, false, JSON.stringify(bad));
  }
  // SameSite rules
  assert.equal(verdict('a=1; SameSite=None').accepted, false);
  assert.equal(verdict('a=1; SameSite=None; Secure').accepted, true);
  assert.equal(verdict('a=1; SameSite=Whatever').stored.sameSite, 'default');
  // prefixes
  assert.equal(verdict('__Host-x=1; Secure; Path=/').accepted, true);
  assert.equal(verdict('__Host-x=1; Secure; Path=/set').accepted, false);
  assert.equal(verdict('__Host-x=1; Secure; Path=/; Domain=a.localhost').accepted, false);
  assert.equal(verdict('__Secure-x=1').accepted, false);
  // domain rules (a.localhost page)
  assert.equal(verdict('a=1; Domain=a.localhost').stored.hostOnly, false);
  assert.equal(verdict('b=2; Domain=.A.LOCALHOST').stored.domain, 'a.localhost');
  assert.equal(verdict('c=3; Domain=localhost').accepted, false);   // public suffix in Chrome
  assert.equal(verdict('d=4; Domain=b.localhost').accepted, false); // mismatch
  // default path comes from the request-path directory
  assert.equal(verdict('a=1').stored.path, '/set/sub');
  assert.equal(verdict('a=1; Path=/other').stored.path, '/other');
  // limits
  assert.equal(verdict('big=' + 'x'.repeat(4093)).accepted, true);   // 4096 total
  assert.equal(verdict('big=' + 'x'.repeat(4094)).accepted, false);  // 4097 total
  const longPath = verdict('a=1; Path=/' + 'p'.repeat(1200));
  assert.equal(longPath.stored.path, '/set/sub'); // oversized attr ignored
  // name/value forms
  assert.equal(verdict('justvalue').stored.name, '');
  assert.equal(verdict('justvalue').stored.value, 'justvalue');
  assert.equal(verdict('=').accepted, false);
  assert.equal(verdict('=a=b').accepted, false);          // nameless with '=' in value
  assert.equal(verdict('=__Host-spoof').accepted, false); // nameless prefix spoof
  assert.equal(verdict('a b=c').stored.name, 'a b');
  assert.equal(verdict('a="quoted"').stored.value, '"quoted"');
  // Max-Age
  const ma = verdict('a=1; Max-Age=3600');
  assert.equal(ma.stored.expires, NOW + 3600);
  assert.equal(verdict('a=1; Max-Age=0').stored.expires, 'past');
  assert.equal(verdict('a=1; Max-Age=-5').stored.expires, 'past');
  assert.equal(verdict('a=1; Max-Age=1.5').stored.expires, 'session'); // fraction ignored
  assert.equal(verdict('a=1; Max-Age=99999999999').stored.expires, NOW + 400 * 86400); // capped
  // Max-Age beats Expires; duplicate attrs: last wins
  assert.equal(verdict('a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=60').stored.expires, NOW + 60);
  assert.equal(verdict('a=1; Path=/x; Path=/; Max-Age=60; Max-Age=120').stored.path, '/');
  assert.equal(verdict('a=1; Path=/x; Path=/; Max-Age=60; Max-Age=120').stored.expires, NOW + 120);
});

test('pinned cookie-date vectors (Chrome + RFC 6265 §5.1.1)', () => {
  const D = C.parseCookieDate;
  const t = Date.UTC(2026, 9, 21, 7, 28, 0) / 1000;
  assert.equal(D('Wed, 21 Oct 2026 07:28:00 GMT'), t);
  assert.equal(D('Wed, 21-Oct-26 07:28:00 GMT'), t);   // 2-digit year → 2026
  assert.equal(D('07:28:00 21 Oct 2026'), t);          // any token order
  assert.equal(D('Oct 21 07:28:00 2026'), t);
  assert.equal(D('21 oct 2026 07:28'), null);          // no seconds → no time
  assert.equal(D('2026-10-21T07:28:00Z'), null);       // ISO is not a cookie date
  assert.equal(D('21-10-2026 07:28:00'), null);        // numeric month doesn't exist
  assert.equal(D('garbage'), null);
  assert.equal(D('Wed, 32 Oct 2026 07:28:00 GMT'), null); // day > 31
  assert.equal(D('Wed, 21 Oct 2026 24:28:00 GMT'), null); // hour > 23
  assert.equal(D('Wed, 21 Oct 1600 07:28:00 GMT'), null); // year < 1601
  assert.equal(D('Wed, 30 Feb 2026 07:28:00 GMT'), null); // impossible date
  assert.equal(D('Wed, 21 Oct 69 07:28:00 GMT'), Date.UTC(2069, 9, 21, 7, 28, 0) / 1000);
  assert.equal(D('Wed, 21 Oct 70 07:28:00 GMT'), Date.UTC(1970, 9, 21, 7, 28, 0) / 1000);
  // timezone tokens are ignored (GMT assumed), like browsers do
  assert.equal(D('Fri, 13 Feb 2009 23:31:30 +0100'), Date.UTC(2009, 1, 13, 23, 31, 30) / 1000);
});

test('wouldSend: domain, path, secure, SameSite', () => {
  const s = verdict('sid=1; Domain=a.localhost; Path=/app; Secure; SameSite=Lax').stored;
  assert.equal(C.wouldSend(s, 'https://a.localhost/app/x').sent, true);
  assert.equal(C.wouldSend(s, 'https://sub.a.localhost/app/x').sent, true);  // domain cookie
  assert.equal(C.wouldSend(s, 'https://b.localhost/app/x').sent, false);
  assert.equal(C.wouldSend(s, 'https://a.localhost/apple').sent, false);     // path boundary
  assert.equal(C.wouldSend(s, 'https://a.localhost/app').sent, true);
  const hostOnly = verdict('h=1; Path=/').stored;
  assert.equal(C.wouldSend(hostOnly, 'http://sub.a.localhost/').sent, false); // host-only
  const secure = verdict('s=1; Secure; Path=/').stored;
  assert.equal(C.wouldSend(secure, 'http://a.localhost/').sent, true); // trustworthy host
  assert.equal(C.wouldSend(secure, 'https://a.localhost/').sent, true);
  const secureElse = verdict('s=1; Secure; Path=/', 'https://example.com/').stored;
  assert.equal(C.wouldSend(secureElse, 'http://example.com/').sent, false); // http, non-trustworthy
  const strict = verdict('t=1; Path=/; SameSite=Strict').stored;
  assert.equal(C.wouldSend(strict, 'http://a.localhost/', 'cross-site-nav').sent, false);
  assert.equal(C.wouldSend(strict, 'http://a.localhost/', 'same-site').sent, true);
  const lax = verdict('l=1; Path=/').stored; // default → lax
  assert.equal(C.wouldSend(lax, 'http://a.localhost/', 'cross-site-nav').sent, true);
  assert.equal(C.wouldSend(lax, 'http://a.localhost/', 'cross-site-sub').sent, false);
  const none = verdict('n=1; Path=/; SameSite=None; Secure').stored;
  assert.equal(C.wouldSend(none, 'https://a.localhost/', 'cross-site-sub').sent, true);
});

test('parse forms: header names, Cookie request header, folded-comma hazard', () => {
  const entries = C.parseSetCookieInput('Set-Cookie: a=1; Path=/\nset-cookie: b=2\nc=3');
  assert.deepEqual(entries.map((e) => e.name), ['a', 'b', 'c']);
  assert.deepEqual(C.parseCookieHeader('Cookie: a=1; b=2; noval'),
    [{ name: 'a', value: '1' }, { name: 'b', value: '2' }, { name: '', value: 'noval' }]);
  const folded = verdict('a=1; Path=/, b=2; Path=/');
  assert.ok(folded.warnings.some((w) => w.includes('folded')));
});

test('security warnings fire', () => {
  assert.ok(verdict('session_token=abc123def; Path=/').warnings.some((w) => w.includes('HttpOnly')));
  assert.ok(verdict('t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig', 'https://example.com/').warnings.some((w) => w.includes('JWT')));
  assert.ok(verdict('a=1', 'https://example.com/').warnings.some((w) => w.includes('Secure')));
  assert.ok(verdict('a=1; Frobnicate=yes').warnings.some((w) => w.includes('Frobnicate')));
  assert.ok(verdict('__typo-a=1').warnings.some((w) => w.includes('__')));
  // secure-from-insecure-origin on a non-trustworthy host
  assert.equal(verdict('a=1; Secure', 'http://example.com/').accepted, false);
  assert.equal(verdict('a=1; Secure', 'http://a.localhost/').accepted, true);
});

// ---------------------------------------------------------------------------
// Live Chromium differential

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

const ATTR_POOL = [
  '', '; Path=/', '; Path=/set', '; Path=/other/deep', '; Path=nope', '; Path="/quoted"',
  '; Domain=a.localhost', '; Domain=.a.localhost', '; Domain=A.LOCALHOST',
  '; Domain=localhost', '; Domain=b.localhost', '; Domain=',
  '; Secure', '; HttpOnly', '; secure; httponly', '; HTTPONLY',
  '; SameSite=Strict', '; SameSite=lax', '; SameSite=None; Secure', '; SameSite=None',
  '; SameSite=Bogus', '; SameSite = Lax ',
  '; Max-Age=3600', '; Max-Age=0', '; Max-Age=-1', '; Max-Age=1.5', '; Max-Age=99999999999',
  '; Expires=Wed, 21 Oct 2026 07:28:00 GMT', '; Expires=Oct 21 07:28:00 2026',
  '; Expires=Wed, 21-Oct-26 07:28:00 GMT', '; Expires=21 oct 2026 07:28',
  '; Expires=Sun, 06 Nov 1994 08:49:37 GMT', '; Expires=garbage',
  '; Expires="Wed, 21 Oct 2026 07:28:00 GMT"',
  '; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=60',
  // timezone offsets in Expires are ignored (GMT assumed) — the 90s expiry
  // tolerance below would catch an hour-shifted interpretation
  '; Expires=Wed, 21 Oct 2026 07:28:00 +0500',
  '; Path=/x; Path=/', '; Max-Age=60; Max-Age=120',
  '; Frobnicate=yes', '; ; Max-Age=60', '; Partitioned; Secure; Path=/',
  '; Path=/' + 'p'.repeat(1100),
];
const NAME_POOL = ['n', 'session', '__Secure-s', '__Host-h', '__host-l', 'a b', ''];
const VALUE_POOL = ['v1', '', 'has space', '"quoted"', 'a,b', 'a=b', 'x'.repeat(700), 'e f', '__Host-spoof'];

test('differential: acceptance and stored form agree with real Chromium', { skip: !HAS_PLAYWRIGHT && 'playwright not installed in ../devtools' }, async () => {
  const { chromium } = await import(path.join(DEVTOOLS, 'playwright/index.mjs'));
  // raw-socket server so any byte sequence can go into Set-Cookie
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (!buf.includes('\r\n\r\n')) return;
      const m = /GET \/set\/sub\/dir\?([^ ]*) /.exec(buf);
      const cookies = m ? [...m[1].matchAll(/(?:^|&)c=([^&]*)/g)].map((x) => decodeURIComponent(x[1])) : [];
      sock.write(Buffer.from(['HTTP/1.1 200 OK', 'Content-Type: text/html', 'Content-Length: 2',
        ...cookies.map((c) => 'Set-Cookie: ' + c), 'Connection: close', '', 'ok'].join('\r\n'), 'latin1'));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const pageUrl = `http://a.localhost:${port}/set/sub/dir`;

  const browser = await chromium.launch();
  try {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const rnd = mulberry32(20260830);
  const nBatches = parseInt(process.env.COOKIE_CHROME_BATCHES || '25', 10);
  let checked = 0;
  for (let b = 0; b < nBatches; b++) {
    const lines = [];
    const seenKeys = new Set();
    for (let i = 0; i < 6; i++) {
      const name = pick(rnd, NAME_POOL);
      // unique names within a batch so cookies don't overwrite each other
      const uname = name === '' ? '' : `${name}${b}x${i}`;
      const line = `${uname}=${pick(rnd, VALUE_POOL)}${pick(rnd, ATTR_POOL)}${rnd() < 0.3 ? pick(rnd, ATTR_POOL) : ''}`;
      // empty-name cookies can still collide on (name,path,domain): the later
      // Set-Cookie overwrites the earlier, which would invalidate per-line
      // comparison — keep one line per storage key
      const mine = C.analyzeCookie(C.parseSetCookieLine(line), { pageUrl, now: Math.floor(Date.now() / 1000) });
      const k = mine.accepted && mine.stored ? `${mine.stored.name}|${mine.stored.path}|${mine.stored.domain}` : `r${i}`;
      if (seenKeys.has(k)) continue;
      seenKeys.add(k);
      lines.push(line);
    }
    await ctx.clearCookies();
    const now = Math.floor(Date.now() / 1000);
    await page.goto(`${pageUrl}?${lines.map((l) => 'c=' + encodeURIComponent(l)).join('&')}`);
    const got = await ctx.cookies();
    const byKey = new Map(got.map((c) => [`${c.name}|${c.path}|${c.domain}`, c]));

    for (const line of lines) {
      const mine = C.analyzeCookie(C.parseSetCookieLine(line), { pageUrl, now });
      const expectStored = mine.accepted && mine.stored.expires !== 'past';
      const key = expectStored
        ? `${mine.stored.name}|${mine.stored.path}|${mine.stored.hostOnly ? mine.stored.domain : '.' + mine.stored.domain}`
        : null;
      const chrome = key ? byKey.get(key) : undefined;
      assert.equal(!!chrome, expectStored,
        `${line}\n  mine: ${expectStored ? 'stored ' + key : 'not stored (' + (mine.rejectReasons[0] || 'past') + ')'}\n  chrome: ${JSON.stringify(got.map((c) => c.name))}`);
      if (chrome) {
        assert.equal(chrome.value, mine.stored.value, `value for ${line}`);
        assert.equal(chrome.secure, mine.stored.secure, `secure for ${line}`);
        assert.equal(chrome.httpOnly, mine.stored.httpOnly, `httpOnly for ${line}`);
        const ssMap = { default: 'Lax', lax: 'Lax', strict: 'Strict', none: 'None' };
        assert.equal(chrome.sameSite, ssMap[mine.stored.sameSite], `sameSite for ${line}`);
        if (mine.stored.expires === 'session') {
          assert.equal(chrome.expires, -1, `session for ${line}`);
        } else {
          assert.ok(Math.abs(chrome.expires - mine.stored.expires) < 90,
            `expiry for ${line}: chrome ${chrome.expires} vs mine ${mine.stored.expires}`);
        }
        checked++;
      }
    }
  }
  assert.ok(checked > 40, `only ${checked} stored cookies compared`);
  } finally {
    await browser.close();
    server.close();
  }
});

// ---------------------------------------------------------------------------
// curl differential: the date parser, against libcurl's independent one.
// curl applies no 400-day cap, exposing the raw parsed epoch.

const DATE_PARTS = {
  // no unknown weekdays ('Xyz, '): browsers/RFC skip unrecognized tokens,
  // curl fails the whole date on them — another documented curl divergence
  wd: ['Wed, ', 'Sun ', '', 'Mon, '],
  // no out-of-range fields ('32', '24:00:00'): browsers fail the whole date
  // (pinned in the vectors above), while curl's flexible tokenizer reassigns
  // them (day 32 becomes year 2032!) — the last documented curl divergence
  day: ['21', '01', '9', '31'],
  // no full month names ('October'): browsers/RFC match the first 3 chars,
  // curl treats full names differently with 2-digit years — pinned
  // Chrome-side ('21-Oct-26' etc. in the acceptance vectors)
  mon: ['Oct', 'oct', 'OCT', 'Nov', 'Foo', '10'],
  yr: ['2026', '2027', '26', '69', '2100'],
  // no '07:28' (missing seconds): curl accepts it, browsers and the RFC
  // require hh:mm:ss — divergence pinned Chrome-side in the acceptance vectors
  time: ['07:28:00', '23:59:59', '7:8:9'],
  // no '+0100'-style offsets here: curl's date parser honors them, while
  // browsers (and RFC 6265 §5.1.1) ignore timezone tokens and assume GMT —
  // a documented oracle divergence, pinned Chrome-side in the live
  // differential corpus above
  tz: [' GMT', '', ' UTC'],
};

test('differential: cookie-date parser agrees with curl (libcurl)', async () => {
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (!buf.includes('\r\n\r\n')) return;
      const m = /GET \/\?c=([^ ]*) /.exec(buf);
      const cookie = m ? decodeURIComponent(m[1]) : '';
      sock.write(Buffer.from(['HTTP/1.1 200 OK', 'Content-Length: 2',
        'Set-Cookie: ' + cookie, 'Connection: close', '', 'ok'].join('\r\n'), 'latin1'));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const port = server.address().port;
    const rnd = mulberry32(77777);
    const now = Math.floor(Date.now() / 1000);
    let compared = 0;
    for (let i = 0; i < 60; i++) {
      const day = pick(rnd, DATE_PARTS.day), mon = pick(rnd, DATE_PARTS.mon);
      // '31 Nov': impossible calendar date — Chrome (and this parser) reject
      // it, curl rolls it over to Dec 1; verified Chrome-side by probe
      if (day === '31' && mon.toLowerCase().startsWith('nov')) continue;
      const ds = `${pick(rnd, DATE_PARTS.wd)}${day} ${mon} ${pick(rnd, DATE_PARTS.yr)} ${pick(rnd, DATE_PARTS.time)}${pick(rnd, DATE_PARTS.tz)}`;
      const mine = C.parseCookieDate(ds);
      if (mine !== null && mine <= now) continue; // past dates: deletion semantics differ; skip
      // async execFile: execFileSync would block the event loop and deadlock
      // against the in-process server
      const { stdout: jar } = await execFileP('curl', ['-s', '-c', '-', '-o', '/dev/null',
        `http://127.0.0.1:${port}/?c=${encodeURIComponent(`x=1; Expires=${ds}`)}`]);
      const line = jar.split('\n').find((l) => l.includes('\tx\t'));
      assert.ok(line, `curl dropped: Expires=${ds}`);
      const epoch = parseInt(line.split('\t')[4], 10);
      assert.equal(epoch, mine === null ? 0 : mine, `Expires=${ds} (curl ${epoch}, mine ${mine})`);
      compared++;
    }
    assert.ok(compared > 30, `only ${compared} dates compared`);
  } finally { server.close(); }
});
