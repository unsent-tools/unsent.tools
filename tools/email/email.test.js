// Tests for email.js. The differential oracle is Python's email stdlib:
// header splitting vs email.parser (compat32), dates vs
// email.utils.parsedate_to_datetime, address lists vs
// email.utils.getaddresses, RFC 2047 vs email.header.decode_header.
// Received / Authentication-Results / DKIM parsing (which Python does not
// structure) are covered by pinned vectors from the RFCs and realistic
// fixtures.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  splitHeaders, unfold, stripComments, splitTopLevel, parseDate, decodeWords,
  parseAddressList, addressDomain, parseReceived, analyzeReceivedChain,
  parseAuthResults, parseDkimSignature, analyze, fmtDelay, EmailError,
} from "./email.js";

const py = (script, input) =>
  execFileSync("python3", ["-c", script], {
    input: JSON.stringify(input), encoding: "utf8",
  });

// Deterministic PRNG so failures reproduce.
function rng(seed) {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];

// ---------------------------------------------------------------------------

test("splitHeaders differential vs Python email.parser (compat32)", () => {
  const r = rng(1);
  const names = ["From", "To", "Subject", "X-Weird", "Received", "MIME-Version"];
  const values = ["hello", "  padded", "a\n\tfolded\n continuation", "", "x: y (z)"];
  const messages = [];
  for (let i = 0; i < 120; i++) {
    const n = 1 + Math.floor(r() * 6);
    let msg = "";
    for (let j = 0; j < n; j++) msg += `${pick(r, names)}:${pick(r, [" ", ""])}${pick(r, values)}\n`;
    if (r() < 0.5) msg += "\nbody line\nmore body\n";
    messages.push(msg);
  }
  // Hand-picked structural cases.
  messages.push("From x@y Mon Aug 24 01:02:03 2026\nSubject: mbox\n\nb");
  messages.push("Subject: ends without newline");
  messages.push("Subject: ok\nnot a header line\nAfter: never seen");
  messages.push("A: 1\r\nB: 2\r\n\r\nbody");
  const expected = JSON.parse(py(`
import sys, json, re, email
out = []
for m in json.load(sys.stdin):
    msg = email.message_from_string(m)
    items = [[k, re.sub(r"\\n(?=[ \\t])", "", v).replace("\\n", "").strip()]
             for k, v in msg.items()]
    out.append(items)
print(json.dumps(out))
`, messages));
  messages.forEach((m, i) => {
    const got = splitHeaders(m).headers.map((h) => [h.name, h.value.trim()]);
    assert.deepEqual(got, expected[i], `message #${i}: ${JSON.stringify(m)}`);
  });
});

test("parseDate differential vs Python parsedate_to_datetime", () => {
  const r = rng(2);
  const zones = ["+0000", "-0000", "+0530", "-0700", "+1400", "-1130", "UT", "UTC",
                 "GMT", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT", "XXX"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const dates = [];
  for (let i = 0; i < 200; i++) {
    const day = 1 + Math.floor(r() * 28);
    const mon = pick(r, months);
    // 2-digit years 50–68 excluded: RFC 5322 says 19xx, Python uses the
    // POSIX 69 pivot; we follow the RFC.
    const year = pick(r, ["2026", "1999", "2049", String(69 + Math.floor(r() * 31)),
                          String(Math.floor(r() * 50)).padStart(2, "0")]);
    const hms = `${String(Math.floor(r() * 24)).padStart(2, "0")}:${String(Math.floor(r() * 60)).padStart(2, "0")}` +
                (r() < 0.8 ? `:${String(Math.floor(r() * 60)).padStart(2, "0")}` : "");
    const dow = r() < 0.5 ? pick(r, ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]) + ", " : "";
    const comment = r() < 0.3 ? " (a comment)" : "";
    dates.push(`${dow}${day} ${mon} ${year} ${hms} ${pick(r, zones)}${comment}`);
  }
  const expected = JSON.parse(py(`
import sys, json, email.utils, datetime
out = []
for s in json.load(sys.stdin):
    dt = email.utils.parsedate_to_datetime(s)
    if dt.tzinfo is None:
        out.append([dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000, None])
    else:
        out.append([dt.timestamp() * 1000, dt.utcoffset().total_seconds() / 60])
print(json.dumps(out))
`, dates));
  dates.forEach((s, i) => {
    const got = parseDate(s);
    assert.equal(got.epochMs, expected[i][0], `epoch for ${JSON.stringify(s)}`);
    assert.equal(got.offsetMin, expected[i][1], `offset for ${JSON.stringify(s)}`);
  });
});

test("parseDate rejects nonsense, accepts RFC edge forms", () => {
  assert.throws(() => parseDate("yesterday"), EmailError);
  assert.throws(() => parseDate("31 Feb 2026 10:00:00 +0000"), EmailError);
  assert.throws(() => parseDate("1 Aug 2026 25:00:00 +0000"), EmailError);
  // Leap second: clamped to :59 rather than rejected (Python raises here).
  const leap = parseDate("31 Dec 2016 23:59:60 +0000");
  assert.equal(leap.epochMs, Date.UTC(2016, 11, 31, 23, 59, 59));
  // Obsolete 3-digit year (RFC 5322 §4.3: add 1900).
  assert.equal(parseDate("1 Jan 100 00:00 GMT").epochMs, Date.UTC(2000, 0, 1));
  // Full month name, folded whitespace, leap day.
  assert.equal(parseDate("29   February 2024 12:00:00 +0000").epochMs,
               Date.UTC(2024, 1, 29, 12));
});

test("decodeWords differential vs Python decode_header", () => {
  const r = rng(3);
  const texts = ["café au lait", "日本語テスト", "snowman ☃", "plain ascii",
                 "Ünïcödé", "a=b_c d?e", "réponse: où?"];
  const cases = [];
  const b64utf8 = (t) => `=?utf-8?B?${Buffer.from(t, "utf8").toString("base64")}?=`;
  const qLatin1 = (t) => "=?iso-8859-1?Q?" + Array.from(Buffer.from(t, "latin1"))
    .map((b) => {
      const c = String.fromCharCode(b);
      if (/[a-zA-Z0-9!*+\-/]/.test(c)) return c;
      if (c === " ") return "_";
      return "=" + b.toString(16).toUpperCase().padStart(2, "0");
    }).join("") + "?=";
  for (let i = 0; i < 60; i++) {
    const t = pick(r, texts);
    const isLatin1 = [...t].every((c) => c.charCodeAt(0) < 256);
    const word = isLatin1 && r() < 0.5 ? qLatin1(t) : b64utf8(t);
    cases.push(pick(r, [
      word,
      `prefix ${word} suffix`,
      `${word} ${b64utf8("second")}`,      // adjacent: gap must vanish
      `${word} plain ${b64utf8("third")}`, // non-adjacent: gap stays
    ]));
  }
  const expected = JSON.parse(py(`
import sys, json
from email.header import decode_header, make_header
out = [str(make_header(decode_header(s))) for s in json.load(sys.stdin)]
print(json.dumps(out))
`, cases));
  cases.forEach((s, i) => {
    const got = decodeWords(s);
    assert.equal(got.text, expected[i], `decode of ${JSON.stringify(s)}`);
    assert.equal(got.problems.length, 0);
  });
});

test("decodeWords: broken words are surfaced, not swallowed", () => {
  const bad = decodeWords("=?utf-8?B?!!notb64!!?= and =?no-such-charset-9?Q?ab?=");
  assert.equal(bad.problems.length, 2);
  assert.match(bad.problems[0], /base64/);
  assert.match(bad.problems[1], /charset/i);
  assert.ok(bad.text.includes("=?no-such-charset-9?Q?ab?=")); // left as-is
});

test("parseAddressList differential vs Python getaddresses", () => {
  const r = rng(4);
  const displays = ['Jane Doe', '"Doe, Jane"', '"quoted \\"inner\\""', "", "Ünïcödé Näme"];
  const addrs = ["a@example.com", "b.c+tag@mail.example.org", "x_y@sub.domain.io"];
  const lists = [];
  for (let i = 0; i < 100; i++) {
    const n = 1 + Math.floor(r() * 3);
    const parts = [];
    for (let j = 0; j < n; j++) {
      const d = pick(r, displays), a = pick(r, addrs);
      parts.push(d ? `${d} <${a}>` : (r() < 0.5 ? a : `<${a}>`));
    }
    lists.push(parts.join(", "));
  }
  lists.push('undisclosed-recipients:;');
  lists.push('grp: g@h.example, "Q;x" <i@j.example>;, after@k.example');
  lists.push('e@f.example (a comment)');
  const expected = JSON.parse(py(`
import sys, json, email.utils
out = [email.utils.getaddresses([s]) for s in json.load(sys.stdin)]
print(json.dumps(out))
`, lists));
  lists.forEach((s, i) => {
    // Python uses a trailing comment as display-name fallback; mirror that
    // here (we keep comments separate for the UI).
    const got = parseAddressList(s)
      .filter((mb) => mb.address !== "" || (mb.display !== "" && !mb.comment))
      .map((mb) => [mb.display || mb.comment || "", mb.address]);
    const exp = expected[i].filter(([d, a]) => a !== "" || d !== "");
    assert.deepEqual(got, exp, `addresses in ${JSON.stringify(s)}`);
  });
});

test("parseAddressList: route addresses and domains (better than Python here)", () => {
  // Python's getaddresses returns ('','') for an obs-route address; we
  // extract the real mailbox.
  assert.deepEqual(parseAddressList("<@relay.example,@x.example:user@final.example>")[0].address,
                   "user@final.example");
  assert.equal(addressDomain("User@Sub.Example.COM."), "sub.example.com");
  assert.equal(addressDomain("no-at-sign"), null);
});

test("parseReceived: RFC 5321-style trace line", () => {
  const rec = parseReceived(
    "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) " +
    "by mx.example.com (Postfix) with ESMTPS id 4XyZ12AbCd " +
    "for <user@example.com>; Tue, 26 Aug 2026 05:01:02 -0700 (PDT)");
  assert.equal(rec.clauses.from.split(" ")[0], "mail-sor-f41.google.com");
  assert.match(rec.clauses.by, /^mx\.example\.com/);
  assert.equal(rec.clauses.with, "ESMTPS");
  assert.equal(rec.clauses.id, "4XyZ12AbCd");
  assert.equal(rec.clauses.for, "<user@example.com>");
  assert.deepEqual(rec.ips, ["209.85.220.41"]);
  assert.equal(rec.date.epochMs, Date.UTC(2026, 7, 26, 12, 1, 2));
  assert.equal(rec.date.offsetMin, -420);
});

test("parseReceived: IPv6, missing date, semicolon in quoted string", () => {
  const v6 = parseReceived("from x ([IPv6:2001:db8::1]) by y; 1 Jan 2026 00:00:00 +0000");
  assert.deepEqual(v6.ips, ["2001:db8::1"]);
  const nodate = parseReceived("by mail.example.com with local");
  assert.equal(nodate.date, null);
  assert.equal(nodate.clauses.with, "local");
  const q = parseReceived('from a (helo="b;c") by d; 1 Jan 2026 00:00:00 GMT');
  assert.equal(q.date.epochMs, Date.UTC(2026, 0, 1));
});

test("analyzeReceivedChain: chronological order, delays, total", () => {
  const chain = analyzeReceivedChain([
    "from c by d; Tue, 26 Aug 2026 12:00:10 +0000",   // top = latest
    "from b by c; Tue, 26 Aug 2026 12:00:03 +0000",
    "from a by b; Tue, 26 Aug 2026 12:00:00 +0000",   // bottom = first
  ]);
  assert.equal(chain.hops[0].clauses.from, "a");
  assert.equal(chain.hops[0].delayMs, null);
  assert.equal(chain.hops[1].delayMs, 3000);
  assert.equal(chain.hops[2].delayMs, 7000);
  assert.equal(chain.totalMs, 10000);
});

test("parseAuthResults: RFC 8601 examples", () => {
  // Modeled on RFC 8601 appendix B examples.
  const a = parseAuthResults(
    'example.com; spf=pass smtp.mailfrom=example.net; ' +
    'dkim=pass (good signature) header.d=example.net header.s=sel1; ' +
    'dmarc=fail reason="p=reject" header.from=example.org');
  assert.equal(a.authserv, "example.com");
  assert.deepEqual(a.results.map((r) => [r.method, r.result]),
                   [["spf", "pass"], ["dkim", "pass"], ["dmarc", "fail"]]);
  assert.deepEqual(a.results[0].props,
                   [{ ptype: "smtp", prop: "mailfrom", value: "example.net" }]);
  assert.equal(a.results[2].reason, "p=reject");
  const none = parseAuthResults("mx.example.com 1; none");
  assert.equal(none.authserv, "mx.example.com");
  assert.deepEqual(none.results, [{ method: "none", result: null, props: [] }]);
  // Method version suffix is stripped: dkim/1=pass
  const ver = parseAuthResults("s.example; dkim/1=pass header.d=x.example");
  assert.equal(ver.results[0].method, "dkim");
});

test("parseDkimSignature: tag list with folded values", () => {
  const d = parseDkimSignature(
    "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=20230601; " +
    "t=1756200000; x=1756804800; l=1024; " +
    "h=to:subject:message-id:date:from:mime-version; " +
    "bh=abc def=; b=xyz 123");
  assert.equal(d.domain, "example.com");
  assert.equal(d.selector, "20230601");
  assert.equal(d.algorithm, "rsa-sha256");
  assert.equal(d.signedAt, 1756200000000);
  assert.equal(d.expiresAt, 1756804800000);
  assert.equal(d.bodyLengthLimited, true);
  assert.equal(d.fromSigned, true);
  assert.equal(d.tags.bh, "abcdef="); // FWS inside tag values is stripped
});

const CLEAN_FIXTURE = `Delivered-To: user@example.com
Received: by 2002:a05:6a10:1234:0:0:0:0 with SMTP id abc123;
        Tue, 26 Aug 2026 05:01:04 -0700 (PDT)
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.example.com (Postfix) with ESMTPS id 4XyZ12AbCd
        for <user@example.com>;
        Tue, 26 Aug 2026 05:01:03 -0700 (PDT)
Received: from sender-host ([10.0.0.5])
        by smtp.sender.org with ESMTPSA;
        Tue, 26 Aug 2026 05:01:00 -0700 (PDT)
Authentication-Results: mx.example.com;
       dkim=pass header.i=@sender.org header.s=sel1 header.b=AbCdEf;
       spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=sender.org;
       dmarc=pass (p=NONE) header.from=sender.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.org; s=sel1;
        t=1787490060; h=from:to:subject:date:message-id;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdA==
From: =?utf-8?B?SsO8cmdlbg==?= Sender <j@sender.org>
To: user@example.com
Subject: =?utf-8?Q?Caf=C3=A9?= meeting
Date: Tue, 26 Aug 2026 05:00:58 -0700
Message-ID: <20260826120058.GA1234@sender.org>

Body here.
`;

test("analyze: clean fixture — chain, auth, no spurious warnings", () => {
  const now = Date.UTC(2026, 7, 26, 13, 0, 0);
  const a = analyze(CLEAN_FIXTURE, now);
  assert.equal(a.headers.length, 11);
  assert.equal(a.bodyPresent, true);
  assert.equal(a.subject.text, "Café meeting");
  assert.equal(a.from[0].display, "=?utf-8?B?SsO8cmdlbg==?= Sender");
  assert.equal(a.from[0].address, "j@sender.org");
  assert.equal(a.chain.hops.length, 3);
  assert.equal(a.chain.hops[0].clauses.by, "smtp.sender.org");
  assert.equal(a.chain.hops[1].delayMs, 3000);
  assert.equal(a.chain.hops[2].delayMs, 1000);
  assert.equal(a.chain.totalMs, 4000);
  assert.equal(a.auth[0].authserv, "mx.example.com");
  assert.deepEqual(a.auth[0].results.map((r) => r.result), ["pass", "pass", "pass"]);
  assert.equal(a.dkim[0].domain, "sender.org");
  assert.equal(a.dkim[0].fromSigned, true);
  assert.equal(a.dateHeader.offsetMin, -420);
  assert.deepEqual(a.warnings, [], "no warnings expected on the clean fixture");
});

const NASTY_FIXTURE = `Received: from mx.big.example (mx.big.example [198.51.100.7])
        by inbox.example.net; Tue, 26 Aug 2026 12:00:00 +0000
Received: from unknown (HELO spam-relay) ([203.0.113.9])
        by mx.big.example; Tue, 26 Aug 2026 12:30:00 +0000
Authentication-Results: inbox.example.net;
       spf=softfail smtp.mailfrom=bounce.shady.example;
       dkim=fail reason="bad signature" header.d=paypal.example;
       dmarc=fail reason="p=reject" header.from=paypal.example
DKIM-Signature: v=1; a=rsa-sha1; d=shady.example; s=x; l=5;
        h=to:subject; bh=x; b=y
From: "PayPal Support <support@paypal.example>" <alerts@shady.example>
Reply-To: collector@other.example
To: victim@example.net
Subject: urgent
Date: Mon, 25 Aug 2026 03:00:00 +0000
Message-ID: <x@shady.example>

.`;

test("analyze: nasty fixture — every red flag fires", () => {
  const a = analyze(NASTY_FIXTURE, Date.UTC(2026, 7, 26, 13, 0, 0));
  const all = a.warnings.join("\n");
  assert.match(all, /Reply-To domain \(other\.example\) differs from From domain \(shady\.example\)/);
  assert.match(all, /display name contains “support@paypal\.example”/);
  assert.match(all, /dkim=fail \(bad signature\)/);
  assert.match(all, /dmarc=fail/);
  assert.match(all, /spf=softfail/);
  assert.match(all, /l= body-length limiting/);
  assert.match(all, /does not sign the From header/);
  assert.match(all, /Date header is .* before final delivery/);
  // Hop timestamped BEFORE previous hop (12:30 at mx.big, then 12:00 at inbox).
  assert.match(all, /before the previous hop/);
});

test("analyze: multiple From headers and no Date are flagged", () => {
  const a = analyze("From: a@x.example\nFrom: b@y.example\nSubject: hi\n", 0);
  const all = a.warnings.join("\n");
  assert.match(all, /Multiple From headers/);
  assert.match(all, /No Date header/);
  assert.throws(() => analyze("", 0), EmailError);
});

test("splitTopLevel / stripComments / unfold primitives", () => {
  assert.deepEqual(splitTopLevel('a;b "x;y" (p;q);c', ";"), ['a', 'b "x;y" (p;q)', 'c']);
  const sc = stripComments('keep (drop (nested) this) "lit (eral)" tail');
  assert.equal(sc.text, 'keep  "lit (eral)" tail');
  assert.deepEqual(sc.comments, ['drop (nested) this']);
  assert.equal(unfold("a\n b\n\tc"), "a b\tc");
  assert.equal(fmtDelay(150000), "2m 30s");
  assert.equal(fmtDelay(90061000), "1d 1h");
});
