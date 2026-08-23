import { test } from "node:test";
import assert from "node:assert/strict";
import { domainToUnicode } from "node:url";
import {
  parseUrl,
  percentDecode,
  encodeVariants,
  punycodeDecode,
  hostToUnicode,
} from "./url.js";

// --- parseUrl: components --------------------------------------------------

test("full URL: every component lands in the right slot", () => {
  const r = parseUrl("https://user:p%40ss@example.com:8443/a/b%20c?x=1&y=two#sec%202");
  assert.equal(r.scheme, "https");
  assert.equal(r.assumedScheme, false);
  assert.equal(r.username, "user");
  assert.equal(r.password, "p@ss"); // percent-decoded for display
  assert.equal(r.hostname, "example.com");
  assert.equal(r.port, "8443");
  assert.equal(r.pathname, "/a/b%20c");
  assert.deepEqual(r.pathSegments, ["a", "b c"]);
  assert.deepEqual(
    r.params.map((p) => [p.key, p.value]),
    [["x", "1"], ["y", "two"]],
  );
  assert.equal(r.fragment, "sec%202");
  assert.equal(r.fragmentDecoded, "sec 2");
});

test("default port is stripped by the URL parser and reported as default", () => {
  const r = parseUrl("https://example.com:443/");
  assert.equal(r.port, "");
  assert.equal(r.defaultPort, 443);
  const r2 = parseUrl("http://example.com:8080/");
  assert.equal(r2.port, "8080");
  assert.equal(r2.defaultPort, 80);
});

test("schemeless input is retried as https:// and flagged", () => {
  const r = parseUrl("example.com/path?x=1");
  assert.equal(r.scheme, "https");
  assert.equal(r.assumedScheme, true);
  assert.equal(r.hostname, "example.com");
});

test("host:port input is not mistaken for a scheme", () => {
  // new URL("localhost:8080/health") "succeeds" with scheme localhost: —
  // the retry logic must catch this case.
  const r = parseUrl("localhost:8080/health");
  assert.equal(r.assumedScheme, true);
  assert.equal(r.hostname, "localhost");
  assert.equal(r.port, "8080");
  assert.equal(r.pathname, "/health");
});

test("IPv6 literal host keeps its brackets", () => {
  const r = parseUrl("http://[::1]:8080/x");
  assert.equal(r.hostname, "[::1]");
  assert.equal(r.port, "8080");
});

test("mailto: has no host and does not crash", () => {
  const r = parseUrl("mailto:someone@example.com");
  assert.equal(r.scheme, "mailto");
  assert.equal(r.hostname, "");
  assert.equal(r.pathname, "someone@example.com");
});

test("garbage throws", () => {
  assert.throws(() => parseUrl("http://exa mple.com/"), /Not a valid URL/);
  assert.throws(() => parseUrl(""), /Enter a URL/);
});

// --- parseUrl: query semantics ---------------------------------------------

test("query: + means space, %20 means space, bare key has null value", () => {
  const r = parseUrl("https://e.com/?q=a+b%20c&flag&=v&x=");
  assert.deepEqual(
    r.params.map((p) => [p.key, p.value]),
    [["q", "a b c"], ["flag", null], ["", "v"], ["x", ""]],
  );
});

test("query: UTF-8 percent-sequences decode", () => {
  const r = parseUrl("https://e.com/?q=%E2%9C%93&name=M%C3%BCller");
  assert.equal(r.params[0].value, "✓");
  assert.equal(r.params[1].value, "Müller");
});

test("query: malformed percent-sequences fall back to raw, not a crash", () => {
  const r = parseUrl("https://e.com/?bad=%zz&worse=%2");
  assert.equal(r.params[0].value, "%zz");
  assert.equal(r.params[1].value, "%2");
});

// --- parseUrl: warnings ----------------------------------------------------

test("warnings: embedded credentials, credential-looking params, repeats", () => {
  const r = parseUrl("https://u:pw@e.com/?access_token=abc&a=1&a=2");
  const ids = r.warnings.map((w) => w.id);
  assert.ok(ids.includes("credentials"));
  assert.ok(ids.includes("credential-params"));
  assert.ok(ids.includes("repeated-params"));
});

test("warnings: a clean URL has none", () => {
  assert.deepEqual(parseUrl("https://example.com/docs?page=2").warnings, []);
});

test("warnings: 'sig' matches but 'design' and 'author' do not", () => {
  const hit = parseUrl("https://e.com/?sig=x");
  assert.ok(hit.warnings.some((w) => w.id === "credential-params"));
  const miss = parseUrl("https://e.com/?design=x&author=y&assignee=z");
  assert.ok(!miss.warnings.some((w) => w.id === "credential-params"));
});

// --- punycode --------------------------------------------------------------

test("punycode: known vectors", () => {
  assert.equal(punycodeDecode("mnchen-3ya"), "münchen");
  // Cyrillic lookalike of apple.com — the homograph classic. Note the "l" is
  // U+04CF (lowercase palochka), not the capital: verified against Node's
  // domainToUnicode in the differential test below.
  assert.equal(punycodeDecode("80ak6aa92e"), "аррӏе");
  // all-basic label: trailing delimiter, no extended part
  assert.equal(punycodeDecode("abc-"), "abc");
});

test("punycode: differential against Node's domainToUnicode oracle", () => {
  const domains = [
    "xn--mnchen-3ya.de",
    "xn--80ak6aa92e.com",
    "xn--fsqu00a.xn--0zwm56d",
    "xn--wgbh1c.example",
    "xn--bcher-kva.ch",
    "plain-ascii.example.com",
  ];
  for (const d of domains) {
    assert.equal(hostToUnicode(d).unicode, domainToUnicode(d), d);
  }
});

test("punycode: invalid input throws; hostToUnicode leaves it raw", () => {
  assert.throws(() => punycodeDecode("!!!"), /invalid punycode digit/);
  assert.throws(() => punycodeDecode("999"), /truncated/);
  const r = hostToUnicode("xn--!!!.example");
  assert.equal(r.unicode, "xn--!!!.example");
  assert.equal(r.isIdn, false);
});

test("IDN hostname surfaces both forms and a warning", () => {
  const r = parseUrl("https://xn--80ak6aa92e.com/login");
  assert.equal(r.hostname, "xn--80ak6aa92e.com");
  assert.equal(r.hostUnicode, "аррӏе.com");
  assert.ok(r.warnings.some((w) => w.id === "idn"));
});

test("unicode input host is punycoded by the parser, then round-trips", () => {
  const r = parseUrl("https://münchen.example/");
  assert.equal(r.hostname, "xn--mnchen-3ya.example");
  assert.equal(r.hostUnicode, "münchen.example");
});

// --- percent-decode / encode helpers ---------------------------------------

test("percentDecode: strict errors carry the offending position", () => {
  assert.throws(() => percentDecode("ab%2"), /position 2/);
  assert.throws(() => percentDecode("%G1x"), /position 0/);
});

test("percentDecode: plusAsSpace only when asked", () => {
  assert.equal(percentDecode("a+b%20c"), "a+b c");
  assert.equal(percentDecode("a+b%20c", { plusAsSpace: true }), "a b c");
});

test("percentDecode: invalid UTF-8 becomes U+FFFD, not an exception", () => {
  assert.equal(percentDecode("%FF"), "�");
});

test("encodeVariants: component vs full-URL vs form encoding", () => {
  const v = encodeVariants("a b&c/d?");
  assert.equal(v.component, "a%20b%26c%2Fd%3F");
  assert.equal(v.full, "a%20b&c/d?");
  assert.equal(v.form, "a+b%26c%2Fd%3F");
});
