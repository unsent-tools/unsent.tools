// Tests for spf.js. Differential oracles:
//   - pyspf (spf.query.validate_mechanism / .check) for SPF mechanism grammar
//     and full-record evaluation of ip4/ip6/all records — both DNS-free.
//   - checkdmarc.parse_dmarc_record (blackhole resolver, so network-dependent
//     warnings degrade the same way everywhere) for DMARC tags and defaults.
//   - dkimpy's dkim.util.parse_tag_value for RFC 6376 tag-list strictness.
//   - openssl-generated RSA/Ed25519 keys for DKIM key-size reporting.
// Calibrated divergences are noted inline where generation avoids them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  extractRecords, detectType, checkMacroString, parseSPFTerm, parseSPF,
  evaluateSPF, parseTagList, parseDMARC, parseDKIMKey, parseMTASTS,
  parseTLSRPT, analyze, RecordError,
} from "./spf.js";

const py = (script, input) =>
  execFileSync("python3", ["-c", script], {
    input: JSON.stringify(input), encoding: "utf8", maxBuffer: 1 << 24,
  });

function rng(seed) {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];

// ---------------------------------------------------------------------------

test("SPF mechanism grammar differential vs pyspf validate_mechanism", () => {
  const r = rng(42);
  const quals = ["", "+", "-", "~", "?"];
  // "%{d0}" excluded: RFC 7208 §7.3 requires a nonzero digit transformer
  // (we reject) but pyspf accepts it — divergence pinned in the vectors test.
  const domains = ["example.com", "_spf.google.com", "mail.example-x.org", "%{d}", "%{i2r}.rbl.example", "%{s}", "%{l}.%{o}", "a..b", "-x.example", "%{x}", "%{c}.d", "x%(i)", "%{ir}.%{v}._spf.%{d2}"];
  const ips4 = ["192.0.2.1", "1.2.3.0", "255.255.255.255", "0.0.0.0", "1.2.3.01", "999.1.1.1", "1.2.3", "1.2.3.4.5"];
  const ips6 = ["2001:db8::1", "::1", "fe80::", "::ffff:1.2.3.4", "2001:db8::/x", "1:2:3:4:5:6:7:8:9", "12345::"];
  const cidr4s = ["", "/0", "/24", "/32", "/33", "/033", "/3a"];
  const cidr6s = ["", "//0", "//64", "//128", "//129", "//012"];
  const mechs = [];
  for (let i = 0; i < 400; i++) {
    const q = pick(r, quals);
    switch (Math.floor(r() * 6)) {
      case 0: mechs.push(q + "all" + pick(r, ["", ":", "/24"])); break;
      // pyspf flags include:<query domain> as "trivial recursion", a semantic
      // check pinned separately — keep the query domain out of this pool.
      // Bare "include"/"exists" (no colon) also excluded: the ABNF requires a
      // domain-spec (we reject) but pyspf defaults to the query domain.
      // ("%{d}" expands to the query domain, tripping the same check.)
      case 1: mechs.push(q + pick(r, ["include", "exists"]) + ":" + (r() < 0.85 ? pick(r, domains.filter((d) => d !== "example.com" && d !== "%{d}")) : "")); break;
      case 2: mechs.push(q + pick(r, ["a", "mx", "A", "MX"]) + (r() < 0.6 ? ":" + pick(r, domains) : "") + pick(r, cidr4s) + pick(r, cidr6s)); break;
      case 3: mechs.push(q + "ptr" + (r() < 0.5 ? ":" + pick(r, domains) : "")); break;
      case 4: mechs.push(q + pick(r, ["ip4", "IP4"]) + (r() < 0.9 ? ":" : "") + pick(r, ips4) + pick(r, cidr4s)); break;
      case 5: mechs.push(q + "ip6" + (r() < 0.9 ? ":" : "") + pick(r, ips6) + pick(r, cidr4s.map((c) => c || ""))); break;
    }
  }
  mechs.push("all", "-ALL", "ip4:1.2.3.4/0", "a/0//0", "mx/31//127", "ip6:::1",
             "include:foo.com/24", "exists:%%dot%-%_x.example", "bogus:xyz", "ip5:1.2.3.4");
  const expected = JSON.parse(py(`
import sys, json, spf
q = spf.query(i='1.2.3.4', s='x@example.com', h='example.com', receiver='t', verbose=False)
out = []
for m in json.load(sys.stdin):
    try:
        r = q.validate_mechanism(m)
        out.append({"ok": True, "name": r[1], "cidr": r[3], "result": r[4]})
    except spf.PermError as e:
        out.append({"ok": False})
print(json.dumps(out))
`, mechs));
  mechs.forEach((m, i) => {
    const exp = expected[i];
    let got = null, err = null;
    try { got = parseSPFTerm(m); } catch (e) { err = e; }
    if (got && got.kind !== "mechanism") got = null; // pyspf only validates mechanisms
    assert.equal(!!got, exp.ok, `validity mismatch for ${JSON.stringify(m)}: js=${err ? err.message : "ok"} py=${exp.ok}`);
    if (!exp.ok) return;
    assert.equal(got.name, exp.name, `name for ${JSON.stringify(m)}`);
    assert.equal(got.result, exp.result, `qualifier result for ${JSON.stringify(m)}`);
    const cidr = got.name === "ip6" ? got.cidr6
      : ["ip4", "a", "mx"].includes(got.name) ? got.cidr4 : 32;
    assert.equal(cidr ?? 32, exp.cidr, `cidr for ${JSON.stringify(m)}`);
  });
});

test("SPF full-record evaluation differential vs pyspf check (no DNS needed)", () => {
  const r = rng(7);
  const cases = [];
  for (let i = 0; i < 150; i++) {
    const n = 1 + Math.floor(r() * 4);
    const terms = [];
    const candidates4 = [], candidates6 = [];
    for (let j = 0; j < n; j++) {
      const q = pick(r, ["", "+", "-", "~", "?"]);
      if (r() < 0.5) {
        const net = `${1 + Math.floor(r() * 223)}.${Math.floor(r() * 256)}.${Math.floor(r() * 256)}.0`;
        const cidr = pick(r, ["", "/8", "/16", "/24", "/31", "/32"]);
        terms.push(`${q}ip4:${net}${cidr}`);
        candidates4.push(net.replace(/0$/, String(Math.floor(r() * 256))));
      } else {
        const net = `2001:db8:${Math.floor(r() * 65536).toString(16)}::`;
        terms.push(`${q}ip6:${net}${pick(r, ["", "/48", "/64", "/128"])}`);
        candidates6.push(net + Math.floor(r() * 65536).toString(16));
      }
    }
    if (r() < 0.8) terms.push(pick(r, ["", "+", "-", "~", "?"]) + "all");
    const record = "v=spf1 " + terms.join(" ");
    // Half the probes aim near a listed network, half are far away.
    const ip = r() < 0.5 && (candidates4.length || candidates6.length)
      ? pick(r, [...candidates4, ...candidates6])
      : (r() < 0.5 ? `${1 + Math.floor(r() * 223)}.${Math.floor(r() * 250)}.9.9` : `2001:db8:${Math.floor(r() * 65536).toString(16)}::9`);
    cases.push({ record, ip });
  }
  cases.push({ record: "v=spf1 ip4:1.2.3.0/24", ip: "9.9.9.9" });          // default neutral
  cases.push({ record: "v=spf1 ip4:1.2.3.0/24 foo=bar ~all", ip: "9.9.9.9" }); // unknown modifier ignored
  cases.push({ record: "v=spf1 ip6:::ffff/112 -all", ip: "::1" });
  const expected = JSON.parse(py(`
import sys, json, spf
out = []
for c in json.load(sys.stdin):
    q = spf.query(i=c["ip"], s='x@example.com', h='example.com', receiver='t', verbose=False)
    out.append(q.check(c["record"])[0])
print(json.dumps(out))
`, cases));
  cases.forEach((c, i) => {
    const parsed = parseSPF(c.record);
    assert.equal(parsed.error, null, `record should parse: ${c.record}`);
    const got = evaluateSPF(parsed, c.ip);
    assert.equal(got.result, expected[i], `${c.record} for ${c.ip}`);
  });
});

test("SPF pinned vectors: RFC 7208 shapes, macros, lookup counting, permerrors", () => {
  for (const rec of [
    "v=spf1 +all", "v=spf1 a -all", "v=spf1 a:example.org -all",
    "v=spf1 mx -all", "v=spf1 mx:example.org -all", "v=spf1 mx mx:example.org -all",
    "v=spf1 mx/30 mx:example.org/30 -all", "v=spf1 ptr -all",
    "v=spf1 ip4:192.0.2.128/28 -all",
    "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all",
    "v=spf1 redirect=_spf.example.com",
  ]) assert.equal(parseSPF(rec).error, null, rec);

  for (const rec of [
    "v=spf1 ip4:1.2.3.4 -all extra",       // unknown bare term
    "v=spf1 exists:%{c}.example.com -all", // exp-only macro in a mechanism
    "v=spf1 redirect=a.com redirect=b.com",
    "v=spf1 exp=a.com exp=b.com",
    "v=spf1 all:",
    "v=spf1 ip4:1.2.3.4/33 -all",
    "v=spf1 include: -all",
    "v=spf6 -all",
    "v=spf1 exists:%{d0}.x -all", // digit transformer MUST be nonzero (§7.3); pyspf is laxer
    "v=spf1 exists -all",         // include/exists require ":domain" (§5.2); pyspf is laxer
    "v=spf1 include ~all",
  ]) assert.notEqual(parseSPF(rec).error, null, rec);

  const p = parseSPF("v=spf1 include:a.com include:b.com a mx ptr exists:x.y redirect=z.example");
  assert.equal(p.lookups, 7);
  assert.ok(parseSPF("v=spf1 " + "include:x.com ".repeat(11) + "-all").warnings.some((w) => w.includes("over the hard limit")));
  assert.ok(parseSPF("v=spf1 +all").warnings.some((w) => w.includes("entire internet")));
  assert.ok(parseSPF("v=spf1 ip4:1.2.3.4").warnings.some((w) => w.includes('No "all"')));
  assert.ok(parseSPF("v=spf1 -all ip4:1.2.3.4").warnings.some((w) => w.includes('after "all"')));
  assert.ok(parseSPF("v=spf1 ptr -all").warnings.some((w) => w.includes("deprecated")));
  assert.ok(parseSPF("v=spf1 -all redirect=x.com").warnings.some((w) => w.includes("redirect")));

  // Qualifier-less modifiers only: "+redirect=x" is not a modifier.
  assert.equal(parseSPF("v=spf1 +foo=bar -all").error !== null, true);

  const e = evaluateSPF(parseSPF("v=spf1 ip4:192.0.2.0/24 mx -all"), "::ffff:192.0.2.7");
  assert.equal(e.result, "pass"); // IPv4-mapped input evaluated as IPv4
});

test("input extraction: dig lines, escapes, multi-string concatenation", () => {
  // Multi-string TXT concatenates with no separator (RFC 7208 §3.3).
  const [r1] = extractRecords('example.com. 3600 IN TXT "v=spf1 ip4:192.0.2.0/2" "4 -all"');
  assert.equal(r1.record, "v=spf1 ip4:192.0.2.0/24 -all");
  assert.equal(r1.name, "example.com");
  const spf1 = parseSPF(r1.record);
  assert.equal(spf1.terms[0].cidr4, 24);

  // RFC 1035 escapes: \" and \\ and \DDD.
  const [r2] = extractRecords('x.example. IN TXT "a\\"b\\\\c\\065"');
  assert.equal(r2.record, 'a"b\\cA');

  // dig with several records: unrecognized ones are skipped, names captured.
  const multi = analyze([
    'example.com. 300 IN TXT "google-site-verification=abc123"',
    'example.com. 300 IN TXT "v=spf1 mx -all"',
  ].join("\n"));
  assert.equal(multi.results.length, 1);
  assert.equal(multi.skipped.length, 1);

  // Two SPF records for one name is a permerror-level cross warning.
  const two = analyze('a. TXT "v=spf1 -all"\nb. TXT "v=spf1 ~all"');
  assert.ok(two.cross.some((w) => w.includes("exactly one")));

  // Bare records with soft wrapping join into one.
  const [r3] = extractRecords("v=DMARC1; p=reject;\n  rua=mailto:x@example.com");
  assert.equal(detectType(r3.record, null), "dmarc");

  assert.throws(() => extractRecords('x TXT "unbalanced'), RecordError);
});

test("DMARC differential vs checkdmarc (tags, defaults, validity)", () => {
  const r = rng(99);
  // Valid enum values only: on invalid values checkdmarc is inconsistent with
  // the RFCs (it accepts any adkim/aspf but hard-errors on bad sp/fo, where
  // RFC 9989 prescribes relaxation/defaults) — that logic is pinned instead.
  const pols = ["none", "quarantine", "reject", "NONE", "Reject"];
  const records = [];
  for (let i = 0; i < 120; i++) {
    const tags = ["v=DMARC1", "p=" + pick(r, pols)];
    if (r() < 0.4) tags.push("sp=" + pick(r, pols));
    if (r() < 0.3) tags.push("np=" + pick(r, pols));
    if (r() < 0.4) tags.push("adkim=" + pick(r, ["r", "s"]));
    if (r() < 0.4) tags.push("aspf=" + pick(r, ["r", "s"]));
    if (r() < 0.3) tags.push("fo=" + pick(r, ["0", "1", "d", "s", "1:d", "1:d:s"]));
    if (r() < 0.2) tags.push("psd=" + pick(r, ["y", "n", "u"]));
    if (r() < 0.2) tags.push("t=" + pick(r, ["y", "n"]));
    if (r() < 0.25) tags.push("rua=mailto:" + pick(r, ["agg@example.com", "a@x.zz,mailto:b@y.zz", "r@ex.org!10m"]));
    records.push(tags.join("; ") + (r() < 0.2 ? ";" : ""));
  }
  records.push("v=DMARC1", "p=reject; v=DMARC1",
               "v=DMARC1; p=reject; p=none", "V=DMARC1; P=REJECT",
               "v=DMARC1;p=quarantine;sp=none;np=reject");
  const expected = JSON.parse(py(`
import sys, json
from checkdmarc.dmarc import parse_dmarc_record
import dns.resolver
res = dns.resolver.Resolver(configure=False)
res.nameservers = ['192.0.2.1']; res.lifetime = 0.05
out = []
for rec in json.load(sys.stdin):
    try:
        p = parse_dmarc_record(rec, "example.com", resolver=res, ignore_unrelated_records=True)
        out.append({"ok": True, "tags": {k: v["value"] for k, v in p["tags"].items()}})
    except Exception:
        out.append({"ok": False})
print(json.dumps(out))
`, records));
  records.forEach((rec, i) => {
    const exp = expected[i];
    const got = parseDMARC(rec, "_dmarc.example.com");
    assert.equal(got.error === null, exp.ok, `validity for ${JSON.stringify(rec)}: js=${got.error} py=${exp.ok}`);
    if (!exp.ok) return;
    for (const k of ["p", "sp", "np", "adkim", "aspf", "psd"]) {
      assert.equal(got.effective[k], exp.tags[k], `${k} for ${JSON.stringify(rec)}`);
    }
    assert.equal(got.effective.fo.join(":"), exp.tags.fo, `fo for ${JSON.stringify(rec)}`);
    assert.equal(got.effective.testing, exp.tags.t === "y", `t for ${JSON.stringify(rec)}`);
  });
});

test("DMARC pinned vectors: reports, legacy tags, external destinations", () => {
  const d = parseDMARC("v=DMARC1; p=quarantine; rua=mailto:agg@example.com!10m,mailto:agg@thirdparty.example; ruf=mailto:fail@example.com; fo=1:d; ri=86400; pct=25", "_dmarc.example.com");
  assert.equal(d.error, null);
  assert.equal(d.rua.length, 2);
  assert.equal(d.rua[0].sizeLimit, "10m");
  assert.ok(d.infos.some((x) => x.includes("example.com._report._dmarc.thirdparty.example")));
  assert.ok(d.infos.some((x) => x.includes("pct=25")));
  assert.ok(d.warnings.some((x) => x.includes("bypasses the policy")));
  assert.ok(!d.warnings.some((x) => x.includes("no \"ruf=\"")));

  const weak = parseDMARC("v=DMARC1; p=reject; sp=none; t=y; shrug=1; fo=1", null);
  assert.equal(weak.error, null);
  for (const frag of ["sp=none", "t=y", 'Unknown tag "shrug="', '"fo="', "rua"]) {
    assert.ok(weak.warnings.some((w) => w.includes(frag)), `expected warning about ${frag}: ${JSON.stringify(weak.warnings)}`);
  }
  assert.ok(parseDMARC("v=DMARC1; p=none; np=none; sp=reject", null).warnings.some((w) => w.includes("np=")));
  assert.equal(parseDMARC("v=DMARC1; p=reject; pct=150", null).error !== null, true);
  assert.equal(parseDMARC("v=DMARC1; rua=mailto:x@y.zz", null).effective.p, "none");

  // RFC 9989 §4.7 relaxation: invalid p/sp/np → p=none with rua, no record without.
  assert.equal(parseDMARC("v=DMARC1; p=bogus; rua=mailto:x@y.zz", null).effective.p, "none");
  assert.equal(parseDMARC("v=DMARC1; p=bogus", null).error !== null, true);
  assert.equal(parseDMARC("v=DMARC1; p=reject; sp=bogus; rua=mailto:x@y.zz", null).effective.p, "none");
  // Invalid minor tags fall back to their defaults with a warning.
  const minor = parseDMARC("v=DMARC1; p=reject; adkim=x; fo=q; rua=mailto:x@y.zz", null);
  assert.equal(minor.error, null);
  assert.equal(minor.effective.adkim, "r");
  assert.deepEqual(minor.effective.fo, ["0"]);
  assert.ok(minor.warnings.some((w) => w.includes("adkim=x")));

  // Self-referencing SPF include/redirect (pyspf's "trivial recursion").
  assert.ok(parseSPF("v=spf1 include:example.com -all", "example.com").warnings.some((w) => w.includes("own domain")));
  assert.ok(parseSPF("v=spf1 redirect=example.com", "example.com.").warnings.some((w) => w.includes("own domain")));
  assert.equal(parseSPF("v=spf1 include:example.com -all", "other.org").warnings.length, 0);
});

test("DKIM tag-list differential vs dkimpy parse_tag_value", () => {
  const r = rng(5);
  const names = ["v", "k", "p", "h", "s", "t", "n", "g", "x"];
  const values = ["DKIM1", "rsa", "MIGfMA0G", "", "sha1:sha256", "*", "y:s", "a b c", " padded "];
  const lists = [];
  for (let i = 0; i < 150; i++) {
    const n = 1 + Math.floor(r() * 5);
    const parts = [];
    for (let j = 0; j < n; j++) {
      if (r() < 0.08) { parts.push(pick(r, ["bad", "", "=x"])); continue; }
      parts.push(`${pick(r, names)}${pick(r, ["=", " = ", "="])}${pick(r, values)}`);
    }
    lists.push(parts.join(";") + (r() < 0.3 ? ";" : ""));
  }
  lists.push("v=DKIM1; k=rsa; p=MIGf", "p=abc; p=def", "a=1;;b=2", " v=DKIM1", "k = rsa ; p = xyz");
  const expected = JSON.parse(py(`
import sys, json
from dkim.util import parse_tag_value
out = []
for l in json.load(sys.stdin):
    try:
        d = parse_tag_value(l.encode())
        out.append({"ok": True, "tags": {k.decode(): v.decode() for k, v in d.items()}})
    except Exception:
        out.append({"ok": False})
print(json.dumps(out))
`, lists));
  lists.forEach((l, i) => {
    const exp = expected[i];
    let got = null, err = null;
    try { got = parseTagList(l, { strictEmpty: true }); } catch (e) { err = e; }
    assert.equal(!!got, exp.ok, `validity for ${JSON.stringify(l)}: js=${err?.message} py=${exp.ok}`);
    if (!exp.ok) return;
    const map = Object.fromEntries(got.map((t) => [t.name, t.value]));
    assert.deepEqual(map, exp.tags, `tags for ${JSON.stringify(l)}`);
  });
});

test("DKIM key records: sizes vs openssl-generated keys", () => {
  const sh = (cmd) => execFileSync("sh", ["-c", cmd], { encoding: "utf8" }).trim();
  const tmp = sh("mktemp -d");
  try {
    for (const bits of [1024, 2048]) {
      const b64 = sh(`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -quiet -out ${tmp}/k.pem 2>/dev/null; openssl pkey -in ${tmp}/k.pem -pubout -outform DER | base64 -w0`);
      const rec = parseDKIMKey(`v=DKIM1; k=rsa; p=${b64}`, "sel._domainkey.example.com");
      assert.equal(rec.error, null);
      assert.equal(rec.keyBits, bits);
      assert.equal(rec.selector, "sel");
      assert.equal(rec.domain, "example.com");
      assert.equal(rec.warnings.some((w) => w.includes("RFC 8301 recommends 2048")), bits < 2048, `warnings at ${bits}`);
    }
    // Bare RSAPublicKey (legacy publication form).
    const bare = sh(`openssl rsa -in ${tmp}/k.pem -pubout -RSAPublicKey_out -outform DER 2>/dev/null | base64 -w0`);
    const recBare = parseDKIMKey(`k=rsa; p=${bare}`);
    assert.equal(recBare.keyBits, 2048);
    assert.ok(recBare.warnings.some((w) => w.includes("bare RSAPublicKey")));
    // Ed25519: RFC 8463 wants the raw 32 bytes, not SPKI.
    const spki = sh(`openssl genpkey -algorithm ed25519 -out ${tmp}/e.pem 2>/dev/null; openssl pkey -in ${tmp}/e.pem -pubout -outform DER | base64 -w0`);
    const raw = sh(`openssl pkey -in ${tmp}/e.pem -pubout -outform DER | tail -c 32 | base64 -w0`);
    const good = parseDKIMKey(`v=DKIM1; k=ed25519; p=${raw}`);
    assert.equal(good.error, null);
    assert.equal(good.keyBits, 256);
    const wrapped = parseDKIMKey(`v=DKIM1; k=ed25519; p=${spki}`);
    assert.ok(wrapped.error?.includes("common generator mistake"), wrapped.error);
  } finally {
    sh(`rm -rf ${tmp}`);
  }
});

test("DKIM pinned vectors: revocation, flags, hashes, structure", () => {
  const revoked = parseDKIMKey("v=DKIM1; k=rsa; p=");
  assert.equal(revoked.revoked, true);
  assert.ok(revoked.warnings.some((w) => w.includes("revoked")));

  const nasty = parseDKIMKey("v=DKIM1; g=admin; h=sha1; t=y:s; s=phone; p=notb64!!!");
  assert.ok(nasty.warnings.some((w) => w.includes("g=")));
  assert.ok(nasty.warnings.some((w) => w.includes("RFC 8301")));
  assert.ok(nasty.warnings.some((w) => w.includes("t=y") || w.includes("testing")));
  assert.ok(nasty.warnings.some((w) => w.includes("s=phone")));
  assert.ok(nasty.error.includes("base64"));

  assert.ok(parseDKIMKey("k=rsa; v=DKIM1; p=").warnings.some((w) => w.includes("first tag")));
  assert.ok(parseDKIMKey("k=rsa").error.includes('No "p="'));
  assert.ok(parseDKIMKey("v=DKIM1; p=abc; p=def").error.includes("duplicate"));
  // Detection via owner name and via tag shape.
  assert.equal(detectType("k=rsa; p=MIGf", "s1._domainkey.example.com"), "dkim");
  assert.equal(detectType("k=rsa; p=MIGf", null), "dkim");
});

test("MTA-STS and TLSRPT records", () => {
  assert.equal(parseMTASTS("v=STSv1; id=20260827120000").error, null);
  assert.ok(parseMTASTS("v=STSv1; id=20260827120000").infos.some((i) => i.includes("mta-sts.txt")));
  assert.ok(parseMTASTS("v=STSv1").error.includes("id="));
  assert.ok(parseMTASTS("v=STSv1; id=has spaces!").error);
  assert.ok(parseMTASTS("id=x; v=STSv1").error.includes("start with"));

  const t = parseTLSRPT("v=TLSRPTv1; rua=mailto:tls@example.com,https://example.com/report");
  assert.equal(t.error, null);
  assert.equal(t.rua.length, 2);
  assert.ok(parseTLSRPT("v=TLSRPTv1").error.includes("rua"));
  assert.ok(parseTLSRPT("v=TLSRPTv1; rua=ftp://x").error);
  assert.equal(detectType("v=TLSRPTv1; rua=mailto:a@b.c", null), "tlsrpt");

  // Sender ID is recognized and flagged as historic.
  const sid = analyze("spf2.0/pra +all");
  assert.ok(sid.results[0].warnings.some((w) => w.includes("Sender ID")));
});

test("fixtures: clean records produce zero warnings, nasty ones fire everything", () => {
  const cleanSpf = analyze('example.com. IN TXT "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"').results[0];
  assert.equal(cleanSpf.warnings.length, 0, JSON.stringify(cleanSpf.warnings));
  const cleanDmarc = analyze('_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"').results[0];
  assert.equal(cleanDmarc.warnings.length, 0, JSON.stringify(cleanDmarc.warnings));

  const nastySpf = parseSPF("v=spf1 ptr ip4:192.0.2.1 +all mx include:a.b include:c.d a:x.y a:z.w exists:q.r mx:t.u include:v.w include:x.z a redirect=other.example");
  for (const frag of ["deprecated", "entire internet", 'after "all"', "redirect", "over the hard limit"]) {
    assert.ok(nastySpf.warnings.some((w) => w.includes(frag)), `expected ${frag}: ${JSON.stringify(nastySpf.warnings)}`);
  }
});
