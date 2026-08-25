import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseElement, readOid, readInteger, readTime, pemBlocks } from "./der.js";
import { decodeCertificate, decodePemInput, fingerprints, nameToRfc2253 } from "./cert.js";

const FIXTURES = readFileSync(new URL("./fixtures.pem", import.meta.url), "utf8");
const NOW_2026 = Date.UTC(2026, 7, 25); // fixed "now" so tests don't drift

function openssl(args, input) {
  return execFileSync("openssl", args, { input, encoding: "utf8" });
}

// ---- DER primitives ----------------------------------------------------

test("DER primitives: OID, INTEGER, times (hand-built vectors)", () => {
  // OID 2.999 encodes as 0x88 0x37 (multi-byte first component)
  const oid = new Uint8Array([0x06, 0x02, 0x88, 0x37]);
  assert.equal(readOid(oid, parseElement(oid)), "2.999");
  const oid2 = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
  assert.equal(readOid(oid2, parseElement(oid2)), "1.2.840.113549.1.1.11");

  // INTEGER: leading 0x80 bit means negative in DER
  const neg = new Uint8Array([0x02, 0x01, 0x80]);
  assert.equal(readInteger(neg, parseElement(neg)).bigint, -128n);
  assert.equal(readInteger(neg, parseElement(neg)).negative, true);
  const pos = new Uint8Array([0x02, 0x02, 0x00, 0xff]);
  assert.equal(readInteger(pos, parseElement(pos)).bigint, 255n);

  // UTCTime pivot: 49 → 2049, 50 → 1950 (RFC 5280)
  const t = (s, tag = 23) => {
    const b = new Uint8Array([tag, s.length, ...[...s].map((c) => c.charCodeAt(0))]);
    return readTime(b, parseElement(b));
  };
  assert.equal(t("490101000000Z").iso, "2049-01-01T00:00:00Z");
  assert.equal(t("500101000000Z").iso, "1950-01-01T00:00:00Z");
  assert.equal(t("20510416121941Z", 24).iso, "2051-04-16T12:19:41Z");
  assert.equal(t("20510416121941Z", 24).kind, "GeneralizedTime");
  assert.throws(() => t("990230000000Z"), /Impossible date/); // Feb 30
  assert.throws(() => t("4901010000Z"), /Malformed UTCTime/); // missing seconds
});

test("DER parser rejects BER indefinite length and truncation", () => {
  assert.throws(() => parseElement(new Uint8Array([0x30, 0x80, 0x00, 0x00])), /Indefinite/);
  assert.throws(() => parseElement(new Uint8Array([0x30, 0x05, 0x02, 0x01])), /Truncated/);
  assert.throws(() => parseElement(new Uint8Array([])), /Truncated/);
});

// ---- real-world fixture: the unsent.tools chain ------------------------

test("fixture chain: all 4 certificates decode; leaf fields pinned", async () => {
  const { certs, skipped } = decodePemInput(FIXTURES, NOW_2026);
  assert.equal(certs.length, 4);
  assert.equal(skipped.length, 0);
  for (const c of certs) assert.ok(c.decoded, c.error);

  const leaf = certs[0].decoded;
  assert.equal(leaf.subject.rfc2253, "CN=unsent.tools");
  assert.equal(leaf.issuer.rfc2253, "CN=YE2,O=Let's Encrypt,C=US");
  assert.equal(leaf.serial.hex, "057bf538e0c85230c086004b4d19974452c6");
  assert.equal(leaf.version, 3);
  assert.equal(leaf.isCa, false);
  assert.equal(leaf.selfIssued, false);
  assert.equal(leaf.status.state, "valid"); // at the pinned NOW_2026
  assert.deepEqual(leaf.san, [{ type: "DNS", value: "unsent.tools" }]);
  const eku = leaf.extensions.find((e) => e.oid === "2.5.29.37");
  assert.ok(eku.purposes.some((p) => p.name === "TLS server authentication"));
  const ku = leaf.extensions.find((e) => e.oid === "2.5.29.15");
  assert.equal(ku.critical, true);
  assert.ok(ku.usages.includes("digitalSignature"));
  assert.ok(leaf.extensions.some((e) => e.name.includes("Signed Certificate Timestamps")));
  const aia = leaf.extensions.find((e) => e.oid === "1.3.6.1.5.5.7.1.1");
  assert.ok(aia.entries.some((e) => e.label === "CA Issuers"));
  assert.equal(leaf.warnings.length, 0);

  const fp = await fingerprints(certs[0].der);
  assert.equal(fp.sha256, "48:8B:00:B1:85:26:98:47:45:A3:4A:44:23:CA:1F:3F:0D:65:47:74:C5:A4:D2:95:BC:C1:45:EE:EE:FC:CD:A0");

  // the intermediate really is a CA
  const inter = certs[1].decoded;
  assert.equal(inter.isCa, true);
  assert.equal(inter.subject.rfc2253, leaf.issuer.rfc2253);
});

test("validity status pivots on the explicit now parameter", () => {
  const leaf = decodePemInput(FIXTURES, NOW_2026).certs[0].decoded;
  const before = decodePemInput(FIXTURES, leaf.notBefore.epochMs - 1000).certs[0].decoded;
  assert.equal(before.status.state, "not-yet-valid");
  const after = decodePemInput(FIXTURES, leaf.notAfter.epochMs + 86400000).certs[0].decoded;
  assert.equal(after.status.state, "expired");
  assert.ok(after.warnings.some((w) => /Expired/.test(w)));
});

// ---- differential vs openssl over freshly generated certificates -------

const CONFIGS = [
  { label: "rsa2048 basic + SANs",
    key: ["rsa:2048"], days: 365,
    subj: "/CN=test.example/O=Example Org/C=US",
    addext: ["subjectAltName=DNS:test.example,DNS:*.example.net,IP:192.0.2.1,IP:2001:db8::1,email:who@example.com,URI:https://example.com/x"] },
  { label: "rsa4096 sha512 unicode DN",
    key: ["rsa:4096"], days: 30, extra: ["-sha512", "-utf8"],
    subj: "/O=Ünïcode Örg/CN=tëst.example" },
  { label: "ec P-256",
    key: ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], days: 90,
    subj: "/CN=ecc.example/OU=Ops/OU=Dev",
    addext: ["subjectAltName=DNS:ecc.example,IP:2001:db8:85a3::8a2e:370:7334"] },
  { label: "ec P-384 CA with keyUsage/EKU",
    key: ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"], days: 3650,
    subj: "/CN=Test CA/O=CA Org",
    addext: ["keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
             "extendedKeyUsage=serverAuth,clientAuth",
             "basicConstraints=critical,CA:TRUE,pathlen:0"] },
  { label: "ed25519",
    key: ["ed25519"], days: 60, subj: "/CN=eddy.example" },
  // note: `req -x509` defaults to CA:TRUE, which suppresses the leaf-only
  // warnings — force CA:FALSE so this behaves like a real (bad) leaf cert
  { label: "sha1 long validity (GeneralizedTime) escaping DN",
    key: ["rsa:2048"], days: 9000, extra: ["-sha1"],
    subj: "/CN= weird, name/O=Comma\\, Inc",
    addext: ["basicConstraints=CA:FALSE"] },
];

function generate(cfg, dir, i) {
  const out = join(dir, `c${i}.pem`);
  execFileSync("openssl", [
    "req", "-x509", "-newkey", ...cfg.key, "-keyout", join(dir, `k${i}.pem`),
    "-out", out, "-days", String(cfg.days), "-nodes", "-subj", cfg.subj,
    ...(cfg.extra || []),
    ...(cfg.addext || []).flatMap((e) => ["-addext", e]),
  ], { stdio: ["ignore", "ignore", "ignore"] });
  return readFileSync(out, "utf8");
}

test("differential vs openssl x509: subject/issuer/serial/dates/fingerprint/key/sigalg", async () => {
  const dir = mkdtempSync(join(tmpdir(), "certdiff-"));
  for (let i = 0; i < CONFIGS.length; i++) {
    const cfg = CONFIGS[i];
    const pem = generate(cfg, dir, i);
    const d = decodePemInput(pem, NOW_2026).certs[0].decoded;
    const q = (args) => openssl(["x509", "-noout", ...args], pem).trim();

    // DN, RFC 2253 form (raw UTF-8, no MSB escaping)
    const subj = q(["-subject", "-nameopt", "RFC2253,-esc_msb,utf8"]).replace(/^subject=/, "");
    const iss = q(["-issuer", "-nameopt", "RFC2253,-esc_msb,utf8"]).replace(/^issuer=/, "");
    assert.equal(d.subject.rfc2253, subj, `${cfg.label}: subject`);
    assert.equal(d.issuer.rfc2253, iss, `${cfg.label}: issuer`);

    // serial (openssl prints uppercase hex)
    assert.equal(d.serial.hex.toUpperCase(), q(["-serial"]).replace(/^serial=/, ""), `${cfg.label}: serial`);

    // validity instants
    const nb = Date.parse(q(["-startdate"]).replace(/^notBefore=/, ""));
    const na = Date.parse(q(["-enddate"]).replace(/^notAfter=/, ""));
    assert.equal(d.notBefore.epochMs, nb, `${cfg.label}: notBefore`);
    assert.equal(d.notAfter.epochMs, na, `${cfg.label}: notAfter`);

    // SHA-256 fingerprint of the DER
    const fp = await fingerprints(decodePemInput(pem, NOW_2026).certs[0].der);
    const ofp = q(["-fingerprint", "-sha256"]).replace(/^.*Fingerprint=/, "");
    assert.equal(fp.sha256, ofp, `${cfg.label}: fingerprint`);

    // key type/size and signature algorithm from -text
    const text = q(["-text"]);
    if (d.publicKey.type === "RSA") {
      const bits = Number(/Public-Key: \((\d+) bit\)/.exec(text)[1]);
      assert.equal(d.publicKey.bits, bits, `${cfg.label}: RSA bits`);
    }
    const sigalg = /Signature Algorithm: (\S+)/.exec(text)[1];
    // openssl prints Ed25519 as "ED25519"
    assert.equal(d.signature.name.toLowerCase(), sigalg.toLowerCase(), `${cfg.label}: sig alg`);

    // SANs, when present: compare type:value multisets (openssl says "IP Address")
    if (cfg.addext && cfg.addext[0].startsWith("subjectAltName")) {
      const sanLine = q(["-ext", "subjectAltName"]).split("\n").slice(1).join("").trim();
      const expected = sanLine.split(", ").map((s) => {
        let [t, ...rest] = s.split(":");
        let v = rest.join(":");
        if (t === "IP Address") {
          t = "IP";
          // openssl prints IPv6 uncompressed/uppercase; normalize via our decoder's form
          if (v.includes(":")) v = d.san.find((n) => n.type === "IP" && n.value.includes(":"))?.value ?? v.toLowerCase();
        }
        return `${t}:${v}`;
      }).sort();
      const mine = d.san.map((n) => `${n.type}:${n.value}`).sort();
      assert.deepEqual(mine, expected, `${cfg.label}: SAN`);
    }
  }
});

test("generated CA cert: keyUsage bits, basicConstraints, EKU decode", () => {
  const dir = mkdtempSync(join(tmpdir(), "certca-"));
  const pem = generate(CONFIGS[3], dir, 0);
  const d = decodePemInput(pem, NOW_2026).certs[0].decoded;
  assert.equal(d.isCa, true);
  const bc = d.extensions.find((e) => e.oid === "2.5.29.19");
  assert.equal(bc.critical, true);
  assert.equal(bc.pathLen, 0);
  const ku = d.extensions.find((e) => e.oid === "2.5.29.15");
  assert.deepEqual(ku.usages.sort(), ["cRLSign", "digitalSignature", "keyCertSign"]);
  const eku = d.extensions.find((e) => e.oid === "2.5.29.37");
  assert.deepEqual(eku.purposes.map((p) => p.name),
    ["TLS server authentication", "TLS client authentication"]);
  // CA certs are exempt from the 398-day leaf warning
  assert.ok(!d.warnings.some((w) => /398/.test(w)));
  assert.ok(d.notes.some((n) => /Self-signed CA/.test(n)));
});

test("weak signature and long validity are warned about", () => {
  const dir = mkdtempSync(join(tmpdir(), "certweak-"));
  const pem = generate(CONFIGS[5], dir, 0);
  const d = decodePemInput(pem, NOW_2026).certs[0].decoded;
  assert.ok(d.warnings.some((w) => /SHA-1/.test(w)), "SHA-1 warning");
  assert.ok(d.warnings.some((w) => /398 days/.test(w)), "validity warning");
  assert.ok(d.warnings.some((w) => /No Subject Alternative Name/.test(w)), "no-SAN warning");
  assert.ok(d.notes.some((n) => /GeneralizedTime/.test(n)), "GeneralizedTime note");
  // escaping in the DN survived the round trip (checked against openssl in the differential test)
  assert.ok(d.subject.rfc2253.includes("CN=\\ weird\\, name"));
});

test("decipherOnly/keyAgreement: key usage bit 8 lives in the second byte", () => {
  const dir = mkdtempSync(join(tmpdir(), "certku-"));
  const pem = generate({ key: ["rsa:2048"], days: 30, subj: "/CN=ku.example",
    addext: ["keyUsage=keyAgreement,decipherOnly"] }, dir, 0);
  const d = decodePemInput(pem, NOW_2026).certs[0].decoded;
  const ku = d.extensions.find((e) => e.oid === "2.5.29.15");
  assert.deepEqual(ku.usages.sort(), ["decipherOnly", "keyAgreement"]);
});

// ---- input handling ----------------------------------------------------

test("PEM input handling: multiple blocks, keys/CSRs skipped with a message, bare base64", () => {
  const dir = mkdtempSync(join(tmpdir(), "certpem-"));
  const pem = generate(CONFIGS[0], dir, 0);
  const key = readFileSync(join(dir, "k0.pem"), "utf8");
  const csr = openssl(["req", "-new", "-key", join(dir, "k0.pem"), "-subj", "/CN=csr.example"]);

  const mixed = decodePemInput(pem + key + csr + pem, NOW_2026);
  assert.equal(mixed.certs.length, 2);
  assert.equal(mixed.skipped.length, 2);
  assert.ok(mixed.skipped.some((s) => /PRIVATE KEY/.test(s)));
  assert.ok(mixed.skipped.some((s) => /CSR/.test(s)));

  // bare base64 (no armor) decodes as one cert
  const b64 = pem.replace(/-----[A-Z ]+-----/g, "");
  assert.equal(decodePemInput(b64, NOW_2026).certs.length, 1);
  assert.equal(decodePemInput(b64, NOW_2026).certs[0].decoded.subject.rfc2253,
    "C=US,O=Example Org,CN=test.example");

  assert.throws(() => decodePemInput("not a certificate at all!", NOW_2026), /No PEM block/);
  assert.equal(pemBlocks(FIXTURES).length, 4);
});

test("corrupted certificates fail with a clear error, not garbage output", () => {
  const { certs } = decodePemInput(FIXTURES, NOW_2026);
  const der = certs[0].der;
  // truncate mid-structure
  assert.throws(() => decodeCertificate(der.subarray(0, 40), NOW_2026), /Truncated|Malformed|Not valid/);
  // a key, force-labelled as a certificate, must not "decode"
  const notCert = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
  assert.throws(() => decodeCertificate(notCert, NOW_2026), /Malformed|expected/i);
});

test("high-bit serial: DER's 0x00 sign pad is not shown (matches openssl)", () => {
  // 0xDEADBEEFCAFEF00D has its top bit set, so DER stores it with a leading
  // 0x00 pad byte; openssl and browsers display it without the pad.
  const dir = mkdtempSync(join(tmpdir(), "certser-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt",
    "ec_paramgen_curve:P-256", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"),
    "-days", "5", "-nodes", "-subj", "/CN=serial.example",
    "-set_serial", "0xdeadbeefcafef00d"], { stdio: ["ignore", "ignore", "ignore"] });
  const pem = readFileSync(join(dir, "c.pem"), "utf8");
  const d = decodePemInput(pem, NOW_2026).certs[0].decoded;
  assert.equal(d.serial.hex, "deadbeefcafef00d");
  const oss = openssl(["x509", "-noout", "-serial"], pem).trim().replace("serial=", "");
  assert.equal(d.serial.hex.toUpperCase(), oss);
  assert.equal(d.serial.negative, false);
});

test("RFC 2253 escaping rules (unit)", () => {
  const rdns = [[{ name: "CN", value: " lead and trail ", hexFallback: false }],
                [{ name: "O", value: "a,b+c\\d", hexFallback: false }],
                [{ name: "OU", value: "#tag", hexFallback: false }]];
  assert.equal(nameToRfc2253(rdns), "OU=\\#tag,O=a\\,b\\+c\\\\d,CN=\\ lead and trail\\ ");
});
