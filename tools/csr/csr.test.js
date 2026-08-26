import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeCsr, decodeCsrPemInput, verifyCsrSignature, ecdsaDerToRaw } from "./csr.js";
import { parseIPv6, ipv6ToString } from "../subnet/subnet6.js";

// openssl req -text prints IPv6 uncompressed (2001:DB8:0:0:0:0:0:1); we emit
// RFC 5952. Route both spellings through the (Python-verified) subnet6
// canonicalizer so the comparison is about the address, not its spelling.
function canonIp(v) {
  if (!v.includes(":")) return v;
  try { return ipv6ToString(parseIPv6(v).value); } catch { return v; }
}

function openssl(args, input) {
  return execFileSync("openssl", args, { input, encoding: "utf8" });
}

// ---- CSR generation ----------------------------------------------------

const CONFIGS = [
  { label: "rsa2048 + SANs",
    key: ["rsa:2048"],
    subj: "/CN=test.example/O=Example Org/C=US",
    addext: ["subjectAltName=DNS:test.example,DNS:*.example.net,IP:192.0.2.1,IP:2001:db8::1,email:who@example.com,URI:https://example.com/x"] },
  { label: "rsa2048 sha512 unicode DN",
    key: ["rsa:2048"], extra: ["-sha512", "-utf8"],
    subj: "/O=Ünïcode Örg/CN=tëst.example" },
  { label: "ec P-256 + SANs",
    key: ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
    subj: "/CN=ecc.example/OU=Ops/OU=Dev",
    addext: ["subjectAltName=DNS:ecc.example,IP:2001:db8:85a3::8a2e:370:7334"] },
  { label: "ec P-384 CA request with keyUsage/EKU",
    key: ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
    subj: "/CN=Test CA/O=CA Org",
    addext: ["keyUsage=critical,keyCertSign,cRLSign",
             "extendedKeyUsage=serverAuth,clientAuth",
             "basicConstraints=critical,CA:TRUE,pathlen:0",
             "subjectAltName=DNS:ca.example"] },
  { label: "ed25519",
    key: ["ed25519"], subj: "/CN=eddy.example",
    addext: ["subjectAltName=DNS:eddy.example"] },
  { label: "rsa2048 sha1 (weak)",
    key: ["rsa:2048"], extra: ["-sha1"],
    subj: "/CN=old.example/O=Comma\\, Inc" },
];

const dir = mkdtempSync(join(tmpdir(), "csrdiff-"));
function generate(cfg, i) {
  const out = join(dir, `r${i}.pem`);
  execFileSync("openssl", [
    "req", "-new", "-newkey", ...cfg.key, "-keyout", join(dir, `k${i}.pem`),
    "-out", out, "-nodes", "-subj", cfg.subj,
    ...(cfg.extra || []),
    ...(cfg.addext || []).flatMap((e) => ["-addext", e]),
  ], { stdio: ["ignore", "ignore", "ignore"] });
  return readFileSync(out, "utf8");
}
const PEMS = CONFIGS.map((cfg, i) => generate(cfg, i));

// ---- differential vs openssl req ---------------------------------------

test("differential vs openssl req: subject/key/sigalg/SANs on generated CSRs", () => {
  for (let i = 0; i < CONFIGS.length; i++) {
    const cfg = CONFIGS[i], pem = PEMS[i];
    const d = decodeCsrPemInput(pem).csrs[0].decoded;
    const q = (args) => openssl(["req", "-noout", ...args], pem).trim();

    const subj = q(["-subject", "-nameopt", "RFC2253,-esc_msb,utf8"]).replace(/^subject=/, "");
    assert.equal(d.subject.rfc2253, subj, `${cfg.label}: subject`);

    const text = q(["-text"]);
    if (d.publicKey.type === "RSA") {
      const bits = Number(/Public-Key: \((\d+) bit\)/.exec(text)[1]);
      assert.equal(d.publicKey.bits, bits, `${cfg.label}: RSA bits`);
    }
    const sigalg = /Signature Algorithm: (\S+)/.exec(text)[1];
    assert.equal(d.signature.name.toLowerCase(), sigalg.toLowerCase(), `${cfg.label}: sig alg`);

    // SANs: pull the line after "Subject Alternative Name:" out of -text
    if (cfg.addext && cfg.addext.some((e) => e.startsWith("subjectAltName"))) {
      const m = /Subject Alternative Name:[^\n]*\n\s*([^\n]+)/.exec(text);
      assert.ok(m, `${cfg.label}: openssl shows a SAN`);
      const expected = m[1].split(", ").map((s) => {
        let [t, ...rest] = s.split(":");
        if (t === "IP Address") t = "IP";
        return `${t.toLowerCase()}:${canonIp(rest.join(":").toLowerCase())}`;
      }).sort();
      const san = d.extensions.find((e) => e.oid === "2.5.29.17");
      const mine = san.names.map((n) => `${n.type.toLowerCase()}:${n.value.toLowerCase()}`).sort();
      assert.deepEqual(mine, expected, `${cfg.label}: SAN`);
    }

    // both sides agree the self-signature is good
    openssl(["req", "-verify", "-noout"], pem); // throws (non-zero exit) if bad
  }
});

test("self-signature verifies via WebCrypto for RSA, ECDSA, Ed25519, and SHA-1 RSA", async () => {
  for (let i = 0; i < CONFIGS.length; i++) {
    const { csrs } = decodeCsrPemInput(PEMS[i]);
    const v = await verifyCsrSignature(csrs[0].der, csrs[0].decoded);
    assert.equal(v.state, "valid", `${CONFIGS[i].label}: ${v.detail}`);
  }
});

test("tampered CSR: our verifier and openssl both reject it", async () => {
  // flip one bit inside the subject CN ("test.example") of the RSA CSR
  const { csrs } = decodeCsrPemInput(PEMS[0]);
  const der = Uint8Array.from(csrs[0].der);
  const target = [...("test.example")].map((c) => c.charCodeAt(0));
  let pos = -1;
  outer: for (let i = 0; i < der.length - target.length; i++) {
    for (let j = 0; j < target.length; j++) {
      if (der[i + j] !== target[j]) continue outer;
    }
    pos = i; break;
  }
  assert.ok(pos > 0, "found the CN bytes in the DER");
  der[pos] ^= 0x01; // test.example → uest.example, structure intact

  const decoded = decodeCsr(der);
  assert.ok(decoded.subject.rfc2253.includes("uest.example"));
  const v = await verifyCsrSignature(der, decoded);
  assert.equal(v.state, "invalid", v.detail);

  const b64 = Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n");
  const pem = `-----BEGIN CERTIFICATE REQUEST-----\n${b64}\n-----END CERTIFICATE REQUEST-----\n`;
  // OpenSSL 3.0's `req -verify` reports failure on stderr but still exits 0,
  // so check the message rather than the exit status.
  const res = spawnSync("openssl", ["req", "-verify", "-noout"], { input: pem, encoding: "utf8" });
  assert.ok(res.status !== 0 || /verify failure|verification fail/i.test(res.stderr + res.stdout),
    `openssl agrees the tampered CSR fails verification (got: ${(res.stderr + res.stdout).trim()})`);
});

test("ecdsaDerToRaw: strips sign pads and left-pads short integers", () => {
  // SEQUENCE { INTEGER 0x00C0…(33 bytes, sign-padded), INTEGER 0x01 (1 byte) }
  const r = [0x00, 0xc0, ...Array(31).fill(0xaa)];
  const sig = new Uint8Array([0x30, 4 + r.length + 1, 0x02, r.length, ...r, 0x02, 0x01, 0x07]);
  const raw = ecdsaDerToRaw(sig, 32);
  assert.equal(raw.length, 64);
  assert.equal(raw[0], 0xc0);           // pad stripped
  assert.equal(raw[31], 0xaa);
  assert.deepEqual([...raw.slice(32, 63)], Array(31).fill(0)); // s left-padded
  assert.equal(raw[63], 0x07);
  assert.throws(() => ecdsaDerToRaw(sig, 16), /wider than the curve/);
  assert.throws(() => ecdsaDerToRaw(new Uint8Array([0x02, 0x01, 0x01]), 32), /SEQUENCE/);
});

// ---- requested extensions and attributes -------------------------------

test("requested extensions decode: keyUsage, EKU, CA:TRUE warning, SAN", () => {
  const d = decodeCsrPemInput(PEMS[3]).csrs[0].decoded; // the CA request
  const ku = d.extensions.find((e) => e.oid === "2.5.29.15");
  assert.equal(ku.critical, true);
  assert.deepEqual(ku.usages.sort(), ["cRLSign", "keyCertSign"]);
  const eku = d.extensions.find((e) => e.oid === "2.5.29.37");
  assert.deepEqual(eku.purposes.map((p) => p.name),
    ["TLS server authentication", "TLS client authentication"]);
  const bc = d.extensions.find((e) => e.oid === "2.5.29.19");
  assert.equal(bc.ca, true);
  assert.equal(bc.pathLen, 0);
  assert.ok(d.warnings.some((w) => /CA:TRUE/.test(w)), "CA:TRUE warning");
  assert.ok(!d.warnings.some((w) => /subjectAltName/.test(w)), "has a SAN, no warning");
  assert.ok(d.attributes.some((a) => a.name === "extensionRequest"));
});

test("challengePassword and unstructuredName attributes decode, with warning", () => {
  const cfg = join(dir, "attr.cnf");
  writeFileSync(cfg, `[req]
distinguished_name = dn
attributes = attrs
prompt = no
[dn]
CN = pw.example
[attrs]
challengePassword = hunter2
unstructuredName = a note about this request
`);
  execFileSync("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-keyout", join(dir, "kattr.pem"), "-config", cfg, "-out", join(dir, "rattr.pem")],
    { stdio: ["ignore", "ignore", "ignore"] });
  const d = decodeCsrPemInput(readFileSync(join(dir, "rattr.pem"), "utf8")).csrs[0].decoded;
  const pw = d.attributes.find((a) => a.name === "challengePassword");
  assert.equal(pw.value, "hunter2");
  const un = d.attributes.find((a) => a.name === "unstructuredName");
  assert.equal(un.value, "a note about this request");
  assert.ok(d.warnings.some((w) => /challengePassword/.test(w)), "plaintext password warning");
});

test("plain openssl CSR without SAN gets the no-SAN warning; weak SHA-1 warned", () => {
  const noSan = decodeCsrPemInput(PEMS[1]).csrs[0].decoded;
  assert.ok(noSan.warnings.some((w) => /subjectAltName/.test(w)));
  assert.ok(noSan.notes.some((n) => /no extensionRequest|asks for no extensions/i.test(n)));
  const weak = decodeCsrPemInput(PEMS[5]).csrs[0].decoded;
  assert.ok(weak.warnings.some((w) => /SHA-1/.test(w)));
  // RFC 2253 escaping matches openssl (checked in the differential); comma survives
  assert.ok(weak.subject.rfc2253.includes("O=Comma\\, Inc"));
});

// ---- input handling ----------------------------------------------------

test("input handling: certs and keys refused with pointers, bare base64 accepted", () => {
  const key = readFileSync(join(dir, "k0.pem"), "utf8");
  const cert = openssl(["req", "-x509", "-key", join(dir, "k0.pem"), "-subj", "/CN=x", "-days", "1", "-nodes"]);
  const mixed = decodeCsrPemInput(PEMS[0] + key + cert);
  assert.equal(mixed.csrs.length, 1);
  assert.equal(mixed.skipped.length, 2);
  assert.ok(mixed.skipped.some((s) => /PRIVATE KEY/.test(s) && /compromised/.test(s)));
  assert.ok(mixed.skipped.some((s) => /certificate decoder/.test(s)));

  // bare base64 body decodes as a CSR
  const b64 = PEMS[0].replace(/-----[A-Z ]+-----/g, "");
  const bare = decodeCsrPemInput(b64);
  assert.equal(bare.csrs.length, 1);
  assert.equal(bare.csrs[0].decoded.subject.rfc2253, "C=US,O=Example Org,CN=test.example");

  // note the "!" — an all-base64-charset string would be taken as bare DER
  assert.throws(() => decodeCsrPemInput("this is not a CSR at all!"), /No PEM block/);
  // a certificate force-fed as bare DER fails with a clear message, not garbage
  const certDer = decodeCsrPemInput(cert.replace(/-----[A-Z ]+-----/g, "")).csrs[0];
  assert.ok(certDer.error, "certificate DER does not decode as a CSR");
});

test("truncated and non-CSR DER fail with clear errors", () => {
  const { csrs } = decodeCsrPemInput(PEMS[0]);
  const der = csrs[0].der;
  assert.throws(() => decodeCsr(der.subarray(0, 30)), /Truncated|Malformed|Not valid/);
  assert.throws(() => decodeCsr(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00])), /Malformed/);
  // trailing garbage is refused
  const padded = new Uint8Array([...der, 0x00]);
  assert.throws(() => decodeCsr(padded), /Trailing/);
});
