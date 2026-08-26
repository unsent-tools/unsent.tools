// Tests for sshkey.js. The differential oracle is ssh-keygen itself:
// keys and certificates are generated fresh with it at test time, and our
// type / bits / SHA256 / MD5 fingerprints, certificate fields, and the
// full randomart drawing must agree with `ssh-keygen -lf`, `-E md5 -lf`,
// `-lv` and `-Lf` output, byte for byte where the format allows.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  parseAll, parseLine, decodeBlob, splitOptions, randomart, fingerprints,
  formatValidity, SshKeyError,
} from "./sshkey.js";

let dir;
const keygen = (...args) => execFileSync("ssh-keygen", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const pub = (name) => readFileSync(join(dir, name + ".pub"), "utf8");

const KEYS = [
  ["ed25519", ["-t", "ed25519"]],
  ["rsa3072", ["-t", "rsa"]],
  ["rsa2048", ["-t", "rsa", "-b", "2048"]],
  ["rsa1024", ["-t", "rsa", "-b", "1024"]],
  ["ecdsa256", ["-t", "ecdsa", "-b", "256"]],
  ["ecdsa384", ["-t", "ecdsa", "-b", "384"]],
  ["ecdsa521", ["-t", "ecdsa", "-b", "521"]],
  ["dsa", ["-t", "dsa"]],
];

before(() => {
  dir = mkdtempSync(join(tmpdir(), "sshkey-test-"));
  for (const [name, args] of KEYS) {
    keygen("-q", ...args, "-N", "", "-C", `unit ${name}`, "-f", join(dir, name));
  }
  // A CA and certificates signed with it.
  keygen("-q", "-t", "ed25519", "-N", "", "-C", "the CA", "-f", join(dir, "ca"));
  keygen("-q", "-s", join(dir, "ca"), "-I", "alice@example", "-n", "alice,admin",
    "-z", "42", "-V", "+52w", join(dir, "ed25519.pub"));
  keygen("-q", "-s", join(dir, "ca"), "-I", "host.example.org", "-h",
    "-n", "host.example.org,10.7.7.7", join(dir, "rsa3072.pub"));
  keygen("-q", "-s", join(dir, "ca"), "-I", "stale", "-V", "-104w:-52w", join(dir, "rsa2048.pub"));
});

after(() => rmSync(dir, { recursive: true, force: true }));

// -------------------------------------------------- plain-key differential

test("type, bits and both fingerprints match ssh-keygen for every key type", async () => {
  for (const [name] of KEYS) {
    const text = pub(name);
    const { entries } = await parseAll(text);
    assert.equal(entries.length, 1, name);
    const e = entries[0];
    assert.ok(e.ok, `${name}: ${e.error}`);

    const [bits, sha256, ...restA] = keygen("-lf", join(dir, name + ".pub")).trim().split(/\s+/);
    const typeA = restA.pop();
    assert.equal(String(e.key.bits), bits, `${name}: bits`);
    assert.equal(e.fingerprints.sha256, sha256, `${name}: sha256`);
    assert.equal(`(${e.key.alg})`, typeA, `${name}: algorithm label`);
    assert.equal(e.parsed.comment, restA.join(" "), `${name}: comment`);

    const md5Field = keygen("-E", "md5", "-lf", join(dir, name + ".pub")).trim().split(/\s+/)[1];
    assert.equal(e.fingerprints.md5, md5Field, `${name}: md5`);
  }
});

test("randomart matches ssh-keygen -lv byte for byte, all key types and certs", async () => {
  for (const file of [...KEYS.map(([n]) => n), "ed25519-cert", "rsa3072-cert", "rsa2048-cert"]) {
    const out = keygen("-lv", "-f", join(dir, file + ".pub"));
    const lines = out.split("\n");
    const art = lines.slice(lines.findIndex((l) => l.startsWith("+"))).join("\n").trimEnd();
    const { entries } = await parseAll(pub(file));
    assert.ok(entries[0].ok, `${file}: ${entries[0].error}`);
    assert.equal(entries[0].randomart, art, file);
  }
});

// ------------------------------------------------ certificate differential

test("user certificate fields match ssh-keygen -L", async () => {
  const { entries } = await parseAll(pub("ed25519-cert"));
  const e = entries[0];
  assert.ok(e.ok, e.error);
  const cert = e.key.cert;
  const listing = keygen("-Lf", join(dir, "ed25519-cert.pub"));

  assert.ok(listing.includes("Type: ssh-ed25519-cert-v01@openssh.com user certificate"));
  assert.equal(e.key.type, "ssh-ed25519-cert-v01@openssh.com");
  assert.equal(cert.certType, "user");
  assert.equal(cert.serial, 42n);
  assert.equal(cert.keyId, "alice@example");
  assert.deepEqual(cert.principals, ["alice", "admin"]);
  assert.deepEqual(cert.extensions.map((x) => x.name), [
    "permit-X11-forwarding", "permit-agent-forwarding",
    "permit-port-forwarding", "permit-pty", "permit-user-rc",
  ]);
  assert.deepEqual(cert.criticalOptions, []);

  // The certificate's own fingerprint is the certified key's fingerprint.
  assert.ok(listing.includes(`Public key: ED25519-CERT ${e.fingerprints.sha256}`), "public key fp");
  assert.ok(listing.includes(`Signing CA: ED25519 ${e.caFingerprint} `), "CA fp");
  assert.ok(listing.includes(`Valid: ${formatValidity(cert)}`), `validity: ${formatValidity(cert)} not in ${listing}`);
});

test("host certificate and forever validity", async () => {
  const { entries } = await parseAll(pub("rsa3072-cert"));
  const e = entries[0];
  assert.ok(e.ok, e.error);
  assert.equal(e.key.cert.certType, "host");
  assert.equal(e.key.alg, "RSA");
  assert.equal(e.key.bits, 3072);
  assert.deepEqual(e.key.cert.principals, ["host.example.org", "10.7.7.7"]);
  // Signed without -V: valid forever, which earns a warning too.
  assert.equal(formatValidity(e.key.cert), "forever");
  assert.ok(keygen("-Lf", join(dir, "rsa3072-cert.pub")).includes("Valid: forever"));
  assert.ok(e.warnings.some((w) => w.includes("never expires")));
  // Host certificates get no default extensions.
  assert.deepEqual(e.key.cert.extensions, []);
});

test("expired certificate is flagged", async () => {
  const { entries } = await parseAll(pub("rsa2048-cert"));
  assert.ok(entries[0].warnings.some((w) => w.includes("expired")));
});

// --------------------------------------------------- other input formats

test("RFC 4716 export round-trips to the same fingerprint", async () => {
  const exported = keygen("-e", "-f", join(dir, "rsa3072.pub"));
  assert.ok(exported.startsWith("---- BEGIN SSH2 PUBLIC KEY ----"));
  const { entries } = await parseAll(exported);
  assert.equal(entries.length, 1);
  const e = entries[0];
  assert.ok(e.ok, e.error);
  assert.equal(e.source, "rfc4716");
  const { entries: plain } = await parseAll(pub("rsa3072"));
  assert.equal(e.fingerprints.sha256, plain[0].fingerprints.sha256);
  // ssh-keygen -e rewrites the comment ("3072-bit RSA, converted by ...");
  // what matters is that the quoted Comment: header is read at all.
  assert.match(e.parsed.comment, /^3072-bit RSA, converted by /);
});

test("known_hosts lines: plain, hashed, and markers", async () => {
  const keyLine = pub("ed25519").trim();
  const [type, b64] = keyLine.split(/\s+/);
  const khPath = join(dir, "known_hosts");
  writeFileSync(khPath, `example.org,10.0.0.1 ${type} ${b64}\n`);
  keygen("-H", "-f", khPath); // hash it in place

  const plain = await parseAll(`example.org,10.0.0.1 ${type} ${b64}`);
  assert.equal(plain.entries[0].source, "known_hosts");
  assert.equal(plain.entries[0].parsed.hosts, "example.org,10.0.0.1");
  assert.equal(plain.entries[0].hashedHosts ?? plain.entries[0].parsed.hashedHosts, false);

  const hashed = await parseAll(readFileSync(khPath, "utf8"));
  const hs = hashed.entries.filter((e) => e.ok);
  assert.ok(hs.length >= 1);
  for (const e of hs) {
    assert.equal(e.parsed.hashedHosts, true);
    assert.equal(e.fingerprints.sha256, plain.entries[0].fingerprints.sha256);
  }

  const marked = await parseAll(`@cert-authority *.example.org ${type} ${b64}`);
  assert.equal(marked.entries[0].parsed.marker, "@cert-authority");
  assert.equal(marked.entries[0].parsed.hosts, "*.example.org");
});

test("authorized_keys options: quoting, commas, spaces", async () => {
  const keyLine = pub("ed25519").trim();
  const [type, b64] = keyLine.split(/\s+/);
  const line = `command="echo \\"a,b\\" && true",no-pty,from="*.example.org,10.*",environment="FOO=a b" ${type} ${b64} deploy key`;
  // ssh-keygen itself must accept the line (it is legal authorized_keys syntax).
  const akPath = join(dir, "authorized_keys");
  writeFileSync(akPath, line + "\n");
  const oracle = keygen("-lf", akPath).trim();
  assert.ok(oracle.startsWith("256 "), oracle);

  const { entries } = await parseAll(line);
  const e = entries[0];
  assert.ok(e.ok, e.error);
  assert.equal(e.source, "authorized_keys");
  assert.deepEqual(e.parsed.options, [
    'command="echo \\"a,b\\" && true"',
    "no-pty",
    'from="*.example.org,10.*"',
    'environment="FOO=a b"',
  ]);
  assert.equal(e.parsed.comment, "deploy key");
  assert.equal(e.fingerprints.sha256, oracle.split(/\s+/)[1]);
});

test("splitOptions edge cases", () => {
  assert.deepEqual(splitOptions("a,b,c"), ["a", "b", "c"]);
  assert.deepEqual(splitOptions('x="1,2",y'), ['x="1,2"', "y"]);
  assert.throws(() => splitOptions('x="unterminated'), SshKeyError);
});

test("hand-built security-key (sk-) blob decodes", async () => {
  // No FIDO token on a CI box: build the wire format by hand.
  const enc = new TextEncoder();
  const parts = [];
  const pushStr = (bytes) => {
    const b = new Uint8Array(4 + bytes.length);
    new DataView(b.buffer).setUint32(0, bytes.length);
    b.set(bytes, 4);
    parts.push(b);
  };
  pushStr(enc.encode("sk-ssh-ed25519@openssh.com"));
  pushStr(new Uint8Array(32).fill(7));
  pushStr(enc.encode("ssh:"));
  const blob = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { blob.set(p, off); off += p.length; }
  const key = decodeBlob(blob);
  assert.equal(key.alg, "ED25519-SK");
  assert.equal(key.bits, 256);
  assert.equal(key.application, "ssh:");
});

// ------------------------------------------------------------- refusals

test("private keys are refused with a loud warning, never parsed", async () => {
  const priv = readFileSync(join(dir, "ed25519"), "utf8");
  await assert.rejects(parseAll(priv), (e) => {
    assert.ok(e instanceof SshKeyError);
    assert.match(e.message, /PRIVATE/);
    assert.match(e.message, /compromised/);
    return true;
  });
  // PEM-style too (old format markers).
  await assert.rejects(parseAll("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."), /PRIVATE/);
  await assert.rejects(parseAll("PuTTY-User-Key-File-3: ssh-ed25519"), /PRIVATE/);
});

test("malformed input becomes per-line errors, not crashes", async () => {
  const good = pub("ed25519").trim();
  const [type, b64] = good.split(/\s+/);
  const cases = [
    `${type} not!!!base64`,
    `${type} ${b64.slice(0, 20)}`, // truncated blob
    `ssh-rsa ${b64}`, // declared type does not match the blob
    "何 something",
  ];
  for (const c of cases) {
    const { entries } = await parseAll(c);
    assert.equal(entries.length, 1, c);
    assert.equal(entries[0].ok, false, c);
    assert.ok(entries[0].error.length > 0, c);
  }
  // A mixed file keeps going and keeps order.
  const mixed = `# heading comment\n\n${good}\nbroken line here\n${good}\n`;
  const { entries, skipped } = await parseAll(mixed);
  assert.equal(entries.length, 3);
  assert.equal(entries[0].ok, true);
  assert.equal(entries[1].ok, false);
  assert.equal(entries[2].ok, true);
  assert.equal(skipped, 1);
});

test("warnings: DSA and small RSA flagged, healthy keys clean", async () => {
  const dsa = (await parseAll(pub("dsa"))).entries[0];
  assert.ok(dsa.warnings.some((w) => w.includes("OpenSSH 7.0")));
  const small = (await parseAll(pub("rsa1024"))).entries[0];
  assert.ok(small.warnings.some((w) => w.includes("too small")));
  const ok = (await parseAll(pub("ed25519"))).entries[0];
  assert.deepEqual(ok.warnings, []);
  const rsa = (await parseAll(pub("rsa3072"))).entries[0];
  assert.deepEqual(rsa.warnings, []);
});
