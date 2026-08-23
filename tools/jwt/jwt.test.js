import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  b64urlDecodeBytes, b64urlDecodeText, decodeJwt, describeClaims,
  relativeTime, tokenStatus, algNote, verifyHmacSignature,
} from "./jwt.js";

// Build tokens with node:crypto (independent of the module under test).
const b64url = (buf) => Buffer.from(buf).toString("base64url");
function makeToken(header, payload, secret) {
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  if (secret === undefined) return signingInput + ".";
  const hashBits = header.alg.slice(2); // HS256 -> 256
  const sig = createHmac(`sha${hashBits}`, secret).update(signingInput).digest();
  return `${signingInput}.${b64url(sig)}`;
}

const NOW = Date.UTC(2026, 7, 23, 12, 0, 0); // 2026-08-23T12:00:00Z, fixed for determinism

test("base64url decoding", () => {
  assert.equal(b64urlDecodeText("aGVsbG8"), "hello"); // unpadded
  assert.equal(b64urlDecodeText("aGVsbG8="), "hello"); // tolerated padding
  assert.deepEqual([...b64urlDecodeBytes("_w")], [0xff]); // '_' maps to '/'
  assert.deepEqual([...b64urlDecodeBytes("")], []);
  assert.throws(() => b64urlDecodeBytes("a+b"), /invalid base64url characters/);
  assert.throws(() => b64urlDecodeBytes("aaaaa"), /invalid base64url length/);
});

test("decodes a signed token, including unicode claims", () => {
  const token = makeToken(
    { alg: "HS256", typ: "JWT" },
    { sub: "user-1", name: "Zoë 日本 🚀", iat: 1516239022 },
    "secret",
  );
  const d = decodeJwt(token);
  assert.equal(d.header.alg, "HS256");
  assert.equal(d.payload.name, "Zoë 日本 🚀");
  assert.equal(d.isUnsecured, false);
  assert.equal(d.signatureBytes.length, 32); // HMAC-SHA256 is 32 bytes
});

test("accepts a Bearer prefix and surrounding whitespace", () => {
  const token = makeToken({ alg: "HS256", typ: "JWT" }, { sub: "x" }, "s");
  assert.equal(decodeJwt(`  Bearer ${token} `).payload.sub, "x");
});

test("unsecured (alg none) token decodes but is flagged", () => {
  const d = decodeJwt(makeToken({ alg: "none" }, { sub: "x" }));
  assert.equal(d.isUnsecured, true);
  assert.equal(d.signatureBytes.length, 0);
});

test("malformed tokens are rejected with specific errors", () => {
  assert.throws(() => decodeJwt("onlyonepart"), /expected 3 dot-separated sections.*got 1/);
  assert.throws(() => decodeJwt("a.b.c.d"), /got 4/);
  assert.throws(() => decodeJwt("   "), /empty token/);
  assert.throws(() => decodeJwt(`${b64url("not json")}.${b64url("{}")}.`), /header is not valid JSON/);
  assert.throws(() => decodeJwt(`${b64url('"str"')}.${b64url("{}")}.`), /header must be a JSON object/);
  assert.throws(() => decodeJwt(`${b64url("{}")}.${b64url("[1]")}.`), /payload must be a JSON object/);
  assert.throws(() => decodeJwt(`${b64url("{}")}.${b64url("{}")}.+bad+`), /signature: invalid base64url/);
  // header that is not valid UTF-8
  assert.throws(() => decodeJwt(`_w.${b64url("{}")}.`), /header:/);
});

test("relativeTime pinned strings", () => {
  assert.equal(relativeTime(30), "in 30 seconds");
  assert.equal(relativeTime(90), "in 1 minute");
  assert.equal(relativeTime(-7200), "2 hours ago");
  assert.equal(relativeTime(86400 * 3), "in 3 days");
  assert.equal(relativeTime(-86400 * 400), "1 year ago");
});

test("tokenStatus: expired / not-yet-valid / valid / no-expiry", () => {
  const now = NOW / 1000;
  assert.equal(tokenStatus({ exp: now - 3600 }, NOW).state, "expired");
  assert.equal(tokenStatus({ exp: now - 3600 }, NOW).detail, "expired 1 hour ago");
  assert.equal(tokenStatus({ nbf: now + 600, exp: now + 7200 }, NOW).state, "not-yet-valid");
  assert.equal(tokenStatus({ exp: now + 7200 }, NOW).state, "valid");
  assert.equal(tokenStatus({ exp: now + 7200 }, NOW).detail, "expires in 2 hours");
  assert.equal(tokenStatus({ sub: "x" }, NOW).state, "no-expiry");
  // expired wins over nbf-in-future
  assert.equal(tokenStatus({ exp: now - 10, nbf: now + 10 }, NOW).state, "expired");
});

test("describeClaims: order, time formatting, notes", () => {
  const rows = describeClaims(
    { iss: "https://issuer.example", exp: 1787788800, aud: ["a", "b"], custom: 5, iat: "oops" },
    NOW,
  );
  assert.deepEqual(rows.map((r) => r.name), ["iss", "exp", "aud", "custom", "iat"]);
  // 1787788800 = 2026-08-27T00:00:00Z, 3.5 days after NOW
  assert.equal(rows[1].display, "1787788800 — 2026-08-27T00:00:00Z (in 3 days)");
  assert.match(rows[1].note, /Expiration/);
  assert.equal(rows[2].display, '["a","b"]');
  assert.equal(rows[3].note, "");
  assert.match(rows[4].display, /should be a number/);
});

test("algNote classifies algorithms", () => {
  assert.match(algNote("none"), /UNSECURED/);
  assert.match(algNote("HS256"), /symmetric/);
  assert.match(algNote("RS256"), /public key/);
  assert.match(algNote("ES256"), /public key/);
  assert.match(algNote("EdDSA"), /public key/);
  assert.match(algNote("XX999"), /unrecognized/);
});

test("verifyHmacSignature: HS256/384/512 accept correct secret, reject wrong", async () => {
  for (const alg of ["HS256", "HS384", "HS512"]) {
    const token = makeToken({ alg, typ: "JWT" }, { sub: "u", exp: 9999999999 }, "hunter2");
    assert.equal(await verifyHmacSignature(token, "hunter2"), true, alg);
    assert.equal(await verifyHmacSignature(token, "wrong"), false, alg);
  }
});

test("decoding is lenient about non-canonical trailing bits (documented behavior)", async () => {
  // The last base64url char of an HS256 signature carries 4 used bits + 2
  // discarded bits. Flipping only a discarded bit yields the same bytes, so
  // the token still verifies — byte-equality, same as real validators.
  const token = makeToken({ alg: "HS256" }, { sub: "u" }, "s");
  const last = token.slice(-1);
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const flipped = ALPHABET[ALPHABET.indexOf(last) ^ 1]; // differs only in the lowest (discarded) bit
  const nonCanonical = token.slice(0, -1) + flipped;
  assert.deepEqual(
    decodeJwt(nonCanonical).signatureBytes,
    decodeJwt(token).signatureBytes,
  );
  assert.equal(await verifyHmacSignature(nonCanonical, "s"), true);
});

test("verifyHmacSignature rejects tampered payload", async () => {
  const token = makeToken({ alg: "HS256" }, { sub: "u", admin: false }, "s3cret");
  const [h, , s] = token.split(".");
  const tampered = `${h}.${b64url(JSON.stringify({ sub: "u", admin: true }))}.${s}`;
  assert.equal(await verifyHmacSignature(tampered, "s3cret"), false);
});

test("verifyHmacSignature refuses non-HMAC algorithms", async () => {
  const rs = makeToken({ alg: "RS256" }, { sub: "u" });
  await assert.rejects(() => verifyHmacSignature(rs, "s"), /not an HMAC algorithm/);
  const none = makeToken({ alg: "none" }, { sub: "u" });
  await assert.rejects(() => verifyHmacSignature(none, "s"), /not an HMAC algorithm/);
});
