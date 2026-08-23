// jwt.js — decode and inspect JSON Web Tokens, entirely client-side.
// Pure ES module: no DOM access, no globals beyond atob/TextDecoder/crypto,
// all time-dependent functions take `now` explicitly so they are testable.

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export function b64urlDecodeBytes(str) {
  if (typeof str !== "string") throw new Error("expected a string");
  const s = str.replace(/=+$/, ""); // tolerate padding, which RFC 7515 omits
  if (!B64URL_RE.test(s)) throw new Error("invalid base64url characters");
  if (s.length % 4 === 1) throw new Error("invalid base64url length");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function b64urlDecodeText(str) {
  return new TextDecoder("utf-8", { fatal: true }).decode(b64urlDecodeBytes(str));
}

function parseJsonPart(raw, partName) {
  let text;
  try {
    text = b64urlDecodeText(raw);
  } catch (e) {
    throw new Error(`${partName}: ${e.message}`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${partName} is not valid JSON`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${partName} must be a JSON object`);
  }
  return value;
}

// Decode a compact-serialization JWT. Accepts an optional "Bearer " prefix.
// Does NOT verify the signature — decoding and verifying are different things.
export function decodeJwt(token) {
  if (typeof token !== "string") throw new Error("expected a string");
  let t = token.trim().replace(/^Bearer\s+/i, "");
  if (t === "") throw new Error("empty token");
  const parts = t.split(".");
  if (parts.length !== 3) {
    throw new Error(`expected 3 dot-separated sections (header.payload.signature), got ${parts.length}`);
  }
  const header = parseJsonPart(parts[0], "header");
  const payload = parseJsonPart(parts[1], "payload");
  const signatureBytes = (() => {
    try {
      return b64urlDecodeBytes(parts[2]);
    } catch (e) {
      throw new Error(`signature: ${e.message}`);
    }
  })();
  return {
    header,
    payload,
    parts,
    signingInput: parts[0] + "." + parts[1],
    signatureBytes,
    isUnsecured: header.alg === "none",
  };
}

// Registered claim names from RFC 7519 §4.1, plus a few common ones.
export const CLAIM_NOTES = {
  iss: "Issuer — who created and signed the token",
  sub: "Subject — whom the token is about",
  aud: "Audience — intended recipient(s); others must reject it",
  exp: "Expiration time — token must be rejected after this",
  nbf: "Not before — token is invalid until this",
  iat: "Issued at",
  jti: "JWT ID — unique identifier, e.g. to prevent replay",
  scope: "Space-separated OAuth scopes granted",
  azp: "Authorized party — the client the token was issued to",
  nonce: "Value to bind the token to a client session",
};

const TIME_CLAIMS = new Set(["exp", "nbf", "iat", "auth_time"]);

export function relativeTime(deltaSec) {
  const abs = Math.abs(deltaSec);
  let n, unit;
  if (abs < 60) [n, unit] = [Math.floor(abs), "second"];
  else if (abs < 3600) [n, unit] = [Math.floor(abs / 60), "minute"];
  else if (abs < 86400) [n, unit] = [Math.floor(abs / 3600), "hour"];
  else if (abs < 86400 * 365) [n, unit] = [Math.floor(abs / 86400), "day"];
  else [n, unit] = [Math.floor(abs / (86400 * 365)), "year"];
  const s = `${n} ${unit}${n === 1 ? "" : "s"}`;
  return deltaSec >= 0 ? `in ${s}` : `${s} ago`;
}

export function formatEpochSeconds(sec, nowMs) {
  const iso = new Date(sec * 1000).toISOString().replace(".000Z", "Z");
  return `${sec} — ${iso} (${relativeTime(sec - nowMs / 1000)})`;
}

// One display row per payload claim, in payload order.
export function describeClaims(payload, nowMs) {
  return Object.entries(payload).map(([name, value]) => {
    let display;
    if (TIME_CLAIMS.has(name)) {
      display = typeof value === "number" && Number.isFinite(value)
        ? formatEpochSeconds(value, nowMs)
        : `${JSON.stringify(value)} (should be a number: seconds since epoch)`;
    } else {
      display = typeof value === "string" ? value : JSON.stringify(value);
    }
    return { name, display, note: CLAIM_NOTES[name] ?? "" };
  });
}

// Validity window from exp/nbf. Deterministic given nowMs.
export function tokenStatus(payload, nowMs) {
  const now = nowMs / 1000;
  const { exp, nbf } = payload;
  if (typeof exp === "number" && now >= exp) {
    return { state: "expired", detail: `expired ${relativeTime(exp - now)}` };
  }
  if (typeof nbf === "number" && now < nbf) {
    return { state: "not-yet-valid", detail: `becomes valid ${relativeTime(nbf - now)}` };
  }
  if (typeof exp === "number") {
    return { state: "valid", detail: `expires ${relativeTime(exp - now)}` };
  }
  return { state: "no-expiry", detail: "no exp claim — the token never expires" };
}

export const HMAC_ALGS = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };

export function algNote(alg) {
  if (alg === undefined) return "no alg in header";
  if (alg === "none") return "UNSECURED — no signature; must not be trusted";
  if (alg in HMAC_ALGS) return "HMAC (symmetric) — same secret signs and verifies";
  if (/^(RS|PS)(256|384|512)$/.test(alg)) return "RSA (asymmetric) — verified with the issuer's public key";
  if (/^ES(256|384|512|256K)$/.test(alg)) return "ECDSA (asymmetric) — verified with the issuer's public key";
  if (alg === "EdDSA") return "EdDSA (asymmetric) — verified with the issuer's public key";
  return "unrecognized algorithm";
}

// Verify an HS256/384/512 signature with WebCrypto. Returns a Promise<boolean>.
export async function verifyHmacSignature(token, secret) {
  const { header, signingInput, signatureBytes } = decodeJwt(token);
  const hash = HMAC_ALGS[header.alg];
  if (!hash) throw new Error(`${header.alg ?? "(missing alg)"} is not an HMAC algorithm`);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash }, false, ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, signatureBytes, enc.encode(signingInput));
}
