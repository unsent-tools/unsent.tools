// sshkey.js — SSH public key decoder. Accepts OpenSSH public key lines,
// authorized_keys lines (with options), known_hosts lines (plain or
// hashed), RFC 4716 blocks, and OpenSSH certificates; decodes the wire
// format, computes ssh-keygen-compatible fingerprints (SHA256 base64 and
// MD5 colon-hex) and the "randomart" drunken-bishop picture. Pure
// functions, no DOM. Private keys are refused loudly, never parsed.

import { md5, bytesToBase64, bytesToHex } from "../hash/hash.js";

export class SshKeyError extends Error {}
const fail = (msg) => { throw new SshKeyError(msg); };

// ------------------------------------------------------------ wire reader

function reader(bytes) {
  let off = 0;
  const need = (n, what) => {
    if (off + n > bytes.length) fail(`Truncated key data (while reading ${what}).`);
  };
  return {
    string(what) {
      need(4, `${what} length`);
      const len = (bytes[off] << 24 | bytes[off + 1] << 16 | bytes[off + 2] << 8 | bytes[off + 3]) >>> 0;
      off += 4;
      need(len, what);
      const out = bytes.subarray(off, off + len);
      off += len;
      return out;
    },
    text(what) { return new TextDecoder().decode(this.string(what)); },
    uint32(what) {
      need(4, what);
      const v = (bytes[off] << 24 | bytes[off + 1] << 16 | bytes[off + 2] << 8 | bytes[off + 3]) >>> 0;
      off += 4;
      return v;
    },
    uint64(what) {
      const hi = this.uint32(what), lo = this.uint32(what);
      return BigInt(hi) * 4294967296n + BigInt(lo);
    },
    atEnd() { return off === bytes.length; },
    remaining() { return bytes.length - off; },
    offset() { return off; },
  };
}

function wireString(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

// Bit length of an ssh mpint (big-endian, possibly zero-padded).
function mpintBits(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  if (i === bytes.length) return 0;
  return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}

function mpintToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

// ------------------------------------------------------------ key types

const CURVE_BITS = { nistp256: 256, nistp384: 384, nistp521: 521 };

// Reads the type-specific public key fields. `type` is the inner algorithm
// name (certificates repeat their base type here).
function readKeyFields(r, type) {
  switch (type) {
    case "ssh-rsa": {
      const e = r.string("RSA exponent"), n = r.string("RSA modulus");
      return { alg: "RSA", bits: mpintBits(n), exponent: mpintToBigInt(e) };
    }
    case "ssh-dss": {
      const p = r.string("DSA p");
      r.string("DSA q"); r.string("DSA g"); r.string("DSA y");
      return { alg: "DSA", bits: mpintBits(p) };
    }
    case "ssh-ed25519": {
      const pk = r.string("Ed25519 public key");
      if (pk.length !== 32) fail(`Ed25519 public key must be 32 bytes, got ${pk.length}.`);
      return { alg: "ED25519", bits: 256 };
    }
    case "ecdsa-sha2-nistp256":
    case "ecdsa-sha2-nistp384":
    case "ecdsa-sha2-nistp521": {
      const curve = r.text("ECDSA curve name");
      if ("ecdsa-sha2-" + curve !== type) fail(`ECDSA curve "${curve}" does not match the key type ${type}.`);
      const point = r.string("ECDSA public point");
      if (point[0] !== 4) fail("ECDSA public point is not in uncompressed form.");
      return { alg: "ECDSA", bits: CURVE_BITS[curve], curve };
    }
    case "sk-ssh-ed25519@openssh.com": {
      const pk = r.string("Ed25519 public key");
      if (pk.length !== 32) fail(`Ed25519 public key must be 32 bytes, got ${pk.length}.`);
      return { alg: "ED25519-SK", bits: 256, application: r.text("application") };
    }
    case "sk-ecdsa-sha2-nistp256@openssh.com": {
      const curve = r.text("ECDSA curve name");
      const point = r.string("ECDSA public point");
      if (point[0] !== 4) fail("ECDSA public point is not in uncompressed form.");
      return { alg: "ECDSA-SK", bits: CURVE_BITS[curve], curve, application: r.text("application") };
    }
    default:
      fail(`Unsupported key type "${type}".`);
  }
}

const CERT_SUFFIX = "-cert-v01@openssh.com";

// Nested list of strings (certificate principals).
function readStringList(blob) {
  const r = reader(blob), out = [];
  while (!r.atEnd()) out.push(r.text("list item"));
  return out;
}

// Nested name/value pairs (critical options, extensions). Values are
// themselves wrapped strings; empty for flag-style extensions.
function readPairs(blob) {
  const r = reader(blob), out = [];
  while (!r.atEnd()) {
    const name = r.text("option name");
    const data = r.string("option value");
    let value = "";
    if (data.length) {
      const inner = reader(data);
      value = inner.text("option data");
    }
    out.push({ name, value });
  }
  return out;
}

const CERT_TYPE = { 1: "user", 2: "host" };

// Decode one binary key blob (the base64 payload of a public key line).
export function decodeBlob(blob) {
  const r = reader(blob);
  const type = r.text("key type");
  const isCert = type.endsWith(CERT_SUFFIX);
  let cert = null;
  if (isCert) r.string("nonce");
  // Certificates repeat the base algorithm's fields; security-key types
  // put the -cert marker before their own @openssh.com suffix.
  let inner = type;
  if (isCert) {
    inner = type.slice(0, -CERT_SUFFIX.length);
    if (!KEY_TYPES.has(inner) && KEY_TYPES.has(inner + "@openssh.com")) inner += "@openssh.com";
  }
  const fieldsStart = r.offset();
  const fields = readKeyFields(r, inner);
  const fieldsEnd = r.offset();
  // ssh-keygen fingerprints a certificate by its certified public key, not
  // the whole certificate blob — reconstruct that plain key blob.
  let publicBlob = blob;
  if (isCert) {
    const name = wireString(new TextEncoder().encode(inner));
    const raw = blob.subarray(fieldsStart, fieldsEnd);
    publicBlob = new Uint8Array(name.length + raw.length);
    publicBlob.set(name);
    publicBlob.set(raw, name.length);
  }
  if (isCert) {
    const serial = r.uint64("serial");
    const certType = r.uint32("certificate type");
    const keyId = r.text("key id");
    const principals = readStringList(r.string("valid principals"));
    const validAfter = r.uint64("valid after");
    const validBefore = r.uint64("valid before");
    const criticalOptions = readPairs(r.string("critical options"));
    const extensions = readPairs(r.string("extensions"));
    r.string("reserved");
    const signatureKey = r.string("signature key");
    r.string("signature");
    let caKey = null;
    try { caKey = decodeBlob(signatureKey); } catch { /* leave null */ }
    cert = {
      serial, keyId, principals,
      certType: CERT_TYPE[certType] ?? `unknown (${certType})`,
      validAfter, validBefore,
      criticalOptions, extensions,
      caKey, caBlob: signatureKey.slice(),
    };
  }
  if (!r.atEnd()) fail(`${r.remaining()} unexpected trailing bytes after the key.`);
  return { type, ...fields, cert, blob, publicBlob };
}

// ------------------------------------------------------------ fingerprints

// ssh-keygen's two fingerprint formats: SHA256, base64 without padding,
// and legacy MD5 as colon-separated hex pairs.
export async function fingerprints(blob) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return {
    sha256: "SHA256:" + bytesToBase64(digest).replace(/=+$/, ""),
    sha256Bytes: digest,
    md5: "MD5:" + bytesToHex(md5(blob)).replace(/(..)(?=.)/g, "$1:"),
  };
}

// ------------------------------------------------------------ randomart

// The "drunken bishop" visualisation, byte-compatible with OpenSSH's
// sshkey_fingerprint_randomart(): 17×9 field, walk starts in the centre,
// each digest byte yields four 2-bit moves (bit 0: left/right, bit 1:
// up/down), visit counts map to " .o+=*BOX@%&#/^", S marks the start,
// E the end.
const ART_W = 17, ART_H = 9;
const ART_CHARS = " .o+=*BOX@%&#/^";

export function randomart(digest, keyLabel, hashLabel) {
  const field = Array.from({ length: ART_H }, () => new Uint8Array(ART_W));
  let x = (ART_W - 1) / 2, y = (ART_H - 1) / 2;
  const sx = x, sy = y;
  for (let byte of digest) {
    for (let i = 0; i < 4; i++) {
      x += byte & 1 ? 1 : -1;
      y += byte & 2 ? 1 : -1;
      x = Math.max(0, Math.min(ART_W - 1, x));
      y = Math.max(0, Math.min(ART_H - 1, y));
      if (field[y][x] < ART_CHARS.length - 1) field[y][x]++;
      byte >>= 2;
    }
  }
  const border = (label) => {
    let title = `[${label}]`;
    if (title.length > ART_W) title = `[${label.split(" ")[0]}]`;
    if (title.length > ART_W) title = title.slice(0, ART_W);
    const left = Math.floor((ART_W - title.length) / 2);
    return "+" + "-".repeat(left) + title + "-".repeat(ART_W - left - title.length) + "+";
  };
  const lines = [border(keyLabel)];
  for (let r = 0; r < ART_H; r++) {
    let line = "";
    for (let c = 0; c < ART_W; c++) {
      if (r === sy && c === sx) line += "S";
      else if (r === y && c === x) line += "E";
      else line += ART_CHARS[Math.min(field[r][c], ART_CHARS.length - 1)];
    }
    lines.push("|" + line + "|");
  }
  lines.push(border(hashLabel));
  return lines.join("\n");
}

// ------------------------------------------------------------ line formats

const KEY_TYPES = new Set([
  "ssh-rsa", "ssh-dss", "ssh-ed25519",
  "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
  "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
]);
const isKeyType = (tok) => KEY_TYPES.has(tok) || (tok.endsWith(CERT_SUFFIX) && KEY_TYPES.has(tok.slice(0, -CERT_SUFFIX.length)) || KEY_TYPES.has(tok.slice(0, -CERT_SUFFIX.length) + "@openssh.com"));

// Split an authorized_keys options field at unquoted commas, honouring
// backslash escapes inside double quotes (sshd's auth-options grammar).
export function splitOptions(s) {
  const out = [];
  let cur = "", inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQuote && ch === "\\" && i + 1 < s.length && s[i + 1] === '"') { cur += '\\"'; i++; continue; }
    if (ch === '"') { inQuote = !inQuote; cur += ch; continue; }
    if (ch === "," && !inQuote) { out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  if (inQuote) fail("Unbalanced quote in the options field.");
  if (cur) out.push(cur);
  return out;
}

// Scan one whitespace-separated token starting at i, respecting quotes
// (options may contain spaces inside quoted values).
function scanToken(line, i, quoted) {
  let j = i, inQuote = false;
  while (j < line.length) {
    const ch = line[j];
    if (quoted) {
      if (inQuote && ch === "\\" && j + 1 < line.length) { j += 2; continue; }
      if (ch === '"') inQuote = !inQuote;
    }
    if (!inQuote && (ch === " " || ch === "\t")) break;
    j++;
  }
  return [line.slice(i, j), j];
}

const b64decode = (s) => {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) fail("Key data is not valid base64.");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

// Parse one non-blank line into its parts. Tries, in order: a marker line
// (@cert-authority / @revoked from known_hosts), a plain public key line,
// a known_hosts line (hosts field first), an authorized_keys line
// (options field first).
export function parseLine(line) {
  const out = { marker: null, hosts: null, hashedHosts: false, options: null, type: null, b64: null, comment: "" };
  let i = 0;

  const skipWs = () => { while (i < line.length && (line[i] === " " || line[i] === "\t")) i++; };

  skipWs();
  if (line[i] === "@") {
    let tok;
    [tok, i] = scanToken(line, i, false);
    out.marker = tok;
    skipWs();
  }
  const afterMarker = i;

  let tok;
  [tok, i] = scanToken(line, i, false);
  if (!isKeyType(tok)) {
    // Not a key type: this token is a hosts field (known_hosts) or an
    // options field (authorized_keys). Decide by looking at the next token.
    skipWs();
    let next, afterNext;
    [next, afterNext] = scanToken(line, i, false);
    if (isKeyType(next)) {
      out.hosts = tok;
      out.hashedHosts = tok.startsWith("|1|");
      i = afterNext;
      tok = next;
    } else {
      // Re-scan the first token with quote support: options may contain
      // quoted spaces, so the plain scan may have split too early.
      i = afterMarker;
      [tok, i] = scanToken(line, i, true);
      out.options = splitOptions(tok);
      skipWs();
      [tok, i] = scanToken(line, i, false);
      if (!isKeyType(tok)) fail(`"${tok.slice(0, 40)}" is not a recognised key type.`);
    }
  }
  out.type = tok;
  skipWs();
  [out.b64, i] = scanToken(line, i, false);
  if (!out.b64) fail("Missing key data after the key type.");
  out.comment = line.slice(i).trim();
  return out;
}

// ------------------------------------------------------------ warnings

const EPOCH_FOREVER = 0xffffffffffffffffn;

function keyWarnings(key, parsed, now = Date.now()) {
  const w = [];
  if (key.alg === "DSA") {
    w.push("ssh-dss (DSA) has been disabled by default since OpenSSH 7.0 (2015); modern servers and clients refuse it.");
  }
  if (key.alg === "RSA" && key.bits < 2048) {
    w.push(`A ${key.bits}-bit RSA key is too small: 2048 bits is the accepted minimum, 3072+ recommended.`);
  }
  if (key.alg === "RSA" && key.exponent != null && key.exponent < 65537n) {
    w.push(`Unusual RSA public exponent ${key.exponent} (the standard choice is 65537). Small exponents with old padding schemes have a bad history.`);
  }
  if (key.cert) {
    const nowSec = BigInt(Math.floor(now / 1000));
    if (key.cert.validBefore !== EPOCH_FOREVER && nowSec > key.cert.validBefore) {
      w.push("This certificate has expired.");
    } else if (nowSec < key.cert.validAfter) {
      w.push("This certificate is not valid yet.");
    }
    if (key.cert.validBefore === EPOCH_FOREVER && key.cert.validAfter === 0n) {
      w.push("This certificate never expires — CA hygiene usually wants an expiry.");
    }
  }
  return w;
}

// ------------------------------------------------------------ top level

const PRIVATE_KEY_RE = /-----BEGIN\s+(OPENSSH|RSA|DSA|EC|ENCRYPTED)?\s*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File/i;

// RFC 4716 blocks: header lines (with continuations) then base64 body.
function* rfc4716Blocks(text) {
  const re = /---- BEGIN SSH2 PUBLIC KEY ----\r?\n([\s\S]*?)---- END SSH2 PUBLIC KEY ----/g;
  for (const m of text.matchAll(re)) {
    const lines = m[1].split(/\r?\n/);
    let comment = "", body = "", inHeaders = true;
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];
      if (!line.trim()) continue;
      if (inHeaders && /^[A-Za-z0-9-]+:/.test(line)) {
        let value = line.slice(line.indexOf(":") + 1).trim();
        while (value.endsWith("\\") && i + 1 < lines.length) {
          value = value.slice(0, -1) + lines[++i].trim();
        }
        if (/^comment:/i.test(line)) comment = value.replace(/^"|"$/g, "");
        continue;
      }
      inHeaders = false;
      body += line.trim();
    }
    yield { b64: body, comment };
  }
}

// parseAll(text) → { entries, skipped }. Each entry: { ok: true, source,
// key, fingerprints, randomart, warnings, parsed } or { ok: false, line,
// error }. Lines that are blank or #-comments are skipped (counted).
export async function parseAll(text) {
  if (PRIVATE_KEY_RE.test(text)) {
    fail("That is a PRIVATE key. Nothing was decoded or sent anywhere, but if this key has left your machine before, treat it as compromised: generate a new key pair and retire this one.");
  }
  const entries = [];
  let skipped = 0;

  const addKey = async (parsed, source, raw) => {
    const blob = b64decode(parsed.b64);
    const key = decodeBlob(blob);
    if (parsed.type != null && key.type !== parsed.type) {
      fail(`The key type inside the data (${key.type}) does not match the declared type (${parsed.type}).`);
    }
    const fp = await fingerprints(key.publicBlob);
    const artLabel = `${key.alg}${key.cert ? "-CERT" : ""} ${key.bits}`;
    const entry = {
      ok: true, source, raw,
      parsed,
      key,
      fingerprints: { sha256: fp.sha256, md5: fp.md5 },
      randomart: randomart(fp.sha256Bytes, artLabel, "SHA256"),
      warnings: keyWarnings(key, parsed),
    };
    if (key.cert?.caBlob) {
      const caFp = await fingerprints(key.cert.caBlob);
      entry.caFingerprint = caFp.sha256;
    }
    entries.push(entry);
  };

  // RFC 4716 blocks first, then line-oriented formats on the rest.
  let rest = text;
  for (const block of rfc4716Blocks(text)) {
    try {
      await addKey({ marker: null, hosts: null, hashedHosts: false, options: null, type: null, b64: block.b64, comment: block.comment }, "rfc4716", block.b64.slice(0, 40));
    } catch (e) {
      if (!(e instanceof SshKeyError)) throw e;
      entries.push({ ok: false, line: "RFC 4716 block", error: e.message });
    }
  }
  rest = rest.replace(/---- BEGIN SSH2 PUBLIC KEY ----[\s\S]*?---- END SSH2 PUBLIC KEY ----/g, "");

  for (const line of rest.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) { if (trimmed) skipped++; continue; }
    try {
      const parsed = parseLine(trimmed);
      const source = parsed.hosts != null ? "known_hosts" : parsed.options ? "authorized_keys" : "openssh";
      await addKey(parsed, source, trimmed);
    } catch (e) {
      if (!(e instanceof SshKeyError)) throw e;
      entries.push({ ok: false, line: trimmed.slice(0, 60), error: e.message });
    }
  }
  return { entries, skipped };
}

// Certificate validity as ssh-keygen -L prints it.
export function formatValidity(cert) {
  if (cert.validAfter === 0n && cert.validBefore === EPOCH_FOREVER) return "forever";
  const fmt = (t) => {
    const d = new Date(Number(t) * 1000);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  };
  const from = cert.validAfter === 0n ? "always" : `from ${fmt(cert.validAfter)}`;
  const to = cert.validBefore === EPOCH_FOREVER ? "forever" : `to ${fmt(cert.validBefore)}`;
  return `${from} ${to}`;
}
