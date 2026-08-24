// uuid.js — UUID and ULID inspection: detect the format, decode every field
// the identifier actually carries (version, variant, embedded timestamps,
// clock sequence, node/MAC), and convert between representations of the same
// 128 bits. Pure functions, no DOM. The canonical internal form of a value is
// a 32-char lowercase hex string.

class IdError extends Error {}
const fail = (msg) => { throw new IdError(msg); };

// 100-ns intervals between the Gregorian epoch (1582-10-15) and the Unix
// epoch (1970-01-01): the offset used by UUID v1/v6 timestamps.
const GREGORIAN_OFFSET = 122192928000000000n;

// ---------------------------------------------------------------- helpers

const HEX32 = /^[0-9a-f]{32}$/;

function bitsOf(hex) {
  // hex → BigInt for whole-value arithmetic.
  return BigInt("0x" + hex);
}

export function hexToBytes(hex) {
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

export function bytesToHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function canonicalUuid(hex) {
  if (!HEX32.test(hex)) fail("Internal: not 32 hex chars.");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
}

function ts100nsToUnixMs(ts100ns) {
  // 60-bit Gregorian 100-ns count → Unix milliseconds. May be fractional;
  // returns { ms, iso } with ISO to millisecond precision plus the sub-ms rest.
  const rel = ts100ns - GREGORIAN_OFFSET; // can be negative (pre-1970)
  const msBig = rel / 10000n;
  const sub100ns = rel % 10000n; // remainder in 100-ns units (sign follows rel)
  const ms = Number(msBig);
  return { ms, sub100ns: Number(sub100ns), iso: new Date(ms).toISOString() };
}

// ------------------------------------------------------------- detection

// Accepts: canonical 8-4-4-4-12 UUID, with or without {braces} or a
// urn:uuid: prefix, bare 32-hex, or a 26-char Crockford-base32 ULID.
export function parseInput(raw) {
  let s = String(raw).trim();
  if (!s) fail("Enter a UUID or ULID.");
  const notes = [];

  let m = s.match(/^urn:uuid:(.+)$/i);
  if (m) { s = m[1]; notes.push("URN form (urn:uuid:…)."); }
  m = s.match(/^\{(.+)\}$/);
  if (m) { s = m[1]; notes.push("Braced form (Microsoft registry style)."); }

  const compact = s.toLowerCase();
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(compact)) {
    return { kind: "uuid", hex: compact.replace(/-/g, ""), notes };
  }
  if (HEX32.test(compact)) {
    notes.push("Bare 32-hex form, read as a UUID.");
    return { kind: "uuid", hex: compact, notes };
  }
  if (s.length === 26) {
    const r = decodeCrockford(s); // throws IdError with a specific message
    return { kind: "ulid", hex: r.hex, notes: notes.concat(r.notes) };
  }
  if (/^[0-9a-f-]+$/i.test(s)) {
    fail(`Not a UUID: expected 8-4-4-4-12 hex groups or 32 bare hex chars (got ${s.length} chars).`);
  }
  fail("Not recognized: a UUID is 36 chars of hex-and-dashes; a ULID is 26 chars of Crockford base32.");
}

// -------------------------------------------------------------- Crockford

// Crockford base32 alphabet (no I, L, O, U). Decoding maps i/l→1, o→0 per
// Crockford's spec; u is invalid.
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const B32_VAL = (() => {
  const map = new Map();
  for (let i = 0; i < 32; i++) map.set(B32[i], i);
  map.set("I", 1); map.set("L", 1); map.set("O", 0);
  return map;
})();

function decodeCrockford(s) {
  const notes = [];
  const up = s.toUpperCase();
  if (up !== s) notes.push("Lowercase ULID accepted (case-insensitive).");
  if (/[ILO]/.test(up)) notes.push("Ambiguous letters normalized per Crockford base32: I/L → 1, O → 0.");
  let v = 0n;
  for (const ch of up) {
    const d = B32_VAL.get(ch);
    if (d === undefined) fail(`Not a ULID: "${ch}" is not in the Crockford base32 alphabet (I, L, O are folded; U is excluded).`);
    v = (v << 5n) | BigInt(d);
  }
  // 26 chars carry 130 bits; a ULID is 128, so the top char must be 0–7.
  if (v >> 128n !== 0n) fail(`Not a valid ULID: first character "${up[0]}" overflows 128 bits (must be 0–7).`);
  return { hex: v.toString(16).padStart(32, "0"), notes };
}

export function encodeUlid(hex) {
  let v = bitsOf(hex);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = B32[Number(v & 31n)] + out;
    v >>= 5n;
  }
  return out;
}

// ------------------------------------------------------------------ UUID

const VARIANTS = {
  ncs: "0xxx — reserved, NCS backward compatibility (pre-RFC)",
  rfc: "10xx — OSF DCE / RFC 4122 / RFC 9562 (the standard layout)",
  microsoft: "110x — reserved, Microsoft COM/DCOM backward compatibility",
  future: "111x — reserved for future definition",
};

export function decodeUuid(hex) {
  if (!HEX32.test(hex)) fail("Internal: decodeUuid wants 32 lowercase hex chars.");
  const v = bitsOf(hex);
  const out = { canonical: canonicalUuid(hex), hex, notes: [], fields: [] };

  if (v === 0n) {
    out.special = "nil";
    out.summary = "The Nil UUID: all 128 bits zero. Often a placeholder for “no value”.";
    return out;
  }
  if (hex === "f".repeat(32)) {
    out.special = "max";
    out.summary = "The Max UUID: all 128 bits one (RFC 9562). Often a sentinel for “last possible value”.";
    return out;
  }

  // Variant: high bits of byte 8 (clock_seq_hi_and_reserved).
  const vb = Number((v >> 56n) & 0xffn) >> 4; // top 4 bits of byte 8
  const variant = vb < 8 ? "ncs" : vb < 12 ? "rfc" : vb < 14 ? "microsoft" : "future";
  out.variant = variant;
  out.variantDetail = VARIANTS[variant];

  const version = Number((v >> 76n) & 0xfn); // top 4 bits of byte 6
  if (variant !== "rfc") {
    out.summary = `Variant ${variant.toUpperCase()} — not the standard RFC layout; the version and field structure below do not apply.`;
    return out;
  }
  out.version = version;

  const clockSeq = Number((v >> 48n) & 0x3fffn);
  const node = hex.slice(20);
  const nodeMulticast = (parseInt(hex.slice(20, 22), 16) & 1) === 1;

  switch (version) {
    case 1: {
      // time_low(32) time_mid(16) time_hi(12): 60-bit count of 100-ns
      // intervals since 1582-10-15, split low-first.
      const ts = ((v >> 64n) & 0xfffn) << 48n | ((v >> 80n) & 0xffffn) << 32n | (v >> 96n);
      const t = ts100nsToUnixMs(ts);
      out.summary = "Version 1 — Gregorian time-based. Carries a creation timestamp, a clock sequence, and a node ID (historically the MAC address).";
      out.timestampMs = t.ms;
      out.fields.push(
        { label: "Timestamp", value: `${t.iso}${t.sub100ns ? ` + ${t.sub100ns}×100 ns` : ""}`, detail: `${ts} × 100 ns since 1582-10-15` },
        { label: "Clock sequence", value: String(clockSeq) },
        { label: "Node", value: node.replace(/(..)(?=.)/g, "$1:"),
          detail: nodeMulticast
            ? "Multicast bit set: a random node ID, not a real MAC address."
            : "Multicast bit clear: formatted like a real MAC address — v1 UUIDs can leak the generating machine's hardware address." },
      );
      if (!nodeMulticast) out.privacy = "This UUID embeds what looks like a real MAC address and a creation time.";
      else out.privacy = "This UUID embeds its creation time.";
      break;
    }
    case 2: {
      // DCE Security: time_low replaced by a 32-bit local ID; low byte of
      // clock_seq is the local domain.
      const localId = Number(v >> 96n);
      const domain = Number((v >> 48n) & 0xffn);
      const domains = { 0: "person (POSIX UID)", 1: "group (POSIX GID)", 2: "org" };
      out.summary = "Version 2 — DCE Security. Rare; embeds a local ID (often a Unix UID/GID) and domain. Timestamp resolution is very coarse.";
      out.fields.push(
        { label: "Local ID", value: String(localId), detail: domains[domain] ? `interpreted per domain: ${domains[domain]}` : undefined },
        { label: "Local domain", value: `${domain}${domains[domain] ? ` (${domains[domain]})` : ""}` },
        { label: "Node", value: node.replace(/(..)(?=.)/g, "$1:") },
      );
      out.privacy = "This UUID embeds a local user/group ID and a node identifier.";
      break;
    }
    case 3:
    case 5: {
      const alg = version === 3 ? "MD5" : "SHA-1";
      out.summary = `Version ${version} — name-based (${alg} of a namespace + name). Deterministic: the same name in the same namespace always yields this UUID. The hash is one-way; the name cannot be recovered from it.`;
      break;
    }
    case 4: {
      out.summary = "Version 4 — random. 122 bits of randomness; carries no timestamp, order, or machine information.";
      break;
    }
    case 6: {
      // Reordered Gregorian time: time_high(32) time_mid(16) time_low(12),
      // most significant first — same epoch and unit as v1.
      const ts = (v >> 96n) << 28n | ((v >> 80n) & 0xffffn) << 12n | ((v >> 64n) & 0xfffn);
      const t = ts100nsToUnixMs(ts);
      out.summary = "Version 6 — reordered Gregorian time (RFC 9562). Same fields as v1 but timestamp bytes are big-endian first, so the UUIDs sort by creation time.";
      out.timestampMs = t.ms;
      out.fields.push(
        { label: "Timestamp", value: `${t.iso}${t.sub100ns ? ` + ${t.sub100ns}×100 ns` : ""}`, detail: `${ts} × 100 ns since 1582-10-15` },
        { label: "Clock sequence", value: String(clockSeq) },
        { label: "Node", value: node.replace(/(..)(?=.)/g, "$1:"),
          detail: nodeMulticast ? "Multicast bit set: random node ID." : "Formatted like a real MAC address." },
      );
      out.privacy = "This UUID embeds its creation time.";
      break;
    }
    case 7: {
      // 48-bit Unix milliseconds, then 74 random bits.
      const ms = Number(v >> 80n);
      out.summary = "Version 7 — Unix-epoch time-ordered (RFC 9562). A 48-bit millisecond timestamp followed by 74 random bits; sorts by creation time.";
      out.timestampMs = ms;
      out.fields.push(
        { label: "Timestamp", value: new Date(ms).toISOString(), detail: `${ms} ms since 1970-01-01` },
      );
      out.privacy = "This UUID embeds its creation time.";
      break;
    }
    case 8: {
      out.summary = "Version 8 — custom/experimental (RFC 9562). The 122 non-version/variant bits mean whatever the generating system decided; no standard fields to decode.";
      break;
    }
    default: {
      out.summary = `Version ${version} — not defined by RFC 9562.`;
    }
  }
  return out;
}

// ------------------------------------------------------------------ ULID

export function decodeUlid(hex) {
  const v = bitsOf(hex);
  const ms = Number(v >> 80n);
  const randomness = hex.slice(12);
  return {
    canonical: encodeUlid(hex),
    hex,
    timestampMs: ms,
    iso: new Date(ms).toISOString(),
    randomness,
    summary: "ULID — a 48-bit millisecond timestamp followed by 80 random bits, written as 26 chars of Crockford base32. Lexicographic order is creation order.",
  };
}

// ------------------------------------------------------------ generation

// Pure builders: randomness and time are injected so tests control them.
// bytes: array of 16 (v4) or 10 (v7/ULID) integers 0..255.

export function buildV4(bytes16) {
  if (bytes16.length !== 16) fail("buildV4 wants 16 random bytes.");
  const b = bytes16.slice();
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  return bytesToHex(b);
}

export function buildV7(unixMs, bytes10) {
  if (bytes10.length !== 10) fail("buildV7 wants 10 random bytes.");
  if (!Number.isInteger(unixMs) || unixMs < 0 || unixMs >= 2 ** 48) fail("buildV7: timestamp out of 48-bit range.");
  const b = new Array(6);
  let t = BigInt(unixMs);
  for (let i = 5; i >= 0; i--) { b[i] = Number(t & 0xffn); t >>= 8n; }
  const r = bytes10.slice();
  r[0] = (r[0] & 0x0f) | 0x70; // version 7
  r[2] = (r[2] & 0x3f) | 0x80; // variant 10xx
  return bytesToHex(b.concat(r));
}

export function buildUlid(unixMs, bytes10) {
  if (bytes10.length !== 10) fail("buildUlid wants 10 random bytes.");
  if (!Number.isInteger(unixMs) || unixMs < 0 || unixMs >= 2 ** 48) fail("buildUlid: timestamp out of 48-bit range.");
  let v = BigInt(unixMs);
  for (const byte of bytes10) v = (v << 8n) | BigInt(byte);
  return encodeUlid(v.toString(16).padStart(32, "0"));
}

// ---------------------------------------------------------- conversions

// Every 128-bit value has all of these faces; which one is "true" depends
// only on where it came from.
export function representations(hex) {
  const bytes = hexToBytes(hex);
  return {
    uuid: canonicalUuid(hex),
    ulid: encodeUlid(hex),
    hex,
    bytes: bytes.join(" "),
    intBE: bitsOf(hex).toString(),
  };
}
