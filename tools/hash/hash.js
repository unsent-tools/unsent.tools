// hash.js — checksums and cryptographic digests, entirely client-side.
// MD5 is implemented here (WebCrypto has none); SHA-1/256/384/512 use
// crypto.subtle (browsers and Node ≥ 19). HMAC is implemented per RFC 2104
// on top of those primitives rather than via crypto.subtle.importKey, which
// rejects empty keys in some engines. CRC32 is the IEEE/zlib polynomial.
// Pure functions, no DOM. Bytes in, bytes out; formatting is separate.

class HashError extends Error {}
const fail = (msg) => { throw new HashError(msg); };

// ---------------------------------------------------------------- bytes/text

export function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  // btoa exists in browsers and Node ≥ 16.
  return btoa(bin);
}

// ------------------------------------------------------------------- crc32

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

// Returns the CRC-32 (IEEE 802.3 / zlib polynomial) as an unsigned number.
export function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// --------------------------------------------------------------------- md5

// RFC 1321. Constants are the canonical hardcoded table — NOT derived from
// Math.sin at runtime, whose last-ulp behavior is not identical across JS
// engines and could silently corrupt the table.
const MD5_K = new Uint32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
  0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
  0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
  0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
  0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
  0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

export function md5(bytes) {
  const len = bytes.length;
  // Padded message: original, 0x80, zeros to ≡56 (mod 64), 64-bit LE bit length.
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const bitLen = len * 8; // safe as a double up to 2^53 bits
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLen >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const m = new Uint32Array(16);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) m[i] = dv.getUint32(off + i * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const tmp = d;
      d = c;
      c = b;
      const sum = (a + f + MD5_K[i] + m[g]) | 0;
      b = (b + ((sum << MD5_S[i]) | (sum >>> (32 - MD5_S[i])))) | 0;
      a = tmp;
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }

  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, a0 >>> 0, true);
  ov.setUint32(4, b0 >>> 0, true);
  ov.setUint32(8, c0 >>> 0, true);
  ov.setUint32(12, d0 >>> 0, true);
  return out;
}

// ------------------------------------------------------------------ digests

export const ALGOS = [
  { id: "crc32", label: "CRC-32", bits: 32, crypto: false },
  { id: "md5", label: "MD5", bits: 128, crypto: "broken" },
  { id: "sha1", label: "SHA-1", bits: 160, crypto: "broken" },
  { id: "sha256", label: "SHA-256", bits: 256, crypto: true },
  { id: "sha384", label: "SHA-384", bits: 384, crypto: true },
  { id: "sha512", label: "SHA-512", bits: 512, crypto: true },
];

const SUBTLE_NAME = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };

// digest(algo, bytes) → Uint8Array. algo is one of the ids above except crc32.
export async function digest(algo, bytes) {
  if (algo === "md5") return md5(bytes);
  const name = SUBTLE_NAME[algo] || fail(`Unknown algorithm: ${algo}`);
  // Copy into a fresh buffer: subtle.digest wants a BufferSource and should
  // not see a view over a larger buffer with an offset.
  const buf = new Uint8Array(bytes).buffer;
  return new Uint8Array(await crypto.subtle.digest(name, buf));
}

// All digests of one message. Returns { crc32: "…8 hex…", md5: Uint8Array, … }.
export async function digestAll(bytes) {
  const out = { crc32: crc32(bytes).toString(16).padStart(8, "0") };
  for (const { id } of ALGOS) {
    if (id === "crc32") continue;
    out[id] = await digest(id, bytes);
  }
  return out;
}

// -------------------------------------------------------------------- hmac

const BLOCK_SIZE = { md5: 64, sha1: 64, sha256: 64, sha384: 128, sha512: 128 };

// RFC 2104: H(K' ⊕ opad ‖ H(K' ⊕ ipad ‖ m)), K' = key padded (or hashed
// first when longer than the block) to the hash's block size.
export async function hmac(algo, keyBytes, msgBytes) {
  const block = BLOCK_SIZE[algo] || fail(`HMAC: unknown algorithm: ${algo}`);
  let key = new Uint8Array(keyBytes);
  if (key.length > block) key = await digest(algo, key);
  const ipad = new Uint8Array(block + msgBytes.length);
  const opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    const k = i < key.length ? key[i] : 0;
    ipad[i] = k ^ 0x36;
    opad[i] = k ^ 0x5c;
  }
  ipad.set(msgBytes, block);
  const inner = await digest(algo, ipad);
  const outer = new Uint8Array(block + inner.length);
  outer.set(opad);
  outer.set(inner, block);
  return digest(algo, outer);
}

// ---------------------------------------------------------------- compare

// Match a pasted expected digest against computed ones. Accepts hex (any
// case, spaces/colons between bytes tolerated — cert fingerprint style) or
// base64. Returns { matches: [algoId…], normalized, kind } or null when the
// input can't be a digest at all.
export function compareDigest(expected, computedHex) {
  const raw = String(expected).trim();
  if (!raw) return null;

  const hexish = raw.replace(/[\s:]+/g, "").toLowerCase();
  if (/^[0-9a-f]+$/.test(hexish) && hexish.length % 2 === 0) {
    const matches = Object.entries(computedHex)
      .filter(([, hex]) => hex === hexish)
      .map(([id]) => id);
    return { kind: "hex", normalized: hexish, matches };
  }

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(raw) && raw.length % 4 === 0) {
    try {
      const bin = atob(raw);
      let hex = "";
      for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
      const matches = Object.entries(computedHex)
        .filter(([, h]) => h === hex)
        .map(([id]) => id);
      return { kind: "base64", normalized: hex, matches };
    } catch {
      return null;
    }
  }
  return null;
}
