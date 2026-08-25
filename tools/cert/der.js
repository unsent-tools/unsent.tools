// Minimal DER (X.690 Distinguished Encoding Rules) parser — the subset X.509
// needs. Parses a byte array into a tree of TLV nodes; separate helpers decode
// the primitive types (OID, INTEGER, BIT STRING, strings, times).
//
// Deliberately strict where DER is strict: indefinite lengths are rejected,
// lengths must fit in the buffer, and unused-bit counts in BIT STRINGs must be
// 0..7. Everything else (unknown tags) is preserved as raw bytes so callers
// can display what they don't understand instead of failing.

export const CLASS_UNIVERSAL = 0, CLASS_APPLICATION = 1,
             CLASS_CONTEXT = 2, CLASS_PRIVATE = 3;

// Parse one TLV element starting at `offset`. Returns a node:
//   { cls, tag, constructed, start, contentStart, length, end, children|null }
// `children` is populated (recursively) for constructed elements.
export function parseElement(bytes, offset = 0) {
  if (offset >= bytes.length) throw new Error("Truncated DER: expected a tag, hit end of data.");
  const first = bytes[offset];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let pos = offset + 1;
  if (tag === 0x1f) { // high-tag-number form
    tag = 0;
    let more = true, count = 0;
    while (more) {
      if (pos >= bytes.length) throw new Error("Truncated DER: unterminated high tag number.");
      const b = bytes[pos++];
      tag = tag * 128 + (b & 0x7f);
      more = (b & 0x80) !== 0;
      if (++count > 4) throw new Error("Unsupported DER: tag number too large.");
    }
  }
  if (pos >= bytes.length) throw new Error("Truncated DER: expected a length, hit end of data.");
  let lenByte = bytes[pos++];
  let length;
  if (lenByte < 0x80) {
    length = lenByte;
  } else if (lenByte === 0x80) {
    throw new Error("Indefinite length is BER, not DER — certificates must use definite lengths.");
  } else {
    const n = lenByte & 0x7f;
    if (n > 6) throw new Error("Unsupported DER: length field wider than 6 bytes.");
    length = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= bytes.length) throw new Error("Truncated DER: length field runs past end of data.");
      length = length * 256 + bytes[pos++];
    }
  }
  const contentStart = pos;
  const end = contentStart + length;
  if (end > bytes.length) {
    throw new Error(`Truncated DER: element claims ${length} content bytes but only ${bytes.length - contentStart} remain.`);
  }
  const node = { cls, tag, constructed, start: offset, contentStart, length, end, children: null };
  if (constructed) {
    node.children = [];
    let p = contentStart;
    while (p < end) {
      const child = parseElement(bytes, p);
      node.children.push(child);
      p = child.end;
    }
  }
  return node;
}

export function content(bytes, node) {
  return bytes.subarray(node.contentStart, node.end);
}

export function toHex(u8, sep = "") {
  return Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join(sep);
}

// ---- primitive decoders ------------------------------------------------

export function readOid(bytes, node) {
  const c = content(bytes, node);
  if (c.length === 0) throw new Error("Empty OBJECT IDENTIFIER.");
  const parts = [];
  let value = 0n, first = true;
  for (let i = 0; i < c.length; i++) {
    value = value * 128n + BigInt(c[i] & 0x7f);
    if ((c[i] & 0x80) === 0) {
      if (first) {
        const v = Number(value);
        parts.push(Math.min(2, Math.floor(v / 40)), v - 40 * Math.min(2, Math.floor(v / 40)));
        first = false;
      } else {
        parts.push(value.toString());
      }
      value = 0n;
    }
  }
  if ((c[c.length - 1] & 0x80) !== 0) throw new Error("Truncated OBJECT IDENTIFIER component.");
  return parts.join(".");
}

// INTEGER → { hex, bigint, negative }. hex is the raw big-endian content
// (two's complement, as certificates carry serial numbers).
export function readInteger(bytes, node) {
  const c = content(bytes, node);
  if (c.length === 0) throw new Error("Empty INTEGER.");
  const negative = (c[0] & 0x80) !== 0;
  let big = 0n;
  for (const b of c) big = (big << 8n) | BigInt(b);
  if (negative) big -= 1n << BigInt(8 * c.length);
  return { hex: toHex(c), bigint: big, negative, byteLength: c.length };
}

// BIT STRING → { unusedBits, bytes } (bytes excludes the leading unused-bits octet)
export function readBitString(bytes, node) {
  const c = content(bytes, node);
  if (c.length === 0) throw new Error("Empty BIT STRING.");
  const unusedBits = c[0];
  if (unusedBits > 7) throw new Error("Invalid BIT STRING: more than 7 unused bits.");
  return { unusedBits, bytes: c.subarray(1) };
}

const UTF8 = new TextDecoder("utf-8", { fatal: false });

// Decode a directory-string-ish value by universal tag.
export function readString(bytes, node) {
  const c = content(bytes, node);
  switch (node.tag) {
    case 12: // UTF8String
    case 19: // PrintableString
    case 22: // IA5String
    case 26: // VisibleString
    case 27: // GeneralString
      return UTF8.decode(c);
    case 20: // T61String / TeletexString — in practice Latin-1
      return Array.from(c, (b) => String.fromCharCode(b)).join("");
    case 30: { // BMPString — UCS-2 big-endian
      let s = "";
      for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]);
      return s;
    }
    case 28: { // UniversalString — UCS-4 big-endian
      let s = "";
      for (let i = 0; i + 3 < c.length; i += 4) {
        s += String.fromCodePoint((c[i] << 24) | (c[i + 1] << 16) | (c[i + 2] << 8) | c[i + 3]);
      }
      return s;
    }
    default:
      return null; // caller decides how to show unknown types
  }
}

// UTCTime (tag 23, YYMMDDHHMMSSZ) and GeneralizedTime (tag 24, YYYYMMDDHHMMSSZ)
// → { iso, epochMs, kind }. RFC 5280 pivots UTCTime at 50: 00–49 → 20xx, 50–99 → 19xx.
export function readTime(bytes, node) {
  const s = UTF8.decode(content(bytes, node));
  let m, year, kind;
  if (node.tag === 23) {
    kind = "UTCTime";
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`Malformed UTCTime "${s}" (expected YYMMDDHHMMSSZ).`);
    const yy = Number(m[1]);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
  } else if (node.tag === 24) {
    kind = "GeneralizedTime";
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`Malformed GeneralizedTime "${s}" (expected YYYYMMDDHHMMSSZ).`);
    year = Number(m[1]);
  } else {
    throw new Error(`Expected a time value, got tag ${node.tag}.`);
  }
  const [mo, d, h, mi, sec] = m.slice(2).map(Number);
  const epochMs = Date.UTC(year, mo - 1, d, h, mi, sec);
  // Round-trip check rejects impossible dates like Feb 30.
  const dt = new Date(epochMs);
  if (dt.getUTCFullYear() !== year || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d ||
      dt.getUTCHours() !== h || dt.getUTCMinutes() !== mi || dt.getUTCSeconds() !== sec) {
    throw new Error(`Impossible date in certificate time "${s}".`);
  }
  const iso = dt.toISOString().replace(".000", "");
  return { iso, epochMs, kind };
}

// ---- PEM ---------------------------------------------------------------

// Extract PEM blocks: returns [{ label, der }]. Accepts leading/trailing junk
// (as openssl does) and, if no PEM armor is present at all, tries to treat the
// whole input as bare base64 DER.
export function pemBlocks(text) {
  const blocks = [];
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    blocks.push({ label: m[1], der: base64Decode(m[2]) });
  }
  if (blocks.length === 0) {
    const stripped = text.replace(/\s+/g, "");
    if (stripped.length > 0 && /^[A-Za-z0-9+/]+=*$/.test(stripped)) {
      blocks.push({ label: "CERTIFICATE", der: base64Decode(stripped), bare: true });
    }
  }
  return blocks;
}

export function base64Decode(text) {
  const clean = text.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*=*$/.test(clean)) throw new Error("Invalid base64 in PEM body.");
  if (typeof atob === "function") {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node fallback (tests)
  return new Uint8Array(Buffer.from(clean, "base64"));
}
