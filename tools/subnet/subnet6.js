// IPv6 subnet / CIDR calculations.
//
// Addresses are handled internally as BigInt (0 .. 2^128-1). Text parsing
// follows RFC 4291 (hextets, `::` compression, embedded dotted-quad IPv4
// tail); formatting follows RFC 5952 (lowercase, longest zero run compressed,
// leftmost on tie, runs of a single zero group not compressed).

const MAX128 = (1n << 128n) - 1n;

/** Parse IPv6 text into { value: BigInt, zone: string|null }.
 *  Accepts a `%zone` suffix (link-local scope id) and reports it separately. */
export function parseIPv6(str) {
  if (typeof str !== "string") throw new TypeError("address must be a string");
  let s = str.trim();
  let zone = null;
  const pct = s.indexOf("%");
  if (pct !== -1) {
    zone = s.slice(pct + 1);
    s = s.slice(0, pct);
    if (!zone) throw new Error(`invalid IPv6 address "${str}": empty zone id after %`);
  }
  if (!s) throw new Error(`invalid IPv6 address "${str}": empty`);

  // Split on "::" (at most one).
  const dcolon = s.indexOf("::");
  if (dcolon !== s.lastIndexOf("::")) {
    throw new Error(`invalid IPv6 address "${str}": more than one "::"`);
  }

  const parseGroups = (part, side) => {
    // side: "head" may not start with ":", "tail" may not end with ":".
    if (part === "") return [];
    const groups = part.split(":");
    if (groups.some((g) => g === "")) {
      throw new Error(`invalid IPv6 address "${str}": empty group`);
    }
    return groups;
  };

  let headGroups, tailGroups, hasCompression;
  if (dcolon === -1) {
    hasCompression = false;
    headGroups = parseGroups(s);
    tailGroups = [];
  } else {
    hasCompression = true;
    headGroups = parseGroups(s.slice(0, dcolon));
    tailGroups = parseGroups(s.slice(dcolon + 2));
  }

  // An embedded dotted-quad IPv4 may only appear as the final group.
  const words = [];
  const pushWord = (g) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
      throw new Error(`invalid IPv6 address "${str}": bad group "${g}"`);
    }
    words.push(parseInt(g, 16));
  };
  const expandGroup = (g, isLast) => {
    if (isLast && g.includes(".")) {
      // Reuse strict IPv4 rules: 4 octets, 0-255, no leading zeros.
      const parts = g.split(".");
      if (parts.length !== 4) throw new Error(`invalid IPv6 address "${str}": bad embedded IPv4 "${g}"`);
      let v4 = 0;
      for (const p of parts) {
        if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === "0") || Number(p) > 255) {
          throw new Error(`invalid IPv6 address "${str}": bad embedded IPv4 octet "${p}"`);
        }
        v4 = v4 * 256 + Number(p);
      }
      words.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
    } else if (g.includes(".")) {
      throw new Error(`invalid IPv6 address "${str}": embedded IPv4 must be the final group`);
    } else {
      pushWord(g);
    }
  };

  headGroups.forEach((g, i) => expandGroup(g, !hasCompression && tailGroups.length === 0 && i === headGroups.length - 1));
  const headLen = words.length;
  tailGroups.forEach((g, i) => expandGroup(g, i === tailGroups.length - 1));
  const tailLen = words.length - headLen;

  if (hasCompression) {
    const missing = 8 - headLen - tailLen;
    // "::" must stand for at least one zero group... except in the bare forms
    // where it legitimately stands for the whole address (::) — RFC 4291 just
    // requires it to shorten; universally accepted parsers (incl. Python's)
    // require missing >= 1.
    if (missing < 1) {
      throw new Error(`invalid IPv6 address "${str}": "::" must replace at least one group`);
    }
    words.splice(headLen, 0, ...new Array(missing).fill(0));
  } else if (words.length !== 8) {
    throw new Error(`invalid IPv6 address "${str}": expected 8 groups, got ${words.length}`);
  }

  let value = 0n;
  for (const w of words) value = (value << 16n) | BigInt(w);
  return { value, zone };
}

/** Format a BigInt as canonical RFC 5952 text. IPv4-mapped addresses
 *  (::ffff:0:0/96) use the mixed a.b.c.d tail, as RFC 5952 §5 recommends. */
export function ipv6ToString(value) {
  if (typeof value !== "bigint" || value < 0n || value > MAX128) {
    throw new RangeError(`value out of IPv6 range: ${value}`);
  }
  const words = [];
  for (let i = 7; i >= 0; i--) words.push(Number((value >> BigInt(i * 16)) & 0xffffn));

  const isV4Mapped = value >> 32n === 0xffffn;
  const hexCount = isV4Mapped ? 6 : 8;

  // Longest run of zero words (length >= 2), leftmost on tie.
  let best = { start: -1, len: 0 };
  let run = { start: -1, len: 0 };
  for (let i = 0; i < hexCount; i++) {
    if (words[i] === 0) {
      if (run.len === 0) run.start = i;
      run.len++;
      if (run.len > best.len) best = { ...run };
    } else {
      run = { start: -1, len: 0 };
    }
  }
  if (best.len < 2) best = { start: -1, len: 0 };

  const hex = (w) => w.toString(16);
  let out;
  if (best.start === -1) {
    out = words.slice(0, hexCount).map(hex).join(":");
  } else {
    const left = words.slice(0, best.start).map(hex).join(":");
    const right = words.slice(best.start + best.len, hexCount).map(hex).join(":");
    out = left + "::" + right;
  }
  if (isV4Mapped) {
    const v4 = Number(value & 0xffffffffn);
    const dotted = [(v4 >>> 24) & 0xff, (v4 >>> 16) & 0xff, (v4 >>> 8) & 0xff, v4 & 0xff].join(".");
    out += ":" + dotted;
  }
  return out;
}

/** Prefix length (0-128) -> mask as BigInt. */
export function prefixToMask6(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    throw new RangeError(`prefix must be 0-128, got ${prefix}`);
  }
  return prefix === 0 ? 0n : (MAX128 << BigInt(128 - prefix)) & MAX128;
}

/** Parse "addr/prefix" or a bare address (treated as /128). */
export function parseCIDR6(str) {
  if (typeof str !== "string") throw new TypeError("input must be a string");
  const s = str.trim();
  const slash = s.indexOf("/");
  if (slash === -1) {
    const { value, zone } = parseIPv6(s);
    return { address: value, prefix: 128, zone };
  }
  const { value, zone } = parseIPv6(s.slice(0, slash));
  const p = s.slice(slash + 1).trim();
  if (!/^\d{1,3}$/.test(p) || Number(p) > 128) {
    throw new Error(`invalid prefix "/${p}": expected 0-128`);
  }
  return { address: value, prefix: Number(p), zone };
}

/** Human-readable 2^n count: exact digits up to 2^53, then "2^n (~x.xe+y)". */
export function formatCount(hostBits) {
  if (hostBits <= 53) return (2 ** hostBits).toLocaleString("en-US");
  const approx = (2 ** hostBits).toExponential(2).replace("e+", "×10^");
  return `2^${hostBits} (≈ ${approx})`;
}

/** Well-known range classification, most specific first. */
export function classifyIPv6(value) {
  const inBlock = (addrStr, prefix) => {
    const net = parseIPv6(addrStr).value;
    const mask = prefixToMask6(prefix);
    return (value & mask) === net;
  };
  if (value === 0n) return "Unspecified address (::)";
  if (value === 1n) return "Loopback (::1)";
  if (inBlock("::ffff:0:0", 96)) return "IPv4-mapped (::ffff:0:0/96)";
  if (inBlock("64:ff9b::", 96)) return "IPv4-IPv6 translation, NAT64 (64:ff9b::/96, RFC 6052)";
  if (inBlock("2001:db8::", 32)) return "Documentation (2001:db8::/32, RFC 3849)";
  if (inBlock("2001::", 32)) return "Teredo tunneling (2001::/32)";
  if (inBlock("2002::", 16)) return "6to4 (2002::/16)";
  if (inBlock("fe80::", 10)) return "Link-local (fe80::/10)";
  if (inBlock("fc00::", 7)) return "Unique local (fc00::/7, RFC 4193)";
  if (inBlock("ff00::", 8)) return "Multicast (ff00::/8)";
  if (inBlock("2000::", 3)) return "Global unicast (2000::/3)";
  return "Reserved / unassigned by IANA";
}

/** Full report for an IPv6 address + prefix. */
export function subnet6Info(address, prefix) {
  const mask = prefixToMask6(prefix);
  const network = address & mask;
  const last = network | (~mask & MAX128);
  const notes = [];
  if (prefix === 128) notes.push("A /128 is a single host address.");
  else if (prefix === 127) notes.push("A /127 is a point-to-point link (RFC 6164): both addresses usable.");
  else if (prefix === 64) notes.push("A /64 is the standard IPv6 subnet size; SLAAC requires it.");
  else if (prefix > 64) notes.push("Longer than /64: SLAAC will not work on this subnet.");
  return {
    prefix,
    network: ipv6ToString(network),
    last: ipv6ToString(last),
    netmask: ipv6ToString(mask),
    totalAddresses: formatCount(128 - prefix),
    range: prefix === 128 ? ipv6ToString(network) : `${ipv6ToString(network)} – ${ipv6ToString(last)}`,
    type: classifyIPv6(address),
    notes,
  };
}

/** Convenience: parse an IPv6 CIDR string and return its full report. */
export function describe6(str) {
  const { address, prefix, zone } = parseCIDR6(str);
  const info = subnet6Info(address, prefix);
  if (zone) info.notes.push(`Zone id "%${zone}" identifies the local interface; it is not part of the address bits.`);
  return info;
}
