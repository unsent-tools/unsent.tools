// IPv4 subnet / CIDR calculations.
//
// All addresses are handled internally as unsigned 32-bit integers. JavaScript's
// bitwise operators work on *signed* 32-bit values, so every result that leaves
// a bitwise expression is normalized with `>>> 0` to keep it unsigned. Shift
// counts are also taken mod 32 by the language, which is why prefix 0 and prefix
// 32 are handled explicitly rather than via `<< (32 - prefix)`.

/** Parse dotted-decimal IPv4 into an unsigned 32-bit integer. Strict: exactly
 *  four octets, each 0-255, no leading zeros (to avoid octal ambiguity). */
export function parseIPv4(str) {
  if (typeof str !== "string") throw new TypeError("address must be a string");
  const s = str.trim();
  const parts = s.split(".");
  if (parts.length !== 4) {
    throw new Error(`invalid IPv4 address "${str}": expected 4 octets`);
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      throw new Error(`invalid IPv4 address "${str}": bad octet "${part}"`);
    }
    if (part.length > 1 && part[0] === "0") {
      throw new Error(`invalid IPv4 address "${str}": leading zero in "${part}"`);
    }
    const n = Number(part);
    if (n > 255) {
      throw new Error(`invalid IPv4 address "${str}": octet ${n} > 255`);
    }
    value = (value * 256) + n;
  }
  return value >>> 0;
}

/** Format an unsigned 32-bit integer as dotted-decimal IPv4. */
export function ipv4ToString(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`value out of IPv4 range: ${value}`);
  }
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

/** Prefix length (0-32) -> netmask as unsigned 32-bit integer. */
export function prefixToMask(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new RangeError(`prefix must be 0-32, got ${prefix}`);
  }
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

/** Contiguous netmask (as unsigned 32-bit int) -> prefix length. Throws if the
 *  mask is not a run of 1s followed by a run of 0s. */
export function maskToPrefix(mask) {
  const m = mask >>> 0;
  // A valid mask has the form 1...10...0. Its bitwise complement + 1, when the
  // mask is non-zero, is a power of two equal to the lowest set bit region.
  // A contiguous mask is 1...10...0, so its complement is 0...01...1. Adding 1
  // to a low run of 1s produces a power of two, i.e. clears against itself.
  const inverted = (~m) >>> 0;
  if ((((inverted + 1) & inverted) >>> 0) !== 0) {
    throw new Error(`not a contiguous netmask: ${ipv4ToString(m)}`);
  }
  let prefix = 0;
  let v = m;
  while (v & 0x80000000) {
    prefix++;
    v = (v << 1) >>> 0;
  }
  return prefix;
}

/** Parse "a.b.c.d/p" or "a.b.c.d" (bare address treated as /32). Also accepts a
 *  dotted-decimal netmask after the slash, e.g. "10.0.0.0/255.0.0.0". */
export function parseCIDR(str) {
  if (typeof str !== "string") throw new TypeError("input must be a string");
  const s = str.trim();
  const slash = s.indexOf("/");
  if (slash === -1) {
    return { address: parseIPv4(s), prefix: 32 };
  }
  const addrPart = s.slice(0, slash);
  const maskPart = s.slice(slash + 1).trim();
  const address = parseIPv4(addrPart);
  let prefix;
  if (maskPart.includes(".")) {
    prefix = maskToPrefix(parseIPv4(maskPart));
  } else {
    if (!/^\d{1,2}$/.test(maskPart)) {
      throw new Error(`invalid prefix "/${maskPart}"`);
    }
    prefix = Number(maskPart);
    if (prefix > 32) throw new RangeError(`prefix must be 0-32, got ${prefix}`);
  }
  return { address, prefix };
}

/** Full report for an address + prefix. Numeric counts are plain numbers
 *  (2^32 fits safely in a JS number). */
export function subnetInfo(address, prefix) {
  const mask = prefixToMask(prefix);
  const wildcard = (~mask) >>> 0;
  const network = (address & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const total = 2 ** (32 - prefix);

  let firstHost, lastHost, usableHosts;
  if (prefix === 32) {
    // Single host.
    firstHost = lastHost = network;
    usableHosts = 1;
  } else if (prefix === 31) {
    // RFC 3021 point-to-point link: both addresses are usable, no broadcast.
    firstHost = network;
    lastHost = broadcast;
    usableHosts = 2;
  } else {
    firstHost = (network + 1) >>> 0;
    lastHost = (broadcast - 1) >>> 0;
    usableHosts = total - 2;
  }

  return {
    prefix,
    netmask: ipv4ToString(mask),
    wildcard: ipv4ToString(wildcard),
    network: ipv4ToString(network),
    broadcast: ipv4ToString(broadcast),
    firstHost: ipv4ToString(firstHost),
    lastHost: ipv4ToString(lastHost),
    totalAddresses: total,
    usableHosts,
    // "class" and privateness are informational conveniences.
    isPrivate: isPrivateIPv4(network),
    range: `${ipv4ToString(network)} – ${ipv4ToString(broadcast)}`,
  };
}

/** True if the address falls in an RFC 1918 private range. */
export function isPrivateIPv4(value) {
  const v = value >>> 0;
  const inRange = (cidr) => {
    const { address, prefix } = parseCIDR(cidr);
    const mask = prefixToMask(prefix);
    return ((v & mask) >>> 0) === ((address & mask) >>> 0);
  };
  return inRange("10.0.0.0/8") || inRange("172.16.0.0/12") || inRange("192.168.0.0/16");
}

/** Convenience: parse a CIDR string and return its full report. */
export function describe(str) {
  const { address, prefix } = parseCIDR(str);
  return subnetInfo(address, prefix);
}
