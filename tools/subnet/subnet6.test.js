import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  parseIPv6, ipv6ToString, prefixToMask6, parseCIDR6,
  subnet6Info, classifyIPv6, describe6, formatCount,
} from "./subnet6.js";

const rand128 = () => {
  let v = 0n;
  for (const b of randomBytes(16)) v = (v << 8n) | BigInt(b);
  return v;
};
// Sparse values (few non-zero words) exercise "::" compression placement.
const sparse128 = () => {
  let v = 0n;
  const k = 1 + Math.floor(Math.random() * 3);
  for (let j = 0; j < k; j++) {
    v |= BigInt(Math.floor(Math.random() * 0x10000)) << BigInt(Math.floor(Math.random() * 8) * 16);
  }
  return v;
};

// ------------------------------------------------- RFC 5952 pinned vectors

test("RFC 5952 canonical formatting rules", () => {
  const f = (s) => ipv6ToString(parseIPv6(s).value);
  // lowercase, leading zeros dropped
  assert.equal(f("2001:0DB8:0000:0000:0000:0000:0000:0001"), "2001:db8::1");
  // a single zero group is NOT compressed (§4.2.2)
  assert.equal(f("2001:db8:0:1:1:1:1:1"), "2001:db8:0:1:1:1:1:1");
  // longest run wins (§4.2.3)
  assert.equal(f("2001:0:0:1:0:0:0:1"), "2001:0:0:1::1");
  // leftmost on tie (§4.2.3)
  assert.equal(f("2001:db8:0:0:1:0:0:1"), "2001:db8::1:0:0:1");
  // whole-address and edge compressions
  assert.equal(f("0:0:0:0:0:0:0:0"), "::");
  assert.equal(f("0:0:0:0:0:0:0:1"), "::1");
  assert.equal(f("2001:db8:0:0:0:0:0:0"), "2001:db8::");
  // IPv4-mapped uses mixed notation (§5)
  assert.equal(f("::ffff:192.0.2.1"), "::ffff:192.0.2.1");
  assert.equal(f("::ffff:c000:201"), "::ffff:192.0.2.1");
});

test("parse accepts standard variants", () => {
  assert.equal(parseIPv6("::").value, 0n);
  assert.equal(parseIPv6("::1").value, 1n);
  assert.equal(parseIPv6("2001:DB8::1").value, parseIPv6("2001:db8::1").value);
  assert.equal(parseIPv6("  2001:db8::1  ").value, parseIPv6("2001:db8::1").value);
  // zone id is reported, not part of the bits
  const z = parseIPv6("fe80::1%eth0");
  assert.equal(z.zone, "eth0");
  assert.equal(z.value, parseIPv6("fe80::1").value);
});

test("malformed addresses fail with specific messages", () => {
  assert.throws(() => parseIPv6("2001::db8::1"), /more than one/);
  assert.throws(() => parseIPv6("2001:db8:::1"), /empty group|more than one/);
  assert.throws(() => parseIPv6("2001:db8:12345::"), /bad group/);
  assert.throws(() => parseIPv6("1:2:3:4:5:6:7:8:9"), /expected 8 groups/);
  assert.throws(() => parseIPv6("1:2:3:4:5:6:7"), /expected 8 groups/);
  assert.throws(() => parseIPv6("1::2:3:4:5:6:7:8"), /at least one group/);
  assert.throws(() => parseIPv6("::192.0.2.1:ffff"), /final group/);
  assert.throws(() => parseIPv6("::ffff:192.0.2.256"), /octet/);
  assert.throws(() => parseIPv6("::ffff:192.0.02.1"), /octet/);
  assert.throws(() => parseIPv6("fe80::1%"), /empty zone/);
  assert.throws(() => parseIPv6(""), /empty/);
  assert.throws(() => parseCIDR6("2001:db8::/129"), /0-128/);
  assert.throws(() => parseCIDR6("2001:db8::/xx"), /0-128/);
});

// --------------------------------- differential: Python ipaddress module
// An independent implementation of both RFC 4291 parsing and RFC 5952
// formatting. Requires python3 on PATH (as the chmod suite requires chmod).

test("differential: format and parse agree with Python for 600 values", () => {
  const vals = [];
  for (let i = 0; i < 250; i++) vals.push(rand128());
  for (let i = 0; i < 350; i++) vals.push(sparse128());
  vals.push(0n, 1n, (1n << 128n) - 1n, (0xffffn << 32n) | 0xc0000201n, 0xffffn << 32n);

  const py = `
import sys, ipaddress
for line in sys.stdin.read().split():
    a = ipaddress.IPv6Address(int(line))
    print(str(a), a.exploded)
`;
  const refs = execFileSync("python3", ["-c", py], { input: vals.join("\n"), encoding: "utf8" })
    .trim().split("\n").map((l) => l.split(" "));
  vals.forEach((v, i) => {
    const [compact, exploded] = refs[i];
    const mine = ipv6ToString(v);
    // Round-trip: my formatter's output parses back to the same bits.
    assert.equal(parseIPv6(mine).value, v, mine);
    // My parser reads both of Python's spellings.
    assert.equal(parseIPv6(compact).value, v, compact);
    assert.equal(parseIPv6(exploded).value, v, exploded);
    // Identical canonical text, except IPv4-mapped where RFC 5952 §5
    // recommends mixed notation and Python stays hexadecimal.
    if ((v >> 32n) !== 0xffffn) assert.equal(mine, compact);
  });
});

test("differential: network/last/mask agree with Python for 300 random CIDRs", () => {
  const cases = [];
  for (let i = 0; i < 300; i++) {
    cases.push([i % 2 ? rand128() : sparse128(), Math.floor(Math.random() * 129)]);
  }
  cases.push([parseIPv6("2001:db8::dead:beef").value, 64], [0n, 0], [(1n << 128n) - 1n, 128]);

  const py = `
import sys, ipaddress, json
out = []
for line in sys.stdin.read().splitlines():
    v, p = line.split()
    n = ipaddress.IPv6Network((int(v), int(p)), strict=False)
    out.append([str(n.network_address), str(n.broadcast_address), str(n.netmask)])
print(json.dumps(out))
`;
  const refs = JSON.parse(execFileSync("python3", ["-c", py],
    { input: cases.map(([v, p]) => `${v} ${p}`).join("\n"), encoding: "utf8" }));
  cases.forEach(([v, p], i) => {
    const info = subnet6Info(v, p);
    const [network, last, netmask] = refs[i];
    // Compare as bits (Python never uses mixed notation; we may).
    assert.equal(parseIPv6(info.network).value, parseIPv6(network).value, `${v}/${p}`);
    assert.equal(parseIPv6(info.last).value, parseIPv6(last).value, `${v}/${p}`);
    assert.equal(parseIPv6(info.netmask).value, parseIPv6(netmask).value, `${v}/${p}`);
  });
});

// ---------------------------------------------------------- classification

test("well-known ranges classify correctly", () => {
  const c = (s) => classifyIPv6(parseIPv6(s).value);
  assert.match(c("::"), /Unspecified/);
  assert.match(c("::1"), /Loopback/);
  assert.match(c("::ffff:192.0.2.1"), /IPv4-mapped/);
  assert.match(c("64:ff9b::192.0.2.1"), /NAT64/);
  assert.match(c("2001:db8::1"), /Documentation/);
  assert.match(c("2001::1"), /Teredo/);
  assert.match(c("2002::1"), /6to4/);
  assert.match(c("fe80::1"), /Link-local/);
  assert.match(c("febf::1"), /Link-local/); // top of fe80::/10
  assert.match(c("fd00::1"), /Unique local/);
  assert.match(c("ff02::1"), /Multicast/);
  assert.match(c("2606:4700:4700::1111"), /Global unicast/);
  assert.match(c("100::1"), /Reserved/);
});

// ------------------------------------------------------------ subnet info

test("subnet6Info basics and notes", () => {
  const i64 = describe6("2001:db8::dead:beef/64");
  assert.equal(i64.network, "2001:db8::");
  assert.equal(i64.last, "2001:db8::ffff:ffff:ffff:ffff");
  assert.equal(i64.netmask, "ffff:ffff:ffff:ffff::");
  assert.equal(i64.totalAddresses, "2^64 (≈ 1.84×10^19)");
  assert.ok(i64.notes.some((n) => /SLAAC requires/.test(n)));

  const p2p = describe6("2001:db8::/127");
  assert.ok(p2p.notes.some((n) => /RFC 6164/.test(n)));

  const host = describe6("2001:db8::1");
  assert.equal(host.prefix, 128);
  assert.equal(host.range, "2001:db8::1");
  assert.ok(host.notes.some((n) => /single host/.test(n)));

  const all = describe6("::/0");
  assert.equal(all.totalAddresses, "2^128 (≈ 3.40×10^38)");
  assert.equal(all.range, ":: – ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

  assert.equal(formatCount(20), "1,048,576");
  assert.equal(prefixToMask6(0), 0n);
  assert.equal(prefixToMask6(128), (1n << 128n) - 1n);

  const zoned = describe6("fe80::1%eth0/64");
  assert.ok(zoned.notes.some((n) => /%eth0/.test(n)));
});
