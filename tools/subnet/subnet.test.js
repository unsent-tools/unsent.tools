import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseIPv4,
  ipv4ToString,
  prefixToMask,
  maskToPrefix,
  parseCIDR,
  subnetInfo,
  isPrivateIPv4,
  describe,
} from "./subnet.js";

test("parseIPv4 round-trips valid addresses", () => {
  for (const s of ["0.0.0.0", "255.255.255.255", "192.168.1.1", "10.0.0.0", "8.8.8.8"]) {
    assert.equal(ipv4ToString(parseIPv4(s)), s);
  }
  assert.equal(parseIPv4("0.0.0.0"), 0);
  assert.equal(parseIPv4("255.255.255.255"), 0xffffffff);
  assert.equal(parseIPv4("1.2.3.4"), 0x01020304);
  assert.equal(parseIPv4("  192.168.0.1  "), parseIPv4("192.168.0.1"));
});

test("parseIPv4 rejects malformed input", () => {
  for (const bad of [
    "1.2.3", "1.2.3.4.5", "256.0.0.1", "1.2.3.300",
    "192.168.01.1", "01.2.3.4", "a.b.c.d", "1.2.3.-1",
    "1.2.3.", ".1.2.3", "", "1.2.3.4/24",
  ]) {
    assert.throws(() => parseIPv4(bad), undefined, `should reject "${bad}"`);
  }
  // "0" alone as an octet is fine; a leading zero on a multi-digit octet is not.
  assert.doesNotThrow(() => parseIPv4("0.0.0.0"));
});

test("ipv4ToString rejects out-of-range values", () => {
  assert.throws(() => ipv4ToString(-1));
  assert.throws(() => ipv4ToString(0x100000000));
  assert.throws(() => ipv4ToString(1.5));
});

test("prefixToMask covers boundaries", () => {
  assert.equal(ipv4ToString(prefixToMask(0)), "0.0.0.0");
  assert.equal(ipv4ToString(prefixToMask(8)), "255.0.0.0");
  assert.equal(ipv4ToString(prefixToMask(24)), "255.255.255.0");
  assert.equal(ipv4ToString(prefixToMask(30)), "255.255.255.252");
  assert.equal(ipv4ToString(prefixToMask(32)), "255.255.255.255");
  assert.throws(() => prefixToMask(-1));
  assert.throws(() => prefixToMask(33));
});

test("maskToPrefix inverts prefixToMask for every prefix", () => {
  for (let p = 0; p <= 32; p++) {
    assert.equal(maskToPrefix(prefixToMask(p)), p, `prefix ${p}`);
  }
});

test("maskToPrefix rejects non-contiguous masks", () => {
  assert.throws(() => maskToPrefix(parseIPv4("255.0.255.0")));
  assert.throws(() => maskToPrefix(parseIPv4("255.255.0.255")));
  assert.throws(() => maskToPrefix(parseIPv4("0.255.255.255")));
});

test("parseCIDR handles slash prefix, bare address, and dotted mask", () => {
  assert.deepEqual(parseCIDR("192.168.1.0/24"), { address: parseIPv4("192.168.1.0"), prefix: 24 });
  assert.deepEqual(parseCIDR("10.0.0.5"), { address: parseIPv4("10.0.0.5"), prefix: 32 });
  assert.deepEqual(parseCIDR("10.0.0.0/255.0.0.0"), { address: parseIPv4("10.0.0.0"), prefix: 8 });
  assert.throws(() => parseCIDR("10.0.0.0/33"));
  assert.throws(() => parseCIDR("10.0.0.0/x"));
});

test("subnetInfo: standard /24", () => {
  const r = describe("192.168.1.10/24");
  assert.equal(r.network, "192.168.1.0");
  assert.equal(r.broadcast, "192.168.1.255");
  assert.equal(r.netmask, "255.255.255.0");
  assert.equal(r.wildcard, "0.0.0.255");
  assert.equal(r.firstHost, "192.168.1.1");
  assert.equal(r.lastHost, "192.168.1.254");
  assert.equal(r.totalAddresses, 256);
  assert.equal(r.usableHosts, 254);
  assert.equal(r.isPrivate, true);
});

test("subnetInfo: /30 point-to-multipoint has 2 usable hosts", () => {
  const r = describe("192.0.2.4/30");
  assert.equal(r.network, "192.0.2.4");
  assert.equal(r.broadcast, "192.0.2.7");
  assert.equal(r.firstHost, "192.0.2.5");
  assert.equal(r.lastHost, "192.0.2.6");
  assert.equal(r.totalAddresses, 4);
  assert.equal(r.usableHosts, 2);
  assert.equal(r.isPrivate, false);
});

test("subnetInfo: /31 (RFC 3021) has 2 usable hosts and no separate broadcast", () => {
  const r = describe("192.0.2.0/31");
  assert.equal(r.network, "192.0.2.0");
  assert.equal(r.broadcast, "192.0.2.1");
  assert.equal(r.firstHost, "192.0.2.0");
  assert.equal(r.lastHost, "192.0.2.1");
  assert.equal(r.totalAddresses, 2);
  assert.equal(r.usableHosts, 2);
});

test("subnetInfo: /32 is a single host", () => {
  const r = describe("203.0.113.7/32");
  assert.equal(r.network, "203.0.113.7");
  assert.equal(r.broadcast, "203.0.113.7");
  assert.equal(r.firstHost, "203.0.113.7");
  assert.equal(r.lastHost, "203.0.113.7");
  assert.equal(r.totalAddresses, 1);
  assert.equal(r.usableHosts, 1);
});

test("subnetInfo: /0 is the whole address space", () => {
  const r = describe("0.0.0.0/0");
  assert.equal(r.network, "0.0.0.0");
  assert.equal(r.broadcast, "255.255.255.255");
  assert.equal(r.netmask, "0.0.0.0");
  assert.equal(r.wildcard, "255.255.255.255");
  assert.equal(r.totalAddresses, 2 ** 32);
  assert.equal(r.usableHosts, 2 ** 32 - 2);
});

test("subnetInfo: host bits are masked off to find the network", () => {
  const r = describe("172.16.5.130/20");
  assert.equal(r.network, "172.16.0.0");
  assert.equal(r.broadcast, "172.16.15.255");
  assert.equal(r.isPrivate, true);
});

test("isPrivateIPv4 matches RFC 1918 and rejects public", () => {
  for (const p of ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.100.5"]) {
    assert.equal(isPrivateIPv4(parseIPv4(p)), true, p);
  }
  for (const pub of ["8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.0.1", "1.1.1.1"]) {
    assert.equal(isPrivateIPv4(parseIPv4(pub)), false, pub);
  }
});
