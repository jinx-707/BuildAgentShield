import assert from "node:assert/strict";
import test from "node:test";

import {
  EgressPolicyError,
  createEgressPolicy,
  isBlockedAddress,
} from "../src/lib/policy.js";

test("blocks loopback, private, link-local, metadata and special-use addresses", () => {
  for (const address of [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.10",
    "169.254.169.254",
    "100.100.100.200",
    "::1",
    "fd00:ec2::254",
    "fe80::1",
    "2001:2::1",
    "2001:10::1",
    "::ffff:127.0.0.1",
  ]) {
    assert.equal(isBlockedAddress(address), true, address);
  }
});

test("allows public unicast addresses", () => {
  assert.equal(isBlockedAddress("1.1.1.1"), false);
  assert.equal(isBlockedAddress("2606:4700:4700::1111"), false);
});

test("allows private addresses only when explicitly configured", () => {
  assert.equal(isBlockedAddress("127.0.0.1", { allowPrivate: true }), false);
  assert.equal(isBlockedAddress("169.254.169.254", { allowPrivate: true }), true);
});

test("enforces domain and port policy at connection time", async () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com,*.example.org",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });

  assert.equal(policy.validateDestination("example.com", 443), "example.com");
  assert.equal(
    policy.validateDestination("api.example.org", 443),
    "api.example.org",
  );

  assert.throws(
    () => policy.validateDestination("blocked.example.net", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );
  assert.throws(
    () => policy.validateDestination("example.com", 8443),
    (error) => error instanceof EgressPolicyError && error.code === "PORT_NOT_ALLOWED",
  );
  assert.throws(
    () => policy.validateDestination("127.0.0.1", 443),
    (error) => error instanceof EgressPolicyError && error.code === "PRIVATE_IP_BLOCKED",
  );
});

test("rejects a DNS answer that changes from public to private at connect time", async () => {
  let calls = 0;
  const resolver = async () => {
    calls += 1;
    if (calls === 1) {
      return [{ address: "93.184.216.34", family: 4 }];
    }
    return [{ address: "127.0.0.1", family: 4 }];
  };

  const policy = createEgressPolicy({
    allowedDomains: "rebind.example",
    allowedPorts: "443",
    resolver,
  });

  assert.equal(policy.validateDestination("rebind.example", 443), "rebind.example");

  await assert.rejects(
    () => policy.resolveDestination("rebind.example", 443),
    (error) =>
      error instanceof EgressPolicyError && error.code === "PRIVATE_IP_BLOCKED",
  );
});

test("rejects a mixed DNS answer when any address is private", async () => {
  const policy = createEgressPolicy({
    allowedDomains: "mixed.example",
    allowedPorts: "443",
    resolver: async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.7", family: 4 },
    ],
  });

  await assert.rejects(
    () => policy.resolveDestination("mixed.example", 443),
    (error) =>
      error instanceof EgressPolicyError && error.code === "PRIVATE_IP_BLOCKED",
  );
});

test("applies DNS timeout when resolution hangs", async () => {
  const resolver = () =>
    new Promise(() => {}); // never resolves

  const policy = createEgressPolicy({
    allowedDomains: "slow.example",
    allowedPorts: "443",
    resolver,
    dnsTimeoutMs: 50,
  });

  await assert.rejects(
    () => policy.resolveDestination("slow.example", 443),
    (error) =>
      error instanceof EgressPolicyError && error.code === "DNS_TIMEOUT",
  );
});

test("domain matching does not allow suffix bypass", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "80,443",
    defaultDomainPolicy: "deny",
  });

  // Exact match allowed
  assert.equal(policy.validateDestination("example.com", 443), "example.com");

  // Subdomain NOT allowed with exact pattern (only *.suffix allows subdomains)
  assert.throws(
    () => policy.validateDestination("www.example.com", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );

  // Suffix bypass attempts blocked
  assert.throws(
    () => policy.validateDestination("notexample.com", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );
  assert.throws(
    () => policy.validateDestination("example.com.attacker.test", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );
  assert.throws(
    () => policy.validateDestination("attackerexample.com", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );
});

test("wildcard subdomain matching allows proper subdomains but not apex", () => {
  const policy = createEgressPolicy({
    allowedDomains: "*.example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });

  // Subdomain allowed
  assert.equal(policy.validateDestination("www.example.com", 443), "www.example.com");
  assert.equal(policy.validateDestination("api.example.com", 443), "api.example.com");
  assert.equal(policy.validateDestination("deep.api.example.com", 443), "deep.api.example.com");

  // Apex NOT allowed with *.suffix
  assert.throws(
    () => policy.validateDestination("example.com", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );

  // Similar but different domain blocked
  assert.throws(
    () => policy.validateDestination("notexample.com", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );
});

test("normalizes hostname case and trailing dots", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });

  assert.equal(policy.validateDestination("EXAMPLE.COM", 443), "example.com");
  assert.equal(policy.validateDestination("example.com.", 443), "example.com");
  assert.equal(policy.validateDestination("Example.Com", 443), "example.com");
});

test("blocked domains take precedence over allowed domains", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    blockedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "allow",
  });

  assert.throws(
    () => policy.validateDestination("example.com", 443),
    (error) => error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
  );
});

test("reserved hostnames are blocked even when allowlisted", () => {
  const policy = createEgressPolicy({
    allowedDomains: "localhost,*.local,metadata.google.internal",
    allowedPorts: "80,443",
    defaultDomainPolicy: "allow",
  });

  for (const hostname of ["localhost", "foo.local", "metadata.google.internal"]) {
    assert.throws(
      () => policy.validateDestination(hostname, 443),
      (error) =>
        error instanceof EgressPolicyError && error.code === "DOMAIN_BLOCKED",
      hostname,
    );
  }
});

test("blocks IPv4-mapped IPv6 addresses", () => {
  assert.equal(isBlockedAddress("::ffff:127.0.0.1"), true);
  assert.equal(isBlockedAddress("::ffff:169.254.169.254"), true);
  assert.equal(isBlockedAddress("::ffff:10.0.0.1"), true);
});

test("blocks cloud metadata and special-use IPv6 addresses", () => {
  for (const address of [
    "fd00:ec2::254",
    "2001:2::1",
    "2001:10::1",
    "ff00::1",
    "::",
  ]) {
    assert.equal(isBlockedAddress(address), true, address);
  }
});

test("rejects ambiguous numeric IP forms", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "80,443",
    defaultDomainPolicy: "allow",
  });

  // These forms are blocked either as INVALID_DESTINATION (if ipaddr.js
  // can't parse them) or as PRIVATE_IP_BLOCKED (if ipaddr.js parses them
  // as a private address like 127.0.0.1). Both outcomes are correct —
  // the important property is that the form is rejected.
  for (const hostname of ["2130706433", "0x7f000001", "017700000001"]) {
    assert.throws(
      () => policy.validateDestination(hostname, 80),
      (error) =>
        error instanceof EgressPolicyError &&
        ["INVALID_DESTINATION", "PRIVATE_IP_BLOCKED"].includes(error.code),
      hostname,
    );
  }
});
