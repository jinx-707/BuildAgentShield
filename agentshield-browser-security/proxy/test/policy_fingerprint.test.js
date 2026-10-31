/**
 * Policy fingerprint and cross-component consistency tests.
 *
 * Verifies that:
 *   - computePolicyFingerprint produces stable, deterministic output
 *   - Identical policy values → identical fingerprint (component A == B)
 *   - Different domain/port values → different fingerprint (drift is detectable)
 *   - Canonical form normalises ordering and case
 *   - validatePolicyConfig fails closed in production with empty allowedDomains
 *   - validatePolicyConfig allows production with non-empty allowedDomains
 *   - validatePolicyConfig allows production with defaultDomainPolicy=allow
 *   - createEgressPolicy: allowed domains pass, blocked domains fail,
 *     unlisted domains follow default-deny
 *   - Wildcard matching is consistent with the API's DomainPolicy semantics
 *   - Port restrictions are enforced
 *   - Missing policy (empty allowedDomains) fails closed under default-deny
 *   - Invalid policy (bad port spec) throws at construction
 *   - Redirects cannot bypass domain policy (policy is stateless per-call)
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  EgressPolicyError,
  computePolicyFingerprint,
  createEgressPolicy,
  validatePolicyConfig,
} from "../src/lib/policy.js";

// ---------------------------------------------------------------------------
// computePolicyFingerprint
// ---------------------------------------------------------------------------

test("fingerprint is deterministic for identical inputs", () => {
  const a = computePolicyFingerprint({
    allowedDomains: "example.com,api.example.org",
    blockedDomains: "evil.com",
    defaultDomainPolicy: "deny",
    allowedPorts: "80,443",
  });
  const b = computePolicyFingerprint({
    allowedDomains: "example.com,api.example.org",
    blockedDomains: "evil.com",
    defaultDomainPolicy: "deny",
    allowedPorts: "80,443",
  });
  assert.equal(a, b);
});

test("fingerprint is 16 hex characters", () => {
  const fp = computePolicyFingerprint({
    allowedDomains: "example.com",
    allowedPorts: "443",
  });
  assert.match(fp, /^[0-9a-f]{16}$/);
});

test("different allowedDomains produce different fingerprints", () => {
  const a = computePolicyFingerprint({ allowedDomains: "example.com", allowedPorts: "443" });
  const b = computePolicyFingerprint({ allowedDomains: "other.com", allowedPorts: "443" });
  assert.notEqual(a, b);
});

test("different allowedPorts produce different fingerprints", () => {
  const a = computePolicyFingerprint({ allowedDomains: "example.com", allowedPorts: "80,443" });
  const b = computePolicyFingerprint({ allowedDomains: "example.com", allowedPorts: "443" });
  assert.notEqual(a, b);
});

test("different defaultDomainPolicy produces different fingerprint", () => {
  const a = computePolicyFingerprint({ allowedDomains: "example.com", defaultDomainPolicy: "deny" });
  const b = computePolicyFingerprint({ allowedDomains: "example.com", defaultDomainPolicy: "allow" });
  assert.notEqual(a, b);
});

test("different blockedDomains produce different fingerprints", () => {
  const a = computePolicyFingerprint({ allowedDomains: "example.com", blockedDomains: "" });
  const b = computePolicyFingerprint({ allowedDomains: "example.com", blockedDomains: "evil.com" });
  assert.notEqual(a, b);
});

test("canonical form: domain list order does not affect fingerprint", () => {
  const a = computePolicyFingerprint({
    allowedDomains: "alpha.com,beta.com,gamma.com",
    allowedPorts: "443",
  });
  const b = computePolicyFingerprint({
    allowedDomains: "gamma.com,alpha.com,beta.com",
    allowedPorts: "443",
  });
  assert.equal(a, b, "order of domains in the list must not change fingerprint");
});

test("canonical form: case does not affect fingerprint", () => {
  const a = computePolicyFingerprint({ allowedDomains: "Example.COM", allowedPorts: "443" });
  const b = computePolicyFingerprint({ allowedDomains: "example.com", allowedPorts: "443" });
  assert.equal(a, b, "domain case must not change fingerprint");
});

test("canonical form: port order does not affect fingerprint", () => {
  const a = computePolicyFingerprint({ allowedDomains: "example.com", allowedPorts: "443,80" });
  const b = computePolicyFingerprint({ allowedDomains: "example.com", allowedPorts: "80,443" });
  assert.equal(a, b, "port order must not change fingerprint");
});

test("fingerprint detects drift: one domain added", () => {
  const before = computePolicyFingerprint({
    allowedDomains: "example.com",
    allowedPorts: "443",
  });
  const after = computePolicyFingerprint({
    allowedDomains: "example.com,extra.com",
    allowedPorts: "443",
  });
  assert.notEqual(before, after, "adding a domain must change the fingerprint");
});

// ---------------------------------------------------------------------------
// validatePolicyConfig
// ---------------------------------------------------------------------------

test("validatePolicyConfig: production + empty allowedDomains + deny → throws", () => {
  assert.throws(
    () =>
      validatePolicyConfig(
        { allowedDomains: "", defaultDomainPolicy: "deny" },
        { environment: "production" },
      ),
    (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /POLICY_MISCONFIGURED/);
      return true;
    },
  );
});

test("validatePolicyConfig: production + non-empty allowedDomains → ok", () => {
  assert.doesNotThrow(() =>
    validatePolicyConfig(
      { allowedDomains: "example.com", defaultDomainPolicy: "deny" },
      { environment: "production" },
    ),
  );
});

test("validatePolicyConfig: production + empty allowedDomains + allow default → ok (intentional allow-all)", () => {
  // If the operator explicitly sets defaultDomainPolicy=allow, they know what
  // they are doing.  We warn via health endpoint mode=permissive but do not block.
  assert.doesNotThrow(() =>
    validatePolicyConfig(
      { allowedDomains: "", defaultDomainPolicy: "allow" },
      { environment: "production" },
    ),
  );
});

test("validatePolicyConfig: development + empty allowedDomains → ok", () => {
  assert.doesNotThrow(() =>
    validatePolicyConfig(
      { allowedDomains: "", defaultDomainPolicy: "deny" },
      { environment: "development" },
    ),
  );
});

test("validatePolicyConfig: test + empty allowedDomains → ok", () => {
  assert.doesNotThrow(() =>
    validatePolicyConfig(
      { allowedDomains: "", defaultDomainPolicy: "deny" },
      { environment: "test" },
    ),
  );
});

// ---------------------------------------------------------------------------
// Policy enforcement: allowed / blocked / default-deny
// ---------------------------------------------------------------------------

test("allowed domain is accepted", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  assert.equal(policy.validateDestination("example.com", 443), "example.com");
});

test("blocked domain is rejected even if also on allowlist", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    blockedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "allow",
  });
  assert.throws(
    () => policy.validateDestination("example.com", 443),
    (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
  );
});

test("unlisted domain follows default-deny", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  assert.throws(
    () => policy.validateDestination("unlisted.com", 443),
    (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
  );
});

test("unlisted domain follows default-allow", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "allow",
  });
  // Should not throw
  assert.equal(policy.validateDestination("anything.com", 443), "anything.com");
});

// ---------------------------------------------------------------------------
// Wildcard matching consistency
// ---------------------------------------------------------------------------

test("wildcard *.example.com allows subdomains but not apex", () => {
  const policy = createEgressPolicy({
    allowedDomains: "*.example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  assert.equal(policy.validateDestination("api.example.com", 443), "api.example.com");
  assert.equal(policy.validateDestination("deep.api.example.com", 443), "deep.api.example.com");
  assert.throws(
    () => policy.validateDestination("example.com", 443),
    (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
  );
});

test("exact pattern does not allow subdomains", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  assert.throws(
    () => policy.validateDestination("www.example.com", 443),
    (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
  );
});

test("suffix bypass attempts are rejected", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  for (const host of ["notexample.com", "example.com.evil.test", "attackerexample.com"]) {
    assert.throws(
      () => policy.validateDestination(host, 443),
      (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
      host,
    );
  }
});

// ---------------------------------------------------------------------------
// Port restrictions
// ---------------------------------------------------------------------------

test("port not on allowlist is rejected", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  assert.throws(
    () => policy.validateDestination("example.com", 8080),
    (err) => err instanceof EgressPolicyError && err.code === "PORT_NOT_ALLOWED",
  );
});

test("port range is accepted at boundary values", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "1024-2048",
    defaultDomainPolicy: "deny",
  });
  assert.equal(policy.validateDestination("example.com", 1024), "example.com");
  assert.equal(policy.validateDestination("example.com", 2048), "example.com");
  assert.throws(
    () => policy.validateDestination("example.com", 1023),
    (err) => err instanceof EgressPolicyError && err.code === "PORT_NOT_ALLOWED",
  );
  assert.throws(
    () => policy.validateDestination("example.com", 2049),
    (err) => err instanceof EgressPolicyError && err.code === "PORT_NOT_ALLOWED",
  );
});

// ---------------------------------------------------------------------------
// Missing / invalid policy fails closed
// ---------------------------------------------------------------------------

test("empty allowedDomains with default-deny blocks every domain", () => {
  const policy = createEgressPolicy({
    allowedDomains: "",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });
  assert.throws(
    () => policy.validateDestination("example.com", 443),
    (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
  );
});

test("invalid port spec throws at construction", () => {
  assert.throws(
    () =>
      createEgressPolicy({
        allowedDomains: "example.com",
        allowedPorts: "not-a-port",
        defaultDomainPolicy: "deny",
      }),
    (err) => err instanceof Error && /invalid port/.test(err.message),
  );
});

test("invalid defaultDomainPolicy throws at construction", () => {
  assert.throws(
    () =>
      createEgressPolicy({
        allowedDomains: "example.com",
        allowedPorts: "443",
        defaultDomainPolicy: "maybe",
      }),
    (err) => err instanceof Error && /deny/.test(err.message),
  );
});

// ---------------------------------------------------------------------------
// Redirect bypass resistance
// ---------------------------------------------------------------------------

test("policy is enforced per-call — a redirect to a blocked domain is rejected", () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "443",
    defaultDomainPolicy: "deny",
  });

  // First hop allowed
  assert.equal(policy.validateDestination("example.com", 443), "example.com");

  // Redirect destination not in allowlist → rejected
  assert.throws(
    () => policy.validateDestination("evil.com", 443),
    (err) => err instanceof EgressPolicyError && err.code === "DOMAIN_BLOCKED",
  );
});
