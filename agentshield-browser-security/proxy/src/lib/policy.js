import crypto from "node:crypto";
import dns from "node:dns/promises";

import ipaddr from "ipaddr.js";

const ALWAYS_BLOCKED_RANGES = new Set([
  "unspecified",
  "broadcast",
  "multicast",
  "linkLocal",
  "reserved",
  "ipv4Mapped",
  "rfc6145",
  "rfc6052",
  "6to4",
  "teredo",
  "benchmarking",
  "amt",
  "as112",
  "deprecatedOrchid",
  "orchid2",
  "droneRemoteIdProtocolEntityTags",
]);

const PRIVATE_RANGES = new Set([
  "loopback",
  "private",
  "carrierGradeNat",
  "uniqueLocal",
]);

const ALWAYS_BLOCKED_ADDRESSES = new Set([
  "169.254.169.254",
  "169.254.170.2",
  "100.100.100.200",
  "fd00:ec2::254",
]);

const RESERVED_HOSTNAMES = new Set([
  "localhost",
  "metadata",
  "instance-data",
  "metadata.google.internal",
  "metadata.azure.com",
]);

const RESERVED_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
  ".lan",
  ".corp",
  ".intranet",
];

const LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const AMBIGUOUS_IP_PATTERNS = [
  /^[0-9]+$/,
  /^0x[0-9a-f]+$/i,
  /^[0-9.]+$/,
  /^0x[0-9a-f.]+$/i,
];

export class EgressPolicyError extends Error {
  constructor(code, message, status = 403) {
    super(message);
    this.name = "EgressPolicyError";
    this.code = code;
    this.status = status;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function normalizeHostname(value) {
  return String(value ?? "")
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

function validatePattern(pattern) {
  const normalized = normalizeHostname(pattern);
  if (!normalized) {
    throw new Error("empty domain policy pattern");
  }
  if (normalized === "*") {
    throw new Error("standalone wildcard is not permitted");
  }
  if (normalized.includes("*") && !normalized.startsWith("*.")) {
    throw new Error(`unsupported wildcard pattern: ${pattern}`);
  }
  if (normalized.startsWith("*.") && normalized.length <= 2) {
    throw new Error(`invalid wildcard pattern: ${pattern}`);
  }
  if (normalized.includes("://") || normalized.includes("/")) {
    throw new Error(`domain policy patterns must be hostnames: ${pattern}`);
  }
  return normalized;
}

function parseDomainList(value) {
  return String(value ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map(validatePattern);
}

function domainMatches(hostname, pattern) {
  const host = normalizeHostname(hostname);
  const rule = normalizeHostname(pattern);
  if (!host || !rule) {
    return false;
  }
  if (rule.startsWith("*.")) {
    return host.endsWith(`.${rule.slice(2)}`);
  }
  return host === rule;
}

export function parsePortSpec(spec) {
  const ranges = [];
  for (const rawPart of String(spec ?? "").split(",")) {
    const part = rawPart.trim();
    if (!part) {
      continue;
    }

    let start;
    let end;
    if (part.includes("-")) {
      const pieces = part.split("-");
      if (
        pieces.length !== 2 ||
        !/^\d+$/.test(pieces[0]) ||
        !/^\d+$/.test(pieces[1])
      ) {
        throw new Error(`invalid port range: ${part}`);
      }
      start = Number.parseInt(pieces[0], 10);
      end = Number.parseInt(pieces[1], 10);
    } else {
      if (!/^\d+$/.test(part)) {
        throw new Error(`invalid port: ${part}`);
      }
      start = end = Number.parseInt(part, 10);
    }

    if (start < 1 || end > 65535 || start > end) {
      throw new Error(`port range out of bounds: ${part}`);
    }
    ranges.push([start, end]);
  }

  if (ranges.length === 0) {
    throw new Error("at least one allowed port is required");
  }
  return ranges;
}

export function isBlockedAddress(address, { allowPrivate = false } = {}) {
  let parsed;
  try {
    parsed = ipaddr.parse(address);
  } catch {
    return true;
  }

  if (parsed.kind() === "ipv6" && parsed.isIPv4MappedAddress()) {
    parsed = parsed.toIPv4Address();
  }

  if (ALWAYS_BLOCKED_ADDRESSES.has(parsed.toString())) {
    return true;
  }

  const range = parsed.range();
  if (PRIVATE_RANGES.has(range)) {
    return !allowPrivate;
  }
  if (ALWAYS_BLOCKED_RANGES.has(range)) {
    return true;
  }
  return range !== "unicast";
}

function validateHostname(hostname) {
  if (!hostname || hostname.length > 253) {
    throw new EgressPolicyError(
      "INVALID_DESTINATION",
      "destination contains an invalid hostname",
    );
  }

  if (ipaddr.isValid(hostname)) {
    return;
  }

  if (AMBIGUOUS_IP_PATTERNS.some((pattern) => pattern.test(hostname))) {
    throw new EgressPolicyError(
      "INVALID_DESTINATION",
      "ambiguous numeric IP representations are not permitted",
    );
  }

  for (const label of hostname.split(".")) {
    if (!label || label.length > 63 || !LABEL_PATTERN.test(label)) {
      throw new EgressPolicyError(
        "INVALID_DESTINATION",
        "destination contains an invalid hostname",
      );
    }
  }
}

function isReservedHostname(hostname) {
  return (
    RESERVED_HOSTNAMES.has(hostname) ||
    RESERVED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
  );
}

export function createEgressPolicy({
  allowedDomains = "",
  blockedDomains = "",
  defaultDomainPolicy = "deny",
  allowedPorts = "80,443",
  allowPrivateNetworks = false,
  resolver = dns.lookup,
  dnsTimeoutMs = 5000,
} = {}) {
  const allowed = parseDomainList(allowedDomains);
  const blocked = parseDomainList(blockedDomains);
  const defaultPolicy = String(defaultDomainPolicy).toLowerCase();
  if (!["allow", "deny"].includes(defaultPolicy)) {
    throw new Error("default domain policy must be 'allow' or 'deny'");
  }
  const portRanges = parsePortSpec(allowedPorts);

  function isPortAllowed(port) {
    return portRanges.some(([start, end]) => start <= port && end >= port);
  }

  function assertDomainAllowed(hostname) {
    if (blocked.some((pattern) => domainMatches(hostname, pattern))) {
      throw new EgressPolicyError(
        "DOMAIN_BLOCKED",
        "the destination domain is blocked by policy",
      );
    }
    if (allowed.some((pattern) => domainMatches(hostname, pattern))) {
      return;
    }
    if (defaultPolicy === "deny") {
      throw new EgressPolicyError(
        "DOMAIN_BLOCKED",
        "the destination domain is not on the allowlist",
      );
    }
  }

  function validateDestination(hostname, port) {
    const normalized = normalizeHostname(hostname);
    validateHostname(normalized);

    if (!ipaddr.isValid(normalized) && isReservedHostname(normalized)) {
      throw new EgressPolicyError(
        "DOMAIN_BLOCKED",
        "the destination hostname is reserved for internal use",
      );
    }

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new EgressPolicyError(
        "INVALID_DESTINATION",
        "destination contains an invalid port",
      );
    }

    if (!isPortAllowed(port)) {
      throw new EgressPolicyError(
        "PORT_NOT_ALLOWED",
        "the destination port is not permitted by policy",
      );
    }

    if (ipaddr.isValid(normalized)) {
      if (isBlockedAddress(normalized, { allowPrivate: allowPrivateNetworks })) {
        throw new EgressPolicyError(
          "PRIVATE_IP_BLOCKED",
          "private or reserved network targets are not permitted",
        );
      }
    }

    assertDomainAllowed(normalized);

    return normalized;
  }

  async function resolveAddresses(hostname) {
    let addresses;
    try {
      const lookupPromise = resolver(hostname, { all: true, verbatim: true });
      const timeoutPromise = new Promise((_, reject) => {
        const timer = setTimeout(
          () => reject(new EgressPolicyError("DNS_TIMEOUT", "DNS resolution timed out")),
          dnsTimeoutMs,
        );
        timer.unref?.();
      });
      addresses = await Promise.race([lookupPromise, timeoutPromise]);
    } catch (error) {
      if (error instanceof EgressPolicyError) {
        throw error;
      }
      throw new EgressPolicyError(
        "DNS_RESOLUTION_FAILED",
        "target hostname could not be resolved",
      );
    }

    if (!Array.isArray(addresses) || addresses.length === 0) {
      throw new EgressPolicyError(
        "DNS_RESOLUTION_FAILED",
        "target hostname could not be resolved",
      );
    }

    return addresses.map((entry) => ({
      address: entry.address,
      family: entry.family,
    }));
  }

  async function resolveDestination(hostname, port) {
    const normalized = validateDestination(hostname, port);

    if (ipaddr.isValid(normalized)) {
      return {
        hostname: normalized,
        port,
        address: normalized,
        family: ipaddr.parse(normalized).kind() === "ipv6" ? 6 : 4,
        addresses: [
          {
            address: normalized,
            family: ipaddr.parse(normalized).kind() === "ipv6" ? 6 : 4,
          },
        ],
      };
    }

    const initialAddresses = await resolveAddresses(normalized);
    for (const entry of initialAddresses) {
      if (isBlockedAddress(entry.address, { allowPrivate: allowPrivateNetworks })) {
        throw new EgressPolicyError(
          "PRIVATE_IP_BLOCKED",
          "private or reserved network targets are not permitted",
        );
      }
    }

    const rebindingCandidates = await resolveAddresses(normalized);
    for (const entry of rebindingCandidates) {
      if (isBlockedAddress(entry.address, { allowPrivate: allowPrivateNetworks })) {
        throw new EgressPolicyError(
          "PRIVATE_IP_BLOCKED",
          "private or reserved network targets are not permitted",
        );
      }
    }

    const selected = initialAddresses[0];
    return {
      hostname: normalized,
      port,
      address: selected.address,
      family: selected.family,
      addresses: initialAddresses.map((entry) => ({
        address: entry.address,
        family: entry.family,
      })),
    };
  }

  return {
    allowPrivateNetworks,
    defaultDomainPolicy,
    dnsTimeoutMs,
    validateDestination,
    resolveDestination,
    isPortAllowed,
  };
}

/**
 * Compute a short deterministic fingerprint of the four canonical policy
 * configuration values.  Every component that loads policy logs this value
 * at startup; operators can compare logs across API, worker and proxy to
 * confirm all three are enforcing identical policy.
 *
 * The fingerprint is the first 16 hex characters of the SHA-256 hash of a
 * stable canonical representation of the policy.
 *
 * @param {{ allowedDomains: string, blockedDomains: string,
 *           defaultDomainPolicy: string, allowedPorts: string }} policy
 * @returns {string} 16-character hex fingerprint
 */
export function computePolicyFingerprint({
  allowedDomains = "",
  blockedDomains = "",
  defaultDomainPolicy = "deny",
  allowedPorts = "80,443",
} = {}) {
  // Canonical form: sort each comma-separated list so order differences in
  // operator-supplied values don't produce spurious fingerprint mismatches.
  const canonicalDomains = String(allowedDomains)
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .sort()
    .join(",");

  const canonicalBlocked = String(blockedDomains)
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .sort()
    .join(",");

  const canonicalPorts = String(allowedPorts)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .sort()
    .join(",");

  const canonical = JSON.stringify({
    allowedDomains: canonicalDomains,
    blockedDomains: canonicalBlocked,
    defaultDomainPolicy: String(defaultDomainPolicy).toLowerCase(),
    allowedPorts: canonicalPorts,
  });

  return crypto.createHash("sha256").update(canonical).digest("hex").slice(0, 16);
}

/**
 * Validate that the policy configuration is safe to use.
 *
 * In production an empty allowedDomains is almost certainly a
 * misconfiguration: with default-deny the service would silently block every
 * navigation request.  We prefer a loud startup failure over silent
 * breakage.
 *
 * @param {{ allowedDomains: string, defaultDomainPolicy: string }} policy
 * @param {{ environment?: string }} options
 * @throws {Error} if the configuration is unsafe
 */
export function validatePolicyConfig(
  { allowedDomains = "", defaultDomainPolicy = "deny" } = {},
  { environment = "development" } = {},
) {
  if (
    environment.toLowerCase() === "production" &&
    defaultDomainPolicy.toLowerCase() !== "allow" &&
    !String(allowedDomains).trim()
  ) {
    throw new Error(
      "POLICY_MISCONFIGURED: ALLOWED_DOMAINS must be set in production when " +
        "DEFAULT_DOMAIN_POLICY is 'deny'. " +
        "An empty allowlist with default-deny blocks every navigation request. " +
        "Set ALLOWED_DOMAINS to the permitted destination domains before deploying.",
    );
  }
}
