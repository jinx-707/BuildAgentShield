import dns from "node:dns/promises";

import ipaddr from "ipaddr.js";

import { config } from "../config.js";
import { DomainPolicy, DomainPolicyError } from "./domain_policy.js";

const MAX_URL_LENGTH = 4096;

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

export class UrlValidationError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "UrlValidationError";
    this.code = code;
    this.status = status;
  }
}

function parsePortSpec(spec) {
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
      if (pieces.length !== 2 || !/^\d+$/.test(pieces[0]) || !/^\d+$/.test(pieces[1])) {
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

const allowedPortRanges = parsePortSpec(config.allowedPorts);
const domainPolicy = new DomainPolicy({
  allowedDomains: config.allowedDomains,
  blockedDomains: config.blockedDomains,
  defaultPolicy: config.defaultDomainPolicy,
});

function isPortAllowed(port) {
  return allowedPortRanges.some(([start, end]) => start <= port && end >= port);
}

function normalizeHostname(hostname) {
  return hostname.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
}

function isBlockedAddress(address, allowPrivate = config.allowPrivateNetworks) {
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
  if (ALWAYS_BLOCKED_RANGES.has(range)) {
    return true;
  }
  if (PRIVATE_RANGES.has(range)) {
    return !allowPrivate;
  }
  return false;
}

function isReservedHostname(hostname) {
  return (
    RESERVED_HOSTNAMES.has(hostname) ||
    RESERVED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
  );
}

function validateHostname(hostname) {
  if (!hostname || hostname.length > 253) {
    throw new UrlValidationError("INVALID_URL", "url contains an invalid hostname");
  }

  if (ipaddr.isValid(hostname)) {
    return;
  }

  if (AMBIGUOUS_IP_PATTERNS.some((pattern) => pattern.test(hostname))) {
    throw new UrlValidationError(
      "INVALID_URL",
      "ambiguous numeric IP representations are not permitted",
    );
  }

  for (const label of hostname.split(".")) {
    if (!label || label.length > 63 || !LABEL_PATTERN.test(label)) {
      throw new UrlValidationError("INVALID_URL", "url contains an invalid hostname");
    }
  }
}

export async function validateNavigationUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.trim() === "") {
    throw new UrlValidationError("INVALID_URL", "url must be a non-empty string");
  }
  if (rawUrl.length > MAX_URL_LENGTH) {
    throw new UrlValidationError("INVALID_URL", "url exceeds the maximum supported length");
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl)) {
    throw new UrlValidationError("INVALID_URL", "url must be an absolute URL");
  }
  if (
    rawUrl.includes("\\") ||
    [...rawUrl].some((character) => {
      const code = character.codePointAt(0);
      return code <= 0x20 || code === 0x7f;
    })
  ) {
    throw new UrlValidationError(
      "INVALID_URL",
      "url contains whitespace or control characters",
    );
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UrlValidationError("INVALID_URL", "url must be an absolute URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new UrlValidationError(
      "URL_SCHEME_NOT_ALLOWED",
      "only http and https URLs are permitted",
    );
  }
  if (
    parsed.username ||
    parsed.password ||
    /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/i.test(rawUrl)
  ) {
    throw new UrlValidationError(
      "INVALID_URL",
      "URLs containing credentials are not permitted",
    );
  }

  const hostname = normalizeHostname(parsed.hostname);
  validateHostname(hostname);

  if (!ipaddr.isValid(hostname) && isReservedHostname(hostname)) {
    throw new UrlValidationError(
      "DOMAIN_BLOCKED",
      "the destination hostname is reserved for internal use",
      403,
    );
  }

  const defaultPort = parsed.protocol === "https:" ? 443 : 80;
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : defaultPort;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new UrlValidationError("INVALID_URL", "url contains an invalid port");
  }
  if (!isPortAllowed(port)) {
    throw new UrlValidationError(
      "PORT_NOT_ALLOWED",
      "the destination port is not permitted by policy",
      403,
    );
  }

  try {
    domainPolicy.evaluate(hostname);
  } catch (error) {
    if (error instanceof DomainPolicyError) {
      throw new UrlValidationError(error.code, error.message, 403);
    }
    throw error;
  }

  if (ipaddr.isValid(hostname)) {
    if (isBlockedAddress(hostname)) {
      throw new UrlValidationError(
        "PRIVATE_IP_BLOCKED",
        "private or reserved network targets are not permitted",
        403,
      );
    }
    return parsed;
  }

  if (config.allowPrivateNetworks) {
    return parsed;
  }

  let addresses;
  try {
    const lookupPromise = dns.lookup(hostname, { all: true, verbatim: true });
    const timeoutPromise = new Promise((_, reject) => {
      const timer = setTimeout(
        () => reject(new UrlValidationError("DNS_RESOLUTION_FAILED", "DNS resolution timed out", 403)),
        5000,
      );
      timer.unref?.();
    });
    addresses = await Promise.race([lookupPromise, timeoutPromise]);
  } catch (error) {
    if (error instanceof UrlValidationError) {
      throw error;
    }
    throw new UrlValidationError(
      "DNS_RESOLUTION_FAILED",
      "target hostname could not be resolved",
      403,
    );
  }

  if (addresses.length === 0) {
    throw new UrlValidationError(
      "DNS_RESOLUTION_FAILED",
      "target hostname could not be resolved",
      403,
    );
  }

  if (addresses.some((entry) => isBlockedAddress(entry.address))) {
    throw new UrlValidationError(
      "PRIVATE_IP_BLOCKED",
      "private or reserved network targets are not permitted",
      403,
    );
  }

  return parsed;
}

export { isBlockedAddress };
