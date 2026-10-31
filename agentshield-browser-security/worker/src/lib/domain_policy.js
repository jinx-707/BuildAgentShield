export class DomainPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DomainPolicyError";
    this.code = code;
  }
}

function normalizeHostname(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
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

export function parseDomainList(value) {
  return String(value ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map(validatePattern);
}

export function domainMatches(hostname, pattern) {
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

export class DomainPolicy {
  constructor({
    allowedDomains = "",
    blockedDomains = "",
    defaultPolicy = "deny",
  } = {}) {
    this.allowed = parseDomainList(allowedDomains);
    this.blocked = parseDomainList(blockedDomains);
    this.defaultPolicy = String(defaultPolicy).toLowerCase();
    if (!["allow", "deny"].includes(this.defaultPolicy)) {
      throw new Error("default domain policy must be 'allow' or 'deny'");
    }
  }

  evaluate(hostname) {
    if (this.blocked.some((pattern) => domainMatches(hostname, pattern))) {
      throw new DomainPolicyError(
        "DOMAIN_BLOCKED",
        "the destination domain is blocked by policy",
      );
    }

    if (this.allowed.some((pattern) => domainMatches(hostname, pattern))) {
      return;
    }

    if (this.defaultPolicy === "deny") {
      throw new DomainPolicyError(
        "DOMAIN_BLOCKED",
        "the destination domain is not on the allowlist",
      );
    }
  }
}
