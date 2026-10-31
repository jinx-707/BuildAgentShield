function readBoolean(value, fallback) {
  if (value === undefined || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function readPositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function readString(value, fallback = "") {
  return value === undefined || value === null ? fallback : String(value);
}

export const config = {
  version: "0.1.0",
  serviceName: "agentshield-egress-proxy",
  host: process.env.PROXY_HOST || "0.0.0.0",
  port: readPositiveInteger(process.env.PROXY_PORT, 3128),
  healthHost: process.env.PROXY_HEALTH_HOST || "0.0.0.0",
  healthPort: readPositiveInteger(process.env.PROXY_HEALTH_PORT, 9090),
  logLevel: process.env.PROXY_LOG_LEVEL || process.env.LOG_LEVEL || "info",
  authToken: readString(process.env.PROXY_AUTH_TOKEN),
  allowedDomains: readString(
    process.env.PROXY_ALLOWED_DOMAINS ?? process.env.ALLOWED_DOMAINS,
  ),
  blockedDomains: readString(
    process.env.PROXY_BLOCKED_DOMAINS ?? process.env.BLOCKED_DOMAINS,
  ),
  defaultDomainPolicy: readString(
    process.env.PROXY_DEFAULT_DOMAIN_POLICY ??
      process.env.DEFAULT_DOMAIN_POLICY,
    "deny",
  ),
  allowedPorts: readString(
    process.env.PROXY_ALLOWED_PORTS ?? process.env.ALLOWED_PORTS,
    "80,443",
  ),
  allowPrivateNetworks: readBoolean(
    process.env.PROXY_ALLOW_PRIVATE_NETWORKS,
    false,
  ),
  dnsTimeoutMs: readPositiveInteger(process.env.PROXY_DNS_TIMEOUT_MS, 5000),
  connectTimeoutMs: readPositiveInteger(
    process.env.PROXY_CONNECT_TIMEOUT_MS,
    10000,
  ),
};
