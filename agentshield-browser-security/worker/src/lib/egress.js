import { config } from "../config.js";
import { logger } from "./logger.js";

const DEFAULT_PROXY_HEALTH_PORT = 9090;
const DEFAULT_PROXY_HEALTH_PATH = "/health/ready";

let healthCache = {
  checkedAt: 0,
  ok: false,
  proxy: null,
};

export class EgressProxyError extends Error {
  constructor(code, message, status = 503) {
    super(message);
    this.name = "EgressProxyError";
    this.code = code;
    this.status = status;
  }
}

export function parseEgressProxyUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.trim() === "") {
    throw new EgressProxyError(
      "NETWORK_EGRESS_BLOCKED",
      "the egress proxy is required but not configured",
    );
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new EgressProxyError(
      "EGRESS_PROXY_INVALID",
      "the configured egress proxy URL is invalid",
    );
  }

  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
    throw new EgressProxyError(
      "EGRESS_PROXY_INVALID",
      "the configured egress proxy URL must be an absolute HTTP(S) URL",
    );
  }

  if (parsed.username || parsed.password) {
    throw new EgressProxyError(
      "EGRESS_PROXY_INVALID",
      "egress proxy credentials must not be embedded in the proxy URL",
    );
  }

  return parsed;
}

export function resolveProxyHealthUrl() {
  if (config.egressProxyHealthUrl) {
    return config.egressProxyHealthUrl;
  }

  const proxyUrl = parseEgressProxyUrl(config.egressProxyUrl);
  proxyUrl.protocol = "http:";
  proxyUrl.port = String(DEFAULT_PROXY_HEALTH_PORT);
  proxyUrl.pathname = DEFAULT_PROXY_HEALTH_PATH;
  proxyUrl.search = "";
  proxyUrl.hash = "";
  return proxyUrl.href;
}

export function describeEgressProxy() {
  if (!config.egressProxyUrl) {
    return null;
  }
  try {
    const parsed = parseEgressProxyUrl(config.egressProxyUrl);
    return {
      host: parsed.hostname,
      port: Number.parseInt(parsed.port || "3128", 10),
      protocol: parsed.protocol.replace(":", ""),
    };
  } catch {
    return { invalid: true };
  }
}

function recordHealth(ok, proxy) {
  healthCache = {
    checkedAt: Date.now(),
    ok,
    proxy,
  };
}

export function resetEgressHealthCache() {
  healthCache = { checkedAt: 0, ok: false, proxy: null };
}

async function probeProxyHealth(healthUrl) {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    config.proxyHealthTimeoutMs,
  );

  try {
    const response = await fetch(healthUrl, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal,
    });

    if (!response.ok) {
      return false;
    }

    const body = await response.json().catch(() => null);
    if (!body || body.status !== "ok") {
      return false;
    }
    if (body.mode && body.mode !== "enforcing") {
      return false;
    }
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function assertEgressEnforcement({ force = false } = {}) {
  if (!config.requireEgressProxy) {
    return { required: false, verified: false, proxy: describeEgressProxy() };
  }

  const proxy = describeEgressProxy();
  if (!config.egressProxyUrl) {
    logger.error(
      { event: "egress_policy_violation", reason: "proxy_not_configured" },
      "egress_proxy_unavailable",
    );
    throw new EgressProxyError(
      "NETWORK_EGRESS_BLOCKED",
      "the egress proxy is required but not configured",
    );
  }

  try {
    parseEgressProxyUrl(config.egressProxyUrl);
    resolveProxyHealthUrl();
  } catch (error) {
    logger.error(
      {
        event: "egress_policy_violation",
        reason: "proxy_configuration_invalid",
        proxy,
      },
      "egress_proxy_unavailable",
    );
    if (error instanceof EgressProxyError) {
      throw error;
    }
    throw new EgressProxyError(
      "EGRESS_PROXY_INVALID",
      "the configured egress proxy is invalid",
    );
  }

  const now = Date.now();
  if (
    !force &&
    healthCache.checkedAt > 0 &&
    now - healthCache.checkedAt < config.proxyHealthCacheMs
  ) {
    if (healthCache.ok) {
      return { required: true, verified: true, proxy };
    }
    throw new EgressProxyError(
      "EGRESS_PROXY_UNAVAILABLE",
      "the required egress proxy did not pass its health check",
    );
  }

  const healthUrl = resolveProxyHealthUrl();
  const ok = await probeProxyHealth(healthUrl);
  recordHealth(ok, proxy);

  if (!ok) {
    logger.error(
      {
        event: "egress_policy_violation",
        reason: "proxy_health_check_failed",
        proxy,
      },
      "egress_proxy_unavailable",
    );
    throw new EgressProxyError(
      "EGRESS_PROXY_UNAVAILABLE",
      "the required egress proxy is not reachable or is not enforcing policy",
    );
  }

  logger.info({ event: "egress_proxy_verified", proxy }, "egress_proxy_verified");
  return { required: true, verified: true, proxy };
}

export function getEgressHealthSnapshot() {
  if (!config.requireEgressProxy) {
    return { required: false, status: "optional" };
  }
  if (!config.egressProxyUrl) {
    return { required: true, status: "missing" };
  }
  if (!healthCache.checkedAt) {
    return {
      required: true,
      status: "unchecked",
      proxy: describeEgressProxy(),
    };
  }
  return {
    required: true,
    status: healthCache.ok ? "ok" : "unavailable",
    proxy: healthCache.proxy,
    checked_at: new Date(healthCache.checkedAt).toISOString(),
  };
}
