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

function readNonNegativeInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function readString(value, fallback = "") {
  return value === undefined || value === null ? fallback : String(value);
}

// Largest `timeout_ms` a caller may ask for on POST /v1/navigate. A browser
// context is checked out for exactly as long as one request may legitimately
// hold it, so the session lease ceiling has to clear this value: the config
// file is the single source of truth and navigate.js reads it back from here.
const NAVIGATION_TIMEOUT_MAX_MS = 60000;

// D1/D2 requests are also bounded by the session lease ceiling.
const ACTION_TIMEOUT_MAX_MS = 60000;
const SCREENSHOT_TIMEOUT_MAX_MS = 60000;

// Slack for everything a request does outside page.goto() — context creation,
// security installation, content extraction, response serialisation.
const LEASE_GRACE_MS = 10000;

// Sweeping faster than this burns CPU without reaping anything sooner;
// sweeping slower than the idle timeout would let contexts sit expired.
const MIN_CLEANUP_INTERVAL_MS = 1000;

/**
 * Session timing warnings collected while resolving the settings below.
 * Consumed by index.js, which logs them at startup: a clamped or rejected
 * value must never be silently swallowed.
 * @type {string[]}
 */
const sessionTimingWarnings = [];

/**
 * Resolve a millisecond setting, rejecting or clamping values that would make
 * session lifecycle management unsafe.
 */
function resolveTimingMs(raw, { name, fallback, min, max }) {
  if (raw === undefined || raw === "") {
    return fallback;
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    sessionTimingWarnings.push(
      `${name}="${raw}" is not a positive number of milliseconds; using ${fallback}ms`,
    );
    return fallback;
  }

  if (min !== undefined && parsed < min) {
    sessionTimingWarnings.push(
      `${name}=${parsed}ms is below the safe minimum; clamped to ${min}ms`,
    );
    return min;
  }

  if (max !== undefined && parsed > max) {
    sessionTimingWarnings.push(
      `${name}=${parsed}ms is above the safe maximum; clamped to ${max}ms`,
    );
    return max;
  }

  return parsed;
}

const sessionIdleTimeoutMs = resolveTimingMs(
  process.env.BROWSER_SESSION_IDLE_TIMEOUT_MS,
  { name: "BROWSER_SESSION_IDLE_TIMEOUT_MS", fallback: 300000 },
);

// A released (idle) context is reaped once it has been unused for
// sessionIdleTimeoutMs, so sweeping less often than that is enough to honour
// the promise; anything slower would silently extend session lifetime.
const sessionCleanupIntervalMs = resolveTimingMs(
  process.env.BROWSER_SESSION_CLEANUP_INTERVAL_MS,
  {
    name: "BROWSER_SESSION_CLEANUP_INTERVAL_MS",
    fallback: 30000,
    min: MIN_CLEANUP_INTERVAL_MS,
    max: sessionIdleTimeoutMs,
  },
);

// Lease ceiling, not an idle timeout: the longest a single request may hold a
// context before the sweeper is allowed to reclaim it as stranded. It is
// floored above the largest navigation timeout the API accepts, so a checked
// out context can never be reaped while its request is still in budget — even
// if an operator sets the idle timeout to an aggressive value.
const sessionMaxLeaseMs = resolveTimingMs(
  process.env.BROWSER_SESSION_MAX_LEASE_MS,
  {
    name: "BROWSER_SESSION_MAX_LEASE_MS",
    fallback: 120000,
    min:
      Math.max(
        readPositiveInteger(process.env.BROWSER_NAVIGATION_TIMEOUT_MS, 20000),
        NAVIGATION_TIMEOUT_MAX_MS,
        ACTION_TIMEOUT_MAX_MS,
        SCREENSHOT_TIMEOUT_MAX_MS,
      ) + LEASE_GRACE_MS,
  },
);

const sessionMaxAgeMs = resolveTimingMs(process.env.BROWSER_SESSION_MAX_AGE_MS, {
  name: "BROWSER_SESSION_MAX_AGE_MS",
  fallback: 900000,
  min: 60000,
  max: 4 * 60 * 60 * 1000,
});

// B1 — extraction output ceilings. A page of any size can be reduced to a
// bounded amount of text and a bounded number of link records.
const maxExtractionTextBytes = readPositiveInteger(
  process.env.BROWSER_MAX_EXTRACTION_TEXT_BYTES,
  131072,
);

const maxExtractionLinks = readPositiveInteger(
  process.env.BROWSER_MAX_EXTRACTION_LINKS,
  100,
);

// D1 — browser action bounds. The worker validates every value again even
// though the API also validates it; the worker is the last line of defence.
const actionTimeoutMs = readPositiveInteger(
  process.env.BROWSER_ACTION_TIMEOUT_MS,
  10000,
);
const actionMaxTypeBytes = readPositiveInteger(
  process.env.BROWSER_ACTION_MAX_TYPE_BYTES,
  4000,
);
const actionMaxScrollPx = readPositiveInteger(
  process.env.BROWSER_ACTION_MAX_SCROLL_PX,
  5000,
);
const actionMaxTextBytes = readPositiveInteger(
  process.env.BROWSER_ACTION_MAX_TEXT_BYTES,
  8192,
);

// D2 — screenshot bounds. Images are returned as in-memory buffers only; the
// worker never writes caller-visible files and never exposes a path.
const screenshotTimeoutMs = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_TIMEOUT_MS,
  10000,
);
const screenshotMaxWidth = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_MAX_WIDTH,
  2048,
);
const screenshotMaxHeight = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_MAX_HEIGHT,
  2048,
);
const screenshotMaxFullPageHeight = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT,
  12000,
);
const screenshotMaxBytes = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_MAX_BYTES,
  5 * 1024 * 1024,
);
const screenshotMaxConcurrent = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_MAX_CONCURRENT,
  2,
);
const screenshotRateLimitPerMinute = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE,
  20,
);
const screenshotMaxPerSession = readPositiveInteger(
  process.env.BROWSER_SCREENSHOT_MAX_PER_SESSION,
  100,
);

export const config = {
  version: "0.1.0",
  serviceName: "agentshield-browser-worker",
  environment:
    process.env.ENVIRONMENT || process.env.NODE_ENV || "development",
  host: process.env.WORKER_HOST || "127.0.0.1",
  port: readPositiveInteger(process.env.WORKER_PORT, 8080),
  logLevel: process.env.LOG_LEVEL || "info",
  browserExecutablePath: process.env.BROWSER_EXECUTABLE_PATH || undefined,
  headless: readBoolean(process.env.BROWSER_HEADLESS, true),
  navigationTimeoutMs: readPositiveInteger(
    process.env.BROWSER_NAVIGATION_TIMEOUT_MS,
    20000,
  ),
  maxContentBytes: readPositiveInteger(
    process.env.BROWSER_MAX_CONTENT_BYTES,
    524288,
  ),
  allowPrivateNetworks: readBoolean(
    process.env.BROWSER_ALLOW_PRIVATE_NETWORKS,
    false,
  ),
  allowedDomains: readString(process.env.ALLOWED_DOMAINS),
  blockedDomains: readString(process.env.BLOCKED_DOMAINS),
  defaultDomainPolicy: readString(process.env.DEFAULT_DOMAIN_POLICY, "deny"),
  allowedPorts: readString(process.env.ALLOWED_PORTS, "80,443"),
  maxRedirects: readNonNegativeInteger(process.env.MAX_REDIRECTS, 5),
  blockHttpsDowngrade: readBoolean(
    process.env.BLOCK_HTTPS_DOWNGRADE,
    true,
  ),
  egressProxyUrl: readString(process.env.EGRESS_PROXY_URL),
  egressProxyHealthUrl: readString(process.env.EGRESS_PROXY_HEALTH_URL),
  proxyAuthToken: readString(process.env.PROXY_AUTH_TOKEN),
  requireEgressProxy: readBoolean(process.env.REQUIRE_EGRESS_PROXY, true),
  proxyHealthTimeoutMs: readPositiveInteger(
    process.env.EGRESS_PROXY_HEALTH_TIMEOUT_MS,
    3000,
  ),
  proxyHealthCacheMs: readPositiveInteger(
    process.env.EGRESS_PROXY_HEALTH_CACHE_MS,
    5000,
  ),
  allowWebrtc: readBoolean(process.env.BROWSER_ALLOW_WEBRTC, false),
  sessionIdleTimeoutMs,
  // Absolute lifetime of a persistent browser session: no session survives past
  // `createdAt + sessionMaxAgeMs`, however recently it was used.
  sessionMaxAgeMs,
  // Concurrent persistent sessions. Separate from maxConcurrentContexts because
  // a session holds its context between requests and so is the scarcer resource.
  maxSessions: readPositiveInteger(process.env.BROWSER_MAX_SESSIONS, 5),
  // How often the background expiration sweep runs. Reuses the existing
  // sessionIdleTimeoutMs / maxConcurrentContexts lifecycle — this only
  // controls the cadence, independent of any HTTP request.
  sessionCleanupIntervalMs,
  sessionMaxLeaseMs,
  navigationTimeoutMaxMs: NAVIGATION_TIMEOUT_MAX_MS,
  maxExtractionTextBytes,
  maxExtractionLinks,
  actionTimeoutMs,
  actionTimeoutMaxMs: ACTION_TIMEOUT_MAX_MS,
  actionMaxTypeBytes,
  actionMaxScrollPx,
  actionMaxTextBytes,
  screenshotTimeoutMs,
  screenshotTimeoutMaxMs: SCREENSHOT_TIMEOUT_MAX_MS,
  screenshotMaxWidth,
  screenshotMaxHeight,
  screenshotMaxFullPageHeight,
  screenshotMaxBytes,
  screenshotMaxConcurrent,
  screenshotRateLimitPerMinute,
  screenshotMaxPerSession,
  sessionTimingWarnings,
  maxConcurrentContexts: readPositiveInteger(
    process.env.BROWSER_MAX_CONCURRENT_CONTEXTS,
    10,
  ),
  workerAuthToken: readString(process.env.WORKER_AUTH_TOKEN),
};
