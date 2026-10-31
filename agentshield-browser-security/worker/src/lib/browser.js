import { randomUUID, timingSafeEqual } from "node:crypto";

import puppeteer from "puppeteer";

import { config } from "../config.js";
import {
  EgressProxyError,
  assertEgressEnforcement,
  describeEgressProxy,
} from "./egress.js";
import { logger } from "./logger.js";
import { installPageSecurity } from "./page_security.js";

let browserPromise = null;
let browserInstance = null;
const openContexts = new Map();

// Registered persistent sessions: sessionId -> contextId. The session state
// itself lives on the `openContexts` entry, so one map owns browser resources
// and one sweeper reaps both ephemeral contexts and expired sessions.
const sessions = new Map();


// Re-entrancy guard for closeExpiredContexts. Both the background timer and
// the /health/ready handler call the same cleanup function; this flag ensures
// a second run that overlaps an in-progress one is skipped instead of racing
// on the same context.close() call.
let cleanupInProgress = false;

/**
 * Lifecycle states of a registered browser context.
 *
 * INITIALIZING — registered, but its page is still being built. Invisible to
 *                  expiration: reaping it would race puppeteer mid-setup.
 * CHECKED_OUT  — a request owns the context. Expiration must not touch it
 *                  until the lease lapses.
 * IDLE         — released by its request and eligible for expiration once the
 *                  idle timeout lapses.
 * CLOSING      — close has been initiated. Terminal; nothing else closes it.
 */
export const CONTEXT_STATE = Object.freeze({
  INITIALIZING: "initializing",
  CHECKED_OUT: "checked_out",
  IDLE: "idle",
  CLOSING: "closing",
});

/**
 * Initiate the close of one context and retire its registration.
 *
 * The state flip and the map removal happen synchronously, before the first
 * await, so no other caller can observe or act on the context between the
 * decision to close it and the close actually starting.
 *
 * A retired context also leaves the session registry: a session id must never
 * outlive the browser context behind it, otherwise checkout would hand back a
 * dead page.
 */
async function retireContext(contexts, contextId, entry, failureEvent) {
  entry.state = CONTEXT_STATE.CLOSING;
  if (contexts.get(contextId) === entry) {
    contexts.delete(contextId);
  }
  if (entry.sessionId && sessions.get(entry.sessionId) === contextId) {
    sessions.delete(entry.sessionId);
  }
  entry.leases = 0;
  await entry.context.close().catch((error) => {
    logger.warn({ err: error, context_id: contextId }, failureEvent);
  });
}

/**
 * Decide whether the expiration sweep may reclaim `entry` at `now`.
 *
 * @param {object} entry
 * @param {number} now
 * @param {number} idleTimeoutMs
 * @returns {boolean} true when the context is eligible to be closed.
 */
function isReapable(entry, now, idleTimeoutMs) {
  // A registered session that its owner asked to close is retired as soon as it
  // is no longer in use; a checked-out one waits for its lease to be released.
  if (entry.closingRequested && entry.state !== CONTEXT_STATE.CHECKED_OUT) {
    return true;
  }

  switch (entry.state) {
    case CONTEXT_STATE.IDLE:
      // Absolute lifetime wins over idleness: no session may survive its
      // `expiresAt`, however recently it was used.
      if (Number.isFinite(entry.expiresAt) && now >= entry.expiresAt) {
        return true;
      }
      return now - entry.lastUsedAt > (entry.idleTimeoutMs ?? idleTimeoutMs);
    case CONTEXT_STATE.CHECKED_OUT:
      // Only a stranded lease — a request that died without releasing — may be
      // reclaimed. The ceiling is floored above the largest navigation timeout,
      // so an in-budget request is never in this branch.
      return (
        Number.isFinite(entry.leaseExpiresAt) && entry.leaseExpiresAt <= now
      );
    default:
      // INITIALIZING and CLOSING are never reaped.
      return false;
  }
}

export class ContextLimitExceededError extends Error {
  constructor(max) {
    super(`maximum concurrent browser contexts (${max}) exceeded`);
    this.name = "ContextLimitExceededError";
    this.code = "MAX_CONTEXTS_EXCEEDED";
    this.status = 503;
  }
}

/**
 * A3 session errors. Each carries a stable code and an HTTP status, and none of
 * them include a session id in the message: the id is the capability secret of
 * the session and must not reach a log or an error body.
 */
export class SessionNotFoundError extends Error {
  constructor() {
    super("session not found");
    this.name = "SessionNotFoundError";
    this.code = "SESSION_NOT_FOUND";
    this.status = 404;
  }
}

export class SessionForbiddenError extends Error {
  constructor() {
    super("session owner does not match the authenticated caller");
    this.name = "SessionForbiddenError";
    this.code = "SESSION_FORBIDDEN";
    this.status = 403;
  }
}

export class SessionBusyError extends Error {
  constructor(code = "SESSION_CHECKED_OUT", message) {
    super(message ?? "session is already handling another request");
    this.name = "SessionBusyError";
    this.code = code;
    this.status = 409;
  }
}

export class SessionLimitExceededError extends Error {
  constructor(max) {
    super(`maximum concurrent browser sessions (${max}) exceeded`);
    this.name = "SessionLimitExceededError";
    this.code = "MAX_SESSIONS_EXCEEDED";
    this.status = 503;
  }
}

/**
 * Timing-safe owner comparison. The owner strings are caller-influenced, so the
 * comparison never short-circuits on a common prefix.
 */
function ownerMatches(supplied, expected) {
  if (typeof supplied !== "string" || typeof expected !== "string") {
    return false;
  }
  const a = Buffer.from(supplied, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

const DISABLED_FEATURES = [
  "Prerender",
  "Prerender2",
  "SpeculationRules",
  "SpeculationRulesPrefetch",
  "SpeculationRulesPrerender",
  "SpeculationRulesPrefetchProxy",
  "NetworkPrediction",
  "PreconnectToSearch",
  "PreconnectToSearchInLoggedIn",
  "Translate",
  "OptimizationHints",
  "MediaRouter",
  "AutofillServerCommunication",
  "InterestFeedContentSuggestions",
  "ServiceWorkerBackgroundSync",
  "BackgroundFetch",
  "WebRtcAllowInputVolumeAdjustment",
  "WebRtcHideLocalIpsWithMdns",
  "SafetyCheckUnusedSitePermissions",
  "SegmentationPlatform",
  "OptimizationGuideModelDownloading",
  "OptimizationGuideOnDeviceModel",
].join(",");

function proxyHostname() {
  if (!config.egressProxyUrl) {
    return null;
  }
  try {
    return new URL(config.egressProxyUrl).hostname;
  } catch {
    return null;
  }
}

function buildLaunchOptions() {
  const args = [
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-plugins",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-features=" + DISABLED_FEATURES,
    "--disable-hang-monitor",
    "--disable-notifications",
    "--disable-prompt-on-repost",
    "--disable-quic",
    "--disable-save-password-bubble",
    "--disable-sync",
    "--disable-translate",
    "--deny-permission-prompts",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-default-browser-check",
    "--no-first-run",
    "--no-pings",
    "--password-store=basic",
    "--safebrowsing-disable-auto-update",
    "--use-mock-keychain",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--no-sandbox",
    "--disable-setuid-sandbox",
  ];

  if (!config.allowWebrtc) {
    args.push("--disable-webrtc");
  }

  if (config.egressProxyUrl) {
    args.push(
      `--proxy-server=${config.egressProxyUrl}`,
      "--proxy-bypass-list=<-loopback>",
    );

    const host = proxyHostname();
    if (host) {
      args.push(`--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE ${host}`);
    }
  } else if (config.requireEgressProxy) {
    args.push("--host-resolver-rules=MAP * ~NOTFOUND");
  }

  const options = {
    headless: config.headless,
    args,
    defaultViewport: {
      width: 1280,
      height: 720,
    },
  };

  if (config.browserExecutablePath) {
    options.executablePath = config.browserExecutablePath;
  }

  return options;
}

async function launchBrowser() {
  if (config.allowWebrtc) {
    throw new EgressProxyError(
      "WEBRTC_POLICY_UNAVAILABLE",
      "WebRTC is disabled because no separate UDP egress policy is configured",
    );
  }

  await assertEgressEnforcement({ force: true });

  logger.info("browser_launching", {
    executable_path: config.browserExecutablePath || "puppeteer-managed",
    headless: config.headless,
    egress_proxy: describeEgressProxy(),
  });

  const browser = await puppeteer.launch(buildLaunchOptions());

  browser.on("disconnected", () => {
    logger.info("browser_disconnected");
    browserInstance = null;
    browserPromise = null;
    // Every context belonged to the process that just died. Retire the
    // registrations so no session can be checked out against a dead page and no
    // handle tries to close the same context twice; the next request launches a
    // fresh browser and, if it names a session, gets SESSION_NOT_FOUND.
    for (const entry of openContexts.values()) {
      entry.state = CONTEXT_STATE.CLOSING;
      entry.leases = 0;
    }
    openContexts.clear();
    sessions.clear();
  });

  browserInstance = browser;
  logger.info("browser_launched", { version: await browser.version() });
  return browser;
}

export async function getBrowser() {
  if (browserInstance && browserInstance.connected) {
    return browserInstance;
  }

  if (!browserPromise) {
    browserPromise = launchBrowser().catch((error) => {
      browserPromise = null;
      throw error;
    });
  }

  return browserPromise;
}

/**
 * Create one isolated browser context plus page and register it.
 *
 * Shared by the ephemeral navigation path and the persistent session path, so
 * both get identical isolation, accounting and lease protection — a session is a
 * context that stays registered between requests, not a different kind of
 * context.
 *
 * The entry is registered before the page exists so a partially built context is
 * still accounted for (shutdown, limits, leak reaping), and stays in
 * INITIALIZING — invisible to the expiration sweep — until the caller flips it.
 */
async function provisionPage({
  sessionId,
  requestId,
  persistent,
  owner,
  idleTimeoutMs,
  maxAgeMs,
}) {
  const browser = await getBrowser();

  if (openContexts.size >= config.maxConcurrentContexts) {
    throw new ContextLimitExceededError(config.maxConcurrentContexts);
  }

  const context = await browser.createBrowserContext();
  const contextId = randomUUID();
  const createdAt = Date.now();

  const entry = {
    context,
    page: null,
    createdAt,
    lastUsedAt: createdAt,
    sessionId: sessionId || null,
    requestId: requestId || null,
    state: CONTEXT_STATE.INITIALIZING,
    leaseExpiresAt: null,
    leases: 0,
    persistent: persistent === true,
    owner: persistent === true ? owner : null,
    idleTimeoutMs: persistent === true ? idleTimeoutMs : null,
    expiresAt: persistent === true ? createdAt + maxAgeMs : null,
    closingRequested: false,
    security: null,
  };
  openContexts.set(contextId, entry);

  try {
    const page = await context.newPage();
    entry.page = page;
    await page.setBypassServiceWorker(true);

    if (config.proxyAuthToken) {
      await page.authenticate({
        username: "agentshield",
        password: config.proxyAuthToken,
      });
    }

    context.on("targetcreated", (target) => {
      if (target.type() !== "page") {
        return;
      }

      void (async () => {
        try {
          const targetPage = await target.page();
          if (!targetPage || targetPage === page) {
            return;
          }
          logger.warn(
            { event: "browser_target_closed", request_id: requestId },
            "unexpected_browser_page_target",
          );
          await targetPage.close();
        } catch (error) {
          logger.warn(
            { err: error, request_id: requestId },
            "browser_target_close_failed",
          );
        }
      })();
    });

    if (entry.state === CONTEXT_STATE.CLOSING) {
      // Something retired this context while its page was still being built
      // (shutdown, or a forced reclaim). There is nothing usable to hand over,
      // so fall through to the cleanup path instead of leasing a dead context.
      throw new Error("browser context was closed during setup");
    }

    return { contextId, entry, page };
  } catch (error) {
    await retireContext(openContexts, contextId, entry, "browser_context_close_failed");
    throw error;
  }
}

/**
 * Handle for one registered context.
 *
 * The lease transitions are synchronous, so within Node's single-threaded event
 * loop a check-and-set is atomic: two concurrent requests cannot both take the
 * same context, and no global lock is held across a navigation.
 */
function buildHandle(contextId, entry) {
  /**
   * Take the lease again on an IDLE context. Returns false when the context
   * is not idle (already checked out, still initializing, or closing), which
   * makes a racing checkout against a sweep a safe no-op.
   */
  const checkOut = () => {
    if (entry.state !== CONTEXT_STATE.IDLE) {
      return false;
    }
    const now = Date.now();
    entry.state = CONTEXT_STATE.CHECKED_OUT;
    entry.lastUsedAt = now;
    entry.leaseExpiresAt = now + config.sessionMaxLeaseMs;
    entry.leases = 1;
    return true;
  };

  /**
   * Give the lease back, making the context eligible for idle expiration.
   * Idempotent: releasing an already-released (or closing) context returns
   * false and leaves the lifecycle state untouched.
   */
  const release = () => {
    if (entry.state !== CONTEXT_STATE.CHECKED_OUT) {
      return false;
    }
    entry.state = CONTEXT_STATE.IDLE;
    entry.lastUsedAt = Date.now();
    entry.leaseExpiresAt = null;
    entry.leases = 0;
    if (entry.closingRequested) {
      // A close that arrived while this request held the session is honoured now.
      void retireContext(
        openContexts,
        contextId,
        entry,
        "browser_context_close_failed",
      );
    }
    return true;
  };

  // Terminal for this handle. If a sweep already closed the context the entry
  // is CLOSING, so a second context.close() is never attempted.
  const close = async () => {
    if (entry.state === CONTEXT_STATE.CLOSING) {
      if (openContexts.get(contextId) === entry) {
        openContexts.delete(contextId);
      }
      if (entry.sessionId && sessions.get(entry.sessionId) === contextId) {
        sessions.delete(entry.sessionId);
      }
      return;
    }
    await retireContext(openContexts, contextId, entry, "browser_context_close_failed");
  };

  return {
    contextId,
    sessionId: entry.sessionId,
    context: entry.context,
    page: entry.page,
    security: entry.security,
    checkOut,
    release,
    close,
  };
}

export async function createIsolatedPage({ sessionId, requestId } = {}) {
  const { contextId, entry, page } = await provisionPage({
    sessionId,
    requestId,
    persistent: false,
  });

  // Hand the context to the request. Synchronous, so there is no window where
  // the context is in use but not lease-protected.
  const startedAt = Date.now();
  entry.state = CONTEXT_STATE.CHECKED_OUT;
  entry.lastUsedAt = startedAt;
  entry.leaseExpiresAt = startedAt + config.sessionMaxLeaseMs;
  entry.leases = 1;

  return buildHandle(contextId, entry);
}

/**
 * A3 — create a persistent browser session.
 *
 * Registers a real BrowserContext (not a metadata record) under a
 * server-generated id and keeps it IDLE between requests so state survives
 * across navigations. The id is `randomUUID()`: caller-supplied identities never
 * select a context, which is what keeps an A2 header identity and an A3 session
 * id from being the same thing.
 *
 * Ownership: `owner` is the authenticated caller identity as presented by the
 * control plane; every later operation must present the same value.
 */
export async function createSession({
  owner,
  requestId,
  idleTimeoutMs = config.sessionIdleTimeoutMs,
  maxAgeMs = config.sessionMaxAgeMs,
} = {}) {
  if (sessions.size >= config.maxSessions) {
    throw new SessionLimitExceededError(config.maxSessions);
  }

  const sessionId = randomUUID();
  const provisioned = await provisionPage({
    sessionId,
    requestId,
    persistent: true,
    owner,
    idleTimeoutMs,
    maxAgeMs,
  });

  try {
    // Installed once per session page: request interception, redirect analysis
    // and the in-page hardening then cover every navigation the session makes.
    provisioned.entry.security = await installPageSecurity(
      provisioned.page,
      { requestId },
    );

    if (provisioned.entry.state !== CONTEXT_STATE.INITIALIZING) {
      throw new Error("browser context was closed during session setup");
    }

    // Registered and taken out of INITIALIZING in the same synchronous step, so
    // there is no window where a live session is invisible to its owner or
    // visible to the idle sweep while still unowned.
    sessions.set(sessionId, provisioned.contextId);
    provisioned.entry.state = CONTEXT_STATE.IDLE;
    provisioned.entry.lastUsedAt = Date.now();
  } catch (error) {
    // Failed setup must not leave a session behind: retire the context, and the
    // registry entry goes with it.
    await retireContext(
      openContexts,
      provisioned.contextId,
      provisioned.entry,
      "browser_session_setup_close_failed",
    );
    throw error;
  }

  logger.info(
    { event: "browser_session_created", context_id: provisioned.contextId, request_id: requestId },
    "browser_session_created",
  );

  return { handle: buildHandle(provisioned.contextId, provisioned.entry), session: describeSession(provisioned.entry) };
}

function describeSession(entry) {
  return {
    sessionId: entry.sessionId,
    state: entry.state,
    createdAt: entry.createdAt,
    lastUsedAt: entry.lastUsedAt,
    expiresAt: entry.expiresAt,
    maxAgeMs: entry.expiresAt - entry.createdAt,
    idleTimeoutMs: entry.idleTimeoutMs,
    activeRequests: entry.leases,
    closingRequested: entry.closingRequested,
    currentUrl: entry.page && entry.page.url ? safePageUrl(entry.page) : null,
  };
}

function safePageUrl(page) {
  try {
    const url = page.url();
    return url && url !== "about:blank" ? url : null;
  } catch {
    return null;
  }
}

/**
 * Look up a session and confirm the caller owns it.
 *
 * An unknown id and a foreign id are both refused, and the owner check runs
 * before anything is done with the context. The session id is never treated as
 * authorization on its own.
 */
function resolveSession(sessionId, owner) {
  const contextId = sessions.get(sessionId);
  if (!contextId) {
    throw new SessionNotFoundError();
  }
  const entry = openContexts.get(contextId);
  if (!entry || entry.state === CONTEXT_STATE.CLOSING) {
    sessions.delete(sessionId);
    throw new SessionNotFoundError();
  }
  if (!ownerMatches(owner, entry.owner)) {
    logger.warn(
      { event: "browser_session_owner_mismatch", context_id: contextId },
      "browser_session_owner_mismatch",
    );
    throw new SessionForbiddenError();
  }
  return { contextId, entry };
}

export async function getSession({ sessionId, owner }) {
  const { entry } = resolveSession(sessionId, owner);
  return describeSession(entry);
}

/**
 * Take the lease on a session for one request.
 *
 * Returns the handle; the caller must call `handle.release()` (not `close()`)
 * when the request finishes. Concurrent requests on the same session get 409:
 * a browser context has one page, so serialising is the only correct answer.
 */
export async function checkoutSession({ sessionId, owner, requestId }) {
  const { contextId, entry } = resolveSession(sessionId, owner);

  if (entry.state === CONTEXT_STATE.CHECKED_OUT) {
    throw new SessionBusyError(
      entry.leaseExpiresAt && entry.leaseExpiresAt <= Date.now()
        ? "SESSION_LEASE_EXPIRED"
        : "SESSION_CHECKED_OUT",
    );
  }
  if (entry.closingRequested) {
    throw new SessionBusyError("SESSION_CLOSING", "session is closing");
  }

  const handle = buildHandle(contextId, entry);
  if (!handle.checkOut()) {
    // Lost a race against the expiration sweep or another checkout.
    throw new SessionBusyError("SESSION_CHECKED_OUT");
  }
  entry.requestId = requestId ?? entry.requestId;
  return handle;
}

/**
 * Close a session.
 *
 * A session that is mid-request is not torn out from under its request: the
 * close is recorded and applied when the lease is released. Everything else
 * closes immediately. Either way the registry entry is gone, so the id stops
 * resolving at once.
 */
export async function closeSession({ sessionId, owner }) {
  const { contextId, entry } = resolveSession(sessionId, owner);
  sessions.delete(sessionId);

  if (entry.state === CONTEXT_STATE.CHECKED_OUT) {
    entry.closingRequested = true;
    logger.info(
      { event: "browser_session_close_deferred", context_id: contextId },
      "browser_session_close_deferred",
    );
    return { deferred: true };
  }

  await retireContext(
    openContexts,
    contextId,
    entry,
    "browser_session_close_failed",
  );
  logger.info(
    { event: "browser_session_closed", context_id: contextId },
    "browser_session_closed",
  );
  return { deferred: false };
}


export function getOpenContextCount() {
  return openContexts.size;
}

/**
 * Number of registered persistent sessions. The existing per-request contract
 * is unchanged: an unregistered `x-agent-session` identity creates no session,
 * so a normal navigation leaves this count at zero and its context closed.
 */
export function getOpenSessionCount() {
  return sessions.size;
}

export function sessionExists(sessionId) {
  return sessions.has(sessionId);
}

/**
 * Reap browser contexts that are eligible for expiration.
 *
 * This is the single session-expiration entry point shared by the background
 * timer (in index.js) and the /health/ready handler; both reuse the existing
 * lifecycle (`openContexts` + `config.sessionIdleTimeoutMs`), and the timer
 * only sets the sweep cadence.
 *
 * Eligibility is decided by the context lifecycle state, never by age alone:
 *
 *   IDLE         — released by its request; reaped once `lastUsedAt` is more
 *                  than `sessionIdleTimeoutMs` in the past.
 *   CHECKED_OUT  — owned by an in-flight request. Never reaped until its lease
 *                  ceiling (`sessionMaxLeaseMs`, floored above the largest
 *                  navigation timeout the API accepts) lapses, which only
 *                  happens for a lease stranded by a crashed handler.
 *   INITIALIZING — still being built by createIsolatedPage(); never reaped.
 *   CLOSING      — close already initiated; never reaped again.
 *
 * So a checked-out context survives any number of sweeps, however aggressive
 * `sessionIdleTimeoutMs` is configured.
 *
 * A module-level lock (`cleanupInProgress`) prevents concurrent cleanup
 * races: if a run is already in progress (e.g. the timer tick overlaps a
 * /health/ready call), the overlapping run is skipped and returns 0. The next
 * tick reaps anything that expired during the in-progress run. Per-entry
 * eligibility is re-checked immediately before the state is flipped to CLOSING
 * with no intervening await, so a context checked out during a sweep is not
 * closed by it.
 *
 * The parameters default to the real lifecycle state so callers can invoke
 * `closeExpiredContexts()` with no arguments; they are also injectable so the
 * expiration logic can be exercised without launching a real browser.
 *
 * @param {object} [options]
 * @param {number} [options.now]             Current time (ms). Defaults to Date.now().
 * @param {Map}    [options.contexts]        Map of open contexts. Defaults to openContexts.
 * @param {number} [options.idleTimeoutMs]   Idle threshold. Defaults to config.sessionIdleTimeoutMs.
 * @returns {Promise<number>} Number of contexts actually closed.
 */
export async function closeExpiredContexts({
  now = Date.now(),
  contexts = openContexts,
  idleTimeoutMs = config.sessionIdleTimeoutMs,
} = {}) {
  if (cleanupInProgress) {
    return 0;
  }
  cleanupInProgress = true;
  try {
    let closed = 0;

    // One pass, deciding eligibility per entry and retiring it immediately.
    // Entries added while we are looping are INITIALIZING or CHECKED_OUT, so
    // they are skipped rather than half-reaped.
    for (const [contextId, entry] of contexts.entries()) {
      if (!isReapable(entry, now, idleTimeoutMs)) {
        continue;
      }

      if (entry.state === CONTEXT_STATE.CHECKED_OUT) {
        logger.warn(
          { context_id: contextId, request_id: entry.requestId },
          "browser_context_lease_expired",
        );
      }

      await retireContext(
        contexts,
        contextId,
        entry,
        "browser_context_expire_failed",
      );
      closed += 1;

      // A persistent session is reaped for one of three reasons; which one it
      // was tells the operator whether the lifetime settings are too tight.
      if (entry.persistent) {
        logger.info(
          {
            context_id: contextId,
            reason:
              Number.isFinite(entry.expiresAt) && now >= entry.expiresAt
                ? "max_age"
                : "idle",
          },
          "browser_session_expired",
        );
      } else {
        logger.info({ context_id: contextId }, "browser_context_expired");
      }
    }

    return closed;
  } finally {
    cleanupInProgress = false;
  }
}

export async function checkBrowserReadiness() {
  const egress = await assertEgressEnforcement();
  const browser = await getBrowser();
  if (!browser.connected) {
    throw new Error("browser process is not connected");
  }
  return { browser: true, egress };
}

export async function closeBrowser() {
  // Shutdown is unconditional: leases do not protect a context past process
  // exit. Retiring through the same path keeps every handle's state at CLOSING,
  // so a request still finishing cannot try to close its context twice.
  for (const [contextId, entry] of openContexts.entries()) {
    await retireContext(openContexts, contextId, entry, "browser_context_close_failed");
  }

  if (!browserInstance) {
    return;
  }

  const browser = browserInstance;
  browserInstance = null;
  browserPromise = null;

  try {
    await browser.close();
  } catch (error) {
    logger.warn({ err: error }, "browser_close_failed");
  }
}
