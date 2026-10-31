import { createApp } from "./app.js";
import { config } from "./config.js";
import { closeBrowser, closeExpiredContexts } from "./lib/browser.js";
import { logger } from "./lib/logger.js";
import { startSessionCleanupTimer } from "./lib/session_cleanup.js";
import {
  computePolicyFingerprint,
  validatePolicyConfig,
} from "../../proxy/src/lib/policy.js";

// Validate and fingerprint the policy configuration at startup.
// This produces the same fingerprint as the proxy for the same env vars,
// allowing operators to compare startup logs across components.
validatePolicyConfig(
  {
    allowedDomains: config.allowedDomains,
    defaultDomainPolicy: config.defaultDomainPolicy,
  },
  { environment: config.environment },
);

const policyFingerprint = computePolicyFingerprint({
  allowedDomains: config.allowedDomains,
  blockedDomains: config.blockedDomains,
  defaultDomainPolicy: config.defaultDomainPolicy,
  allowedPorts: config.allowedPorts,
});

const app = createApp();

// Never silently accept a clamped or rejected session timing: the sweep
// cadence, idle timeout and lease ceiling are what keep browser contexts from
// leaking, so a corrected value has to be visible in the startup log.
for (const warning of config.sessionTimingWarnings) {
  logger.warn("worker_session_timing_adjusted", { detail: warning });
}

logger.info("worker_session_lifecycle", {
  idle_timeout_ms: config.sessionIdleTimeoutMs,
  cleanup_interval_ms: config.sessionCleanupIntervalMs,
  max_lease_ms: config.sessionMaxLeaseMs,
  session_max_age_ms: config.sessionMaxAgeMs,
  max_sessions: config.maxSessions,
  navigation_timeout_max_ms: config.navigationTimeoutMaxMs,
  max_concurrent_contexts: config.maxConcurrentContexts,
});

const server = app.listen(config.port, config.host, () => {
  logger.info("worker_started", {
    host: config.host,
    port: config.port,
    policy_fingerprint: policyFingerprint,
  });
});

// Background session expiration: reaps idle browser contexts on a fixed cadence
// that is independent of any HTTP request, so leaked/expired sessions are
// closed and their browser resources released even when no traffic arrives.
// Reuses the existing lifecycle (closeExpiredContexts + sessionIdleTimeoutMs);
// the timer only controls the sweep cadence. The interval is unref()'d so it
// never keeps the process alive on its own.
const cleanupTimer = startSessionCleanupTimer({
  cleanupFn: closeExpiredContexts,
  intervalMs: config.sessionCleanupIntervalMs,
});

server.on("error", (error) => {
  logger.error({ err: error }, "worker_server_error");
  process.exitCode = 1;
});

let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  logger.info("worker_shutdown_started", { signal });

  const forceExit = setTimeout(() => {
    logger.error("worker_shutdown_forced");
    process.exit(1);
  }, 10000);
  forceExit.unref();

  server.close(async (error) => {
    if (error) {
      logger.error({ err: error }, "worker_server_close_failed");
    }

    // Cancel the background timer and run one final cleanup pass before the
    // browser is torn down so no session outlives the process.
    await cleanupTimer.stop();
    await closeBrowser();
    logger.info("worker_stopped");
    process.exit(error ? 1 : 0);
  });
}

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});

process.on("unhandledRejection", (reason) => {
  logger.error({ err: reason }, "unhandled_rejection");
});
