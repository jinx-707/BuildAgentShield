import { logger } from "./logger.js";

/**
 * Start a background timer that periodically invokes `cleanupFn`.
 *
 * The sweep runs on its own interval and is decoupled from any HTTP request,
 * so expired sessions are reaped even when no traffic reaches the worker
 * (i.e. it does not depend on `/health/ready` or any inbound request).
 *
 * The interval handle is `unref()`'d so the timer by itself never keeps the
 * Node process alive — only real work (in-flight requests, shutdown) does.
 *
 * `cleanupFn` is expected to be re-entrancy-safe (it is: `closeExpiredContexts`
 * holds a lock and skips overlapping runs). Errors thrown by a tick are
 * logged and swallowed so a failing sweep never kills the timer.
 *
 * @param {object} options
 * @param {() => (Promise<void> | void)} options.cleanupFn
 *   Async cleanup invoked each tick.
 * @param {number} options.intervalMs
 *   Milliseconds between sweeps. Must be a positive finite number.
 * @returns {{ stop: () => Promise<void> }}
 *   Handle whose `stop()` clears the interval and runs one final cleanup pass.
 *   Idempotent: calling it more than once is a no-op after the first.
 */
export function startSessionCleanupTimer({ cleanupFn, intervalMs }) {
  if (typeof cleanupFn !== "function") {
    throw new TypeError("cleanupFn must be a function");
  }
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new TypeError("intervalMs must be a positive finite number");
  }

  const tick = () => {
    Promise.resolve()
      .then(() => cleanupFn())
      .catch((error) => {
        logger.warn({ err: error }, "session_cleanup_tick_failed");
      });
  };

  const interval = setInterval(tick, intervalMs);
  // Do not let the timer keep the event loop alive on its own.
  interval.unref();

  let stopped = false;
  return {
    async stop() {
      if (stopped) {
        return;
      }
      stopped = true;
      clearInterval(interval);
      // One final sweep on shutdown so sessions do not outlive the process.
      try {
        await cleanupFn();
      } catch (error) {
        logger.warn({ err: error }, "session_cleanup_final_failed");
      }
    },
  };
}
