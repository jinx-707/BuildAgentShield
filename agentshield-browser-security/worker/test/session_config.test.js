/**
 * Session timing configuration validation tests.
 *
 * config.js resolves these values at module load, so each case runs the real
 * module in a subprocess with a controlled environment. This is what keeps the
 * lease ceiling honest: an operator cannot configure a value that would let the
 * sweeper outrun a legitimate in-flight request without the worker saying so.
 *
 * Coverage:
 *   - Defaults are used when nothing is configured
 *   - A cleanup interval above the idle timeout is clamped down and reported
 *   - A sub-second cleanup interval is clamped up and reported
 *   - A lease ceiling below the navigation budget is floored and reported
 *   - Non-numeric values fall back and are reported
 *   - The navigation timeout the route accepts is inside the lease floor
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

const CONFIG_MODULE = new URL("../src/config.js", import.meta.url).href;

const SESSION_KEYS = [
  "BROWSER_SESSION_IDLE_TIMEOUT_MS",
  "BROWSER_SESSION_CLEANUP_INTERVAL_MS",
  "BROWSER_SESSION_MAX_LEASE_MS",
  "BROWSER_NAVIGATION_TIMEOUT_MS",
];

/** Read the resolved session timing config for a given environment. */
function resolveConfig(overrides = {}) {
  // Blank the keys under test so an inherited value from the caller's shell
  // cannot change the expectation.
  const env = {};
  for (const key of SESSION_KEYS) {
    env[key] = "";
  }
  Object.assign(env, process.env, overrides);

  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const { config } = await import(${JSON.stringify(CONFIG_MODULE)});
       console.log(JSON.stringify({
         idle: config.sessionIdleTimeoutMs,
         interval: config.sessionCleanupIntervalMs,
         lease: config.sessionMaxLeaseMs,
         navigationTimeout: config.navigationTimeoutMs,
         navigationTimeoutMax: config.navigationTimeoutMaxMs,
         warnings: config.sessionTimingWarnings,
       }));`,
    ],
    { encoding: "utf8", env },
  );

  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim());
}

describe("session timing configuration", () => {
  it("uses the documented defaults when nothing is configured", () => {
    const c = resolveConfig();
    assert.equal(c.idle, 300000);
    assert.equal(c.interval, 30000);
    assert.equal(c.lease, 120000);
    assert.deepEqual(c.warnings, []);
  });

  it("clamps a cleanup interval longer than the idle timeout and reports it", () => {
    const c = resolveConfig({
      BROWSER_SESSION_IDLE_TIMEOUT_MS: "5000",
      BROWSER_SESSION_CLEANUP_INTERVAL_MS: "600000",
    });
    assert.equal(c.interval, 5000, "the sweep may not be slower than expiry");
    assert.match(c.warnings.join("\n"), /BROWSER_SESSION_CLEANUP_INTERVAL_MS/);
  });

  it("clamps a sub-second cleanup interval and reports it", () => {
    const c = resolveConfig({ BROWSER_SESSION_CLEANUP_INTERVAL_MS: "5" });
    assert.equal(c.interval, 1000);
    assert.match(c.warnings.join("\n"), /below the safe minimum/);
  });

  it("floors a lease ceiling that cannot cover the request it protects", () => {
    const c = resolveConfig({ BROWSER_SESSION_MAX_LEASE_MS: "50" });
    assert.equal(
      c.lease,
      70000,
      "must clear the largest navigation timeout the route accepts",
    );
    assert.match(c.warnings.join("\n"), /BROWSER_SESSION_MAX_LEASE_MS/);
  });

  it("floors the lease above a navigation timeout larger than the route cap", () => {
    const c = resolveConfig({
      BROWSER_NAVIGATION_TIMEOUT_MS: "70000",
      BROWSER_SESSION_MAX_LEASE_MS: "60000",
    });
    assert.equal(c.lease, 80000, "70000ms timeout + 10000ms grace");
  });

  it("rejects non-numeric values with a warning instead of trusting them", () => {
    const c = resolveConfig({
      BROWSER_SESSION_IDLE_TIMEOUT_MS: "ten-minutes",
    });
    assert.equal(c.idle, 300000);
    assert.match(c.warnings.join("\n"), /is not a positive number of milliseconds/);

    const negative = resolveConfig({
      BROWSER_SESSION_CLEANUP_INTERVAL_MS: "-1000",
    });
    assert.equal(negative.interval, 30000);
    assert.match(negative.warnings.join("\n"), /BROWSER_SESSION_CLEANUP_INTERVAL_MS/);
  });

  it("keeps the route timeout bound inside the lease floor invariant", () => {
    const c = resolveConfig();
    assert.equal(c.navigationTimeoutMax, 60000);
    assert.ok(
      c.lease > c.navigationTimeoutMax,
      "a request at the largest accepted timeout always fits its lease",
    );
    assert.ok(c.lease > c.navigationTimeout);
  });
});
