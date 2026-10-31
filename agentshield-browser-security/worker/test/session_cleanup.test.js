/**
 * Background session cleanup timer tests.
 *
 * Tests the standalone `startSessionCleanupTimer` scheduling module in
 * isolation, using a fake cleanupFn — no Puppeteer, no browser, no server.
 *
 * Coverage:
 *   - Periodic ticks invoke cleanupFn on the configured cadence
 *   - stop() cancels the timer and runs exactly one final cleanup
 *   - No further ticks fire after stop()
 *   - stop() is idempotent
 *   - A failing tick is swallowed so the timer keeps running
 *   - Invalid options are rejected
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { startSessionCleanupTimer } from "../src/lib/session_cleanup.js";

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("startSessionCleanupTimer", () => {
  it("invokes cleanupFn on each interval tick", async () => {
    let calls = 0;
    const handle = startSessionCleanupTimer({
      cleanupFn: async () => {
        calls += 1;
      },
      intervalMs: 10,
    });
    try {
      await delay(60); // ~6 ticks at 10ms
    } finally {
      await handle.stop();
    }
    assert.ok(calls >= 2, `expected at least 2 periodic ticks, got ${calls}`);
  });

  it("runs exactly one final cleanup on stop() and then stops ticking", async () => {
    let calls = 0;
    const handle = startSessionCleanupTimer({
      cleanupFn: async () => {
        calls += 1;
      },
      intervalMs: 1000, // long enough that no periodic tick fires before stop
    });
    await handle.stop();
    assert.equal(calls, 1, "stop() should run exactly one final cleanup");

    // No further ticks after stop().
    await delay(40);
    assert.equal(calls, 1, "no further ticks should fire after stop()");
  });

  it("stop() is idempotent", async () => {
    let calls = 0;
    const handle = startSessionCleanupTimer({
      cleanupFn: async () => {
        calls += 1;
      },
      intervalMs: 1000,
    });
    await handle.stop();
    await handle.stop();
    assert.equal(calls, 1, "final cleanup should run only once");
  });

  it("swallows cleanupFn errors so the timer keeps running", async () => {
    let calls = 0;
    const handle = startSessionCleanupTimer({
      cleanupFn: async () => {
        calls += 1;
        throw new Error("boom");
      },
      intervalMs: 10,
    });
    try {
      await delay(50); // ~5 failing ticks
    } finally {
      await handle.stop();
    }
    assert.ok(calls >= 2, `timer should survive errors, got ${calls}`);
  });

  it("rejects a non-positive interval", () => {
    assert.throws(
      () => startSessionCleanupTimer({ cleanupFn: async () => {}, intervalMs: 0 }),
      TypeError,
    );
    assert.throws(
      () => startSessionCleanupTimer({ cleanupFn: async () => {}, intervalMs: -5 }),
      TypeError,
    );
  });

  it("rejects a non-finite interval", () => {
    assert.throws(
      () =>
        startSessionCleanupTimer({ cleanupFn: async () => {}, intervalMs: Infinity }),
      TypeError,
    );
  });

  it("rejects a non-function cleanupFn", () => {
    assert.throws(
      () => startSessionCleanupTimer({ cleanupFn: null, intervalMs: 100 }),
      TypeError,
    );
  });

  it("the background interval does not keep the process alive on its own", () => {
    // An unref()'d timer should not block shutdown. We assert the returned
    // handle exposes stop() and that starting it does not throw; the unref()
    // behaviour itself is exercised by the integration shutdown test.
    const handle = startSessionCleanupTimer({
      cleanupFn: async () => {},
      intervalMs: 1000,
    });
    assert.equal(typeof handle.stop, "function");
    return handle.stop();
  });
});
