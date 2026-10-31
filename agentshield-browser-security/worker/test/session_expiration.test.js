/**
 * Session expiration (closeExpiredContexts) tests.
 *
 * Tests the shared cleanup function in isolation using fake context entries
 * injected through the function's options — no Puppeteer, no browser.
 * This is the single expiration entry point used by both the background timer
 * and the /health/ready handler.
 *
 * Coverage:
 *   - Idle contexts released past the idle timeout are closed and removed
 *   - Checked-out contexts survive every sweep, however aggressive the timeout
 *   - Contexts still initializing are never reaped
 *   - Contexts already closing are never reaped twice
 *   - Only a stranded lease may be reclaimed
 *   - A failing context.close() is logged and swallowed; cleanup continues
 *   - Concurrent runs are serialized (the second overlapping run is skipped)
 *   - Eligibility is re-checked against a racing checkout
 *   - A context removed between selection and close is handled safely
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { CONTEXT_STATE, closeExpiredContexts } from "../src/lib/browser.js";

/** Minimal fake BrowserContext with an observable, fast close(). */
function makeContext() {
  let closed = false;
  const context = {
    async close() {
      closed = true;
    },
  };
  return { context, wasClosed: () => closed };
}

/**
 * Fake BrowserContext whose close() stays pending until `release()` is
 * called, then marks the context closed. Used to pin a cleanup run mid-flight
 * so overlapping behaviour can be observed deterministically.
 */
function makeControllableContext() {
  let closed = false;
  let resolveClose;
  const context = {
    close() {
      return new Promise((resolve) => {
        resolveClose = () => {
          closed = true;
          resolve();
        };
      });
    },
  };
  return {
    context,
    wasClosed: () => closed,
    release: () => resolveClose?.(),
  };
}

/**
 * A released (IDLE) context entry — the only state the idle timeout applies to.
 */
function entry(context, lastUsedAt) {
  return {
    context,
    createdAt: lastUsedAt,
    lastUsedAt,
    sessionId: null,
    requestId: null,
    state: CONTEXT_STATE.IDLE,
    leaseExpiresAt: null,
  };
}

/** A context currently owned by a request. */
function checkedOutEntry(context, leaseExpiresAt) {
  return {
    ...entry(context, 0),
    state: CONTEXT_STATE.CHECKED_OUT,
    leaseExpiresAt,
  };
}

/** A context whose page is still being built by createIsolatedPage(). */
function initializingEntry(context) {
  return { ...entry(context, 0), state: CONTEXT_STATE.INITIALIZING };
}

/** A context whose close has already been initiated. */
function closingEntry(context) {
  return { ...entry(context, 0), state: CONTEXT_STATE.CLOSING };
}

describe("closeExpiredContexts — default (production) path", () => {
  it("no-argument call reuses the real openContexts map and config idle timeout", async () => {
    // This is the exact call made by the background timer and /health/ready.
    // With no browser launched, openContexts is empty, so it reaps nothing
    // and must not throw — confirming the defaults resolve to the real
    // session lifecycle state rather than requiring injected arguments.
    const closed = await closeExpiredContexts();
    assert.equal(closed, 0);
  });
});

describe("closeExpiredContexts — expiration", () => {
  it("closes and removes contexts idle past the idle timeout", async () => {
    const ctx = makeContext();
    const contexts = new Map([["expired-1", entry(ctx.context, 0)]]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });

    assert.equal(closed, 1);
    assert.ok(ctx.wasClosed(), "expired context should be closed");
    assert.equal(contexts.size, 0, "expired context should be removed");
  });

  it("does not close contexts exactly at the idle boundary", async () => {
    // lastUsedAt = 9000, now = 10000, elapsed = 1000, idleTimeoutMs = 1000
    // The check is strictly greater-than, so a context idle for exactly the
    // timeout is still considered active and preserved.
    const ctx = makeContext();
    const contexts = new Map([["boundary-1", entry(ctx.context, 9000)]]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });

    assert.equal(closed, 0);
    assert.equal(ctx.wasClosed(), false);
    assert.equal(contexts.size, 1);
  });
});

describe("closeExpiredContexts — active session preservation", () => {
  it("preserves contexts that are still within the idle window", async () => {
    const expired = makeContext();
    const active = makeContext();
    const contexts = new Map([
      ["active-1", entry(active.context, 9500)], // 500ms ago -> active
      ["expired-1", entry(expired.context, 0)], // 10000ms ago -> expired
    ]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });

    assert.equal(closed, 1, "only the expired context should be closed");
    assert.ok(expired.wasClosed());
    assert.equal(active.wasClosed(), false, "active context must not be closed");
    assert.ok(contexts.has("active-1"), "active context remains in the map");
    assert.equal(contexts.size, 1);
  });

  it("closes nothing when all contexts are active", async () => {
    const a = makeContext();
    const b = makeContext();
    const contexts = new Map([
      ["active-1", entry(a.context, 9900)],
      ["active-2", entry(b.context, 9950)],
    ]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });

    assert.equal(closed, 0);
    assert.equal(contexts.size, 2);
  });
});

describe("closeExpiredContexts — cleanup failures", () => {
  it("logs and swallows a failing context.close() and continues closing others", async () => {
    const failing = makeContext();
    failing.context.close = async () => {
      throw new Error("close failed");
    };
    const ok = makeContext();
    const contexts = new Map([
      ["fail-1", entry(failing.context, 0)],
      ["ok-1", entry(ok.context, 0)],
    ]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });

    // Both were selected and removed; the failure did not abort the loop.
    assert.equal(closed, 2);
    assert.equal(contexts.size, 0);
    assert.ok(ok.wasClosed(), "second context closed despite first failure");
  });
});

describe("closeExpiredContexts — concurrency", () => {
  it("skips an overlapping run while a cleanup is in progress", async () => {
    const blocked = makeControllableContext();
    const other = makeContext();
    const contexts = new Map([
      ["blocked", entry(blocked.context, 0)],
      ["other", entry(other.context, 0)],
    ]);

    // First run selects both as expired, deletes `blocked`, then blocks on
    // its close() — leaving `other` still in the map, unprocessed.
    const first = closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });
    await Promise.resolve();

    // Second overlapping run must be skipped by the lock, NOT close `other`.
    const second = closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });
    const secondResult = await second;
    assert.equal(secondResult, 0, "overlapping run should be skipped");
    assert.equal(
      other.wasClosed(),
      false,
      "other context must not be closed by the overlapping run",
    );
    assert.ok(
      contexts.has("other"),
      "other context still pending cleanup by the first run",
    );

    // Let the first run finish; it then processes `other`.
    blocked.release();
    const firstResult = await first;
    assert.equal(firstResult, 2);
    assert.ok(blocked.wasClosed());
    assert.ok(other.wasClosed());
    assert.equal(contexts.size, 0);
  });

  it("handles a context removed between selection and close", async () => {
    const first = makeControllableContext();
    const second = makeContext();
    const contexts = new Map([
      ["first", entry(first.context, 0)],
      ["second", entry(second.context, 0)],
    ]);

    const run = closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });
    await Promise.resolve();
    // Run selected both, deleted `first`, and is blocked on its close().

    // Remove `second` externally (e.g. request finished normally) before its turn.
    contexts.delete("second");

    first.release();
    const closed = await run;

    // `first` was closed; `second` was already gone so it was skipped safely.
    assert.ok(first.wasClosed());
    assert.equal(
      second.wasClosed(),
      false,
      "already-removed context must not be double-closed",
    );
    assert.equal(closed, 1);
    assert.equal(contexts.size, 0);
  });
});

/** Fake context that counts how many times close() was called. */
function makeCountingContext() {
  let closeCalls = 0;
  const context = {
    async close() {
      closeCalls += 1;
    },
  };
  return { context, closeCallCount: () => closeCalls };
}

describe("closeExpiredContexts — lease protection", () => {
  it("never reaps a checked-out context, across many sweeps and a zero idle timeout", async () => {
    const held = checkedOutEntry(makeContext().context, 10000 + 120000);
    const contexts = new Map([["held", held]]);

    for (let sweep = 0; sweep < 3; sweep += 1) {
      const closed = await closeExpiredContexts({
        now: 10000 + sweep,
        contexts,
        idleTimeoutMs: 0,
      });
      assert.equal(closed, 0, `sweep ${sweep} must not reap a held context`);
    }

    assert.equal(held.state, CONTEXT_STATE.CHECKED_OUT);
    assert.equal(contexts.size, 1);
  });

  it("reaps only the idle context when a checked-out one is older than the timeout", async () => {
    const idle = makeContext();
    const held = makeContext();
    const contexts = new Map([
      ["ancient-held", checkedOutEntry(held.context, 10_000_000)],
      ["idle-expired", entry(idle.context, 0)],
    ]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });

    assert.equal(closed, 1);
    assert.ok(idle.wasClosed(), "the released context expires");
    assert.equal(held.wasClosed(), false, "the checked-out context is untouched");
    assert.ok(contexts.has("ancient-held"));
  });

  it("reclaims a stranded lease once its ceiling lapses", async () => {
    const stranded = makeContext();
    const strandedEntry = checkedOutEntry(stranded.context, 9000);
    const contexts = new Map([["stranded", strandedEntry]]);

    const closed = await closeExpiredContexts({
      now: 10000,
      contexts,
      // Age alone would not qualify it: the lease is what expires.
      idleTimeoutMs: 1_000_000,
    });

    assert.equal(closed, 1, "an expired lease may be reclaimed");
    assert.ok(stranded.wasClosed());
    assert.equal(contexts.size, 0);
    assert.equal(strandedEntry.state, CONTEXT_STATE.CLOSING);
  });

  it("never reaps a context that is still initializing", async () => {
    const building = makeContext();
    const contexts = new Map([["building", initializingEntry(building.context)]]);

    const closed = await closeExpiredContexts({
      now: 10_000,
      contexts,
      idleTimeoutMs: 0,
    });

    assert.equal(closed, 0, "a context under construction cannot be reaped");
    assert.equal(building.wasClosed(), false);
    assert.equal(contexts.size, 1);
  });

  it("never reaps a context whose close is already in progress", async () => {
    const closing = makeCountingContext();
    const contexts = new Map([["closing", closingEntry(closing.context)]]);

    for (let sweep = 0; sweep < 2; sweep += 1) {
      const closed = await closeExpiredContexts({
        now: 10000,
        contexts,
        idleTimeoutMs: 0,
      });
      assert.equal(closed, 0);
    }

    assert.equal(
      closing.closeCallCount(),
      0,
      "an already-initiated close must not be issued again",
    );
    assert.equal(contexts.size, 1, "the sweeper does not remove a closing entry");
  });

  it("does not close a context that is checked out while a sweep is in flight", async () => {
    const blocking = makeControllableContext();
    const racing = makeContext();
    const contexts = new Map([
      ["blocking", entry(blocking.context, 0)],
      ["racing", entry(racing.context, 0)],
    ]);

    const sweep = closeExpiredContexts({
      now: 10000,
      contexts,
      idleTimeoutMs: 1000,
    });
    await Promise.resolve();
    // `blocking` is being closed; `racing` has not been visited yet.

    // A request takes the lease on `racing` mid-sweep, with a live lease.
    const racingEntry = contexts.get("racing");
    racingEntry.state = CONTEXT_STATE.CHECKED_OUT;
    racingEntry.leaseExpiresAt = 10000 + 120000;

    blocking.release();
    const closed = await sweep;

    assert.equal(closed, 1, "only the blocked context is reaped");
    assert.equal(racing.wasClosed(), false, "a racing checkout wins against the sweep");
    assert.ok(contexts.has("racing"));
    assert.equal(contexts.get("racing").state, CONTEXT_STATE.CHECKED_OUT);
  });

  it("releasing then re-checking out does not double-close or corrupt the entry", async () => {
    const held = makeCountingContext();
    const entryObject = checkedOutEntry(held.context, 10_000_000);
    const contexts = new Map([["cycle", entryObject]]);

    // Release: becomes idle and eligible once past the idle window.
    entryObject.state = CONTEXT_STATE.IDLE;
    entryObject.leaseExpiresAt = null;
    assert.equal(await closeExpiredContexts({ now: 999, contexts, idleTimeoutMs: 1000 }), 0);

    entryObject.lastUsedAt = 0;
    assert.equal(await closeExpiredContexts({ now: 5000, contexts, idleTimeoutMs: 1000 }), 1);
    assert.equal(held.closeCallCount(), 1);

    // A second sweep must not touch the retired context again.
    assert.equal(await closeExpiredContexts({ now: 9000, contexts, idleTimeoutMs: 1000 }), 0);
    assert.equal(held.closeCallCount(), 1, "close is issued exactly once");
    assert.equal(entryObject.state, CONTEXT_STATE.CLOSING);
    assert.equal(contexts.size, 0);
  });
});
