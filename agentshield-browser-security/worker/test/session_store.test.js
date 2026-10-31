/**
 * A3 — persistent browser sessions, real Chromium.
 *
 * These tests launch the actual browser and make actual navigations, because the
 * claim under test is "a session keeps its browser context and its cookies",
 * which no mock can prove. No egress proxy is involved: the fixture origin is a
 * loopback server whose port is put in the worker's port allowlist, and private
 * networks are permitted only so that fixture is reachable — the same fixture
 * shape worker/test/session_id.test.js uses.
 *
 * Coverage:
 *   - create / retrieve / close round-trips a real BrowserContext
 *   - state (cookies, localStorage) survives across navigations in one session
 *   - two sessions see neither each other's state
 *   - an unregistered identity still gets a fresh per-request context
 *   - ownership is enforced on get, checkout and close
 *   - concurrent requests on one session conflict instead of sharing a page
 *   - idle expiry and absolute lifetime both retire the context
 *   - close during an in-flight request is deferred, not forced
 *   - a browser crash invalidates every session and the next request recovers
 *   - a failed context creation leaves no session behind
 *   - shutdown releases every session's browser resources
 */

import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";

// A fixture that sets state on one path and reports it on another, so a
// navigation that lost its context would report the empty values. It is created
// before the worker modules load because its port has to be in the port
// allowlist the URL guard builds at import time.
const fixture = http.createServer((request, response) => {
  const path = request.url.split("?")[0];
  response.setHeader("content-type", "text/html");

  if (path === "/seed") {
    response.setHeader("set-cookie", "session_state=from-session; Path=/");
    response.end(
      "<!doctype html><title>seed</title><body><p>seeded</p>" +
        "<script>localStorage.setItem('marker','session-marker');</script></body>",
    );
    return;
  }

  if (path === "/probe") {
    response.end(
      "<!doctype html><title>probe</title><body><p id=c></p><p id=l></p>" +
        "<script>" +
        "document.getElementById('c').textContent = document.cookie || 'NO-COOKIES';" +
        "document.getElementById('l').textContent = localStorage.getItem('marker') || 'NO-STORE';" +
        "</script></body>",
    );
    return;
  }

  if (path === "/slow") {
    setTimeout(
      () => response.end("<!doctype html><title>slow</title><body>slow</body>"),
      600,
    );
    return;
  }

  response.end("<!doctype html><title>blank</title><body>blank</body>");
});

const fixturePort = await new Promise((resolve, reject) => {
  fixture.once("error", reject);
  fixture.listen(0, "127.0.0.1", () => resolve(fixture.address().port));
});

Object.assign(process.env, {
  ALLOWED_DOMAINS: "127.0.0.1",
  ALLOWED_PORTS: String(fixturePort),
  DEFAULT_DOMAIN_POLICY: "deny",
  BROWSER_ALLOW_PRIVATE_NETWORKS: "true",
  REQUIRE_EGRESS_PROXY: "false",
  EGRESS_PROXY_URL: "",
  EGRESS_PROXY_HEALTH_URL: "",
  NODE_ENV: "test",
});

const { config } = await import("../src/config.js");
const {
  CONTEXT_STATE,
  SessionBusyError,
  SessionForbiddenError,
  SessionLimitExceededError,
  SessionNotFoundError,
  checkoutSession,
  closeBrowser,
  closeExpiredContexts,
  closeSession,
  createIsolatedPage,
  createSession,
  getBrowser,
  getSession,
  getOpenContextCount,
  getOpenSessionCount,
  sessionExists,
} = await import("../src/lib/browser.js");

const fixtureUrl = (path) => `http://127.0.0.1:${fixturePort}${path}`;

/**
 * Time-travel for the expiration sweep: `closeExpiredContexts` takes the clock as
 * an argument, so a lifetime can be exercised without sleeping for minutes.
 */
function sweepAt(futureMs) {
  return closeExpiredContexts({ now: Date.now() + futureMs });
}

/** Checkout, navigate, hand the lease back, and return the rendered text. */
async function navigateIn(session, owner, url) {
  const handle = await checkoutSession({ sessionId: session.sessionId, owner });
  try {
    await handle.page.goto(url, { waitUntil: "networkidle0", timeout: 15000 });
    return await handle.page.evaluate(() => document.body.innerText);
  } finally {
    handle.release();
  }
}

/**
 * Run `body` with one session and always close it, so a failed assertion cannot
 * leak a browser context into the next test.
 */
async function withSession(owner, options, body) {
  const created = await createSession({ owner, ...options });
  try {
    return await body(created);
  } finally {
    await closeSession({ sessionId: created.session.sessionId, owner }).catch(
      () => {},
    );
    if (created.handle) {
      await created.handle.close().catch(() => {});
    }
  }
}

before(async () => {
  await getBrowser();
});

after(async () => {
  await closeBrowser();
  fixture.closeAllConnections?.();
  await new Promise((resolve) => fixture.close(resolve));
});

test("createSession registers a real browser context and reports its lifecycle", async () => {
  await withSession("agent-a", {}, async ({ handle, session }) => {
    assert.match(session.sessionId, /^[0-9a-f-]{36}$/, "server-generated UUID");
    assert.equal(session.state, CONTEXT_STATE.IDLE);
    assert.equal(session.activeRequests, 0);
    assert.equal(session.owner, undefined, "the owner is never published");
    assert.ok(session.expiresAt > session.createdAt);
    assert.equal(getOpenSessionCount(), 1);
    assert.equal(getOpenContextCount(), 1);
    assert.ok(handle.page, "the session owns a real page");

    const fetched = await getSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    assert.equal(fetched.sessionId, session.sessionId);
    assert.equal(fetched.state, CONTEXT_STATE.IDLE);
    assert.equal(fetched.maxAgeMs, config.sessionMaxAgeMs);
  });

  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
});

test("a session keeps cookies and storage across navigations", async () => {
  await withSession("agent-a", {}, async ({ session }) => {
    const seeded = await navigateIn(session, "agent-a", fixtureUrl("/seed"));
    assert.match(seeded, /seeded/);

    const probe = await navigateIn(session, "agent-a", fixtureUrl("/probe"));
    assert.match(probe, /session_state=from-session/, "cookie survived");
    assert.match(probe, /session-marker/, "localStorage survived");

    const status = await getSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    assert.equal(status.currentUrl, fixtureUrl("/probe"));
    assert.ok(status.lastUsedAt > status.createdAt);
  });

  assert.equal(getOpenContextCount(), 0, "closing released the browser context");
});

test("two sessions share no state, even for the same owner", async () => {
  const a = await withSession("agent-a", {}, async (created) => {
    await navigateIn(created.session, "agent-a", fixtureUrl("/seed"));
    return created.session;
  });
  const b = await withSession("agent-a", {}, async ({ session }) => {
    const probe = await navigateIn(session, "agent-a", fixtureUrl("/probe"));
    assert.match(probe, /NO-COOKIES/, "session B saw none of session A's cookie");
    assert.match(probe, /NO-STORE/, "session B saw none of session A's storage");
    return session;
  });

  assert.notEqual(a.sessionId, b.sessionId);
  assert.equal(getOpenContextCount(), 0);
});

test("an unregistered identity still gets a fresh per-request context", async () => {
  const ephemeral = await createIsolatedPage({
    sessionId: "caller-invented-identity",
    requestId: "req-eph",
  });
  try {
    // A2 metadata is not a session: the registry never issued this id, so it
    // selects nothing and a caller cannot claim another agent's context by
    // guessing a readable identity (session fixation).
    assert.equal(sessionExists("caller-invented-identity"), false);
    await assert.rejects(
      checkoutSession({
        sessionId: "caller-invented-identity",
        owner: "agent-a",
      }),
      SessionNotFoundError,
    );
    assert.equal(getOpenSessionCount(), 0);
  } finally {
    await ephemeral.close();
  }

  assert.equal(getOpenContextCount(), 0);
});

test("ownership is required for every session operation", async () => {
  await withSession("agent-a", {}, async ({ session }) => {
    for (const owner of ["agent-b", "agent-a ", "AGENT-A", null, undefined]) {
      await assert.rejects(
        getSession({ sessionId: session.sessionId, owner }),
        SessionForbiddenError,
        `get as ${String(owner)}`,
      );
      await assert.rejects(
        checkoutSession({ sessionId: session.sessionId, owner }),
        SessionForbiddenError,
        `checkout as ${String(owner)}`,
      );
      await assert.rejects(
        closeSession({ sessionId: session.sessionId, owner }),
        SessionForbiddenError,
        `close as ${String(owner)}`,
      );
    }

    // Refused operations must not have consumed or released the lease.
    const status = await getSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    assert.equal(status.state, CONTEXT_STATE.IDLE);
    assert.equal(status.activeRequests, 0);
  });
});

test("the session id alone authorizes nothing", async () => {
  await withSession("agent-a", {}, async ({ session }) => {
    // Possession of the id is necessary but never sufficient: the owner check
    // runs before the context is touched, so a leaked id is useless without the
    // identity that created it.
    await assert.rejects(
      checkoutSession({ sessionId: session.sessionId, owner: "agent-b" }),
      (error) => error instanceof SessionForbiddenError && error.status === 403,
    );
    assert.equal(
      getOpenSessionCount(),
      1,
      "a refused checkout consumed nothing",
    );
  });
});

test("concurrent requests on one session conflict instead of sharing a page", async () => {
  await withSession("agent-a", {}, async ({ session }) => {
    const held = await checkoutSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    const status = await getSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    assert.equal(status.state, CONTEXT_STATE.CHECKED_OUT);
    assert.equal(status.activeRequests, 1);

    await assert.rejects(
      checkoutSession({ sessionId: session.sessionId, owner: "agent-a" }),
      (error) =>
        error instanceof SessionBusyError &&
        error.code === "SESSION_CHECKED_OUT" &&
        error.status === 409,
    );

    held.release();

    // Released: the second request now takes the lease, on the same page.
    const again = await checkoutSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    assert.equal(
      again.page,
      held.page,
      "the same page is handed over, not a new one",
    );
    again.release();
  });

  assert.equal(getOpenContextCount(), 0);
});

test("sessions of different owners are served concurrently", async () => {
  const created = await Promise.all(
    Array.from({ length: 3 }, async (_unused, index) => {
      const { session } = await createSession({ owner: `agent-${index}` });
      return { session, owner: `agent-${index}` };
    }),
  );

  try {
    const bodies = await Promise.all(
      created.map(({ session, owner }, index) =>
        navigateIn(session, owner, fixtureUrl(`/probe?caller=${index}`)),
      ),
    );
    for (const body of bodies) {
      assert.match(body, /NO-COOKIES/);
    }
  } finally {
    for (const { session, owner } of created) {
      await closeSession({ sessionId: session.sessionId, owner }).catch(() => {});
    }
  }

  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
});

test("the session limit refuses a new session instead of sharing one", async () => {
  const original = config.maxSessions;
  config.maxSessions = 2;
  const opened = [];

  try {
    for (const owner of ["agent-a", "agent-b"]) {
      opened.push({ owner, ...(await createSession({ owner })) });
    }

    await assert.rejects(
      createSession({ owner: "agent-c" }),
      (error) =>
        error instanceof SessionLimitExceededError && error.status === 503,
    );
    assert.equal(
      getOpenSessionCount(),
      2,
      "the rejected request created nothing",
    );

    // A freed slot lets the third owner in, with its own context — never a
    // borrowed one.
    await closeSession({ sessionId: opened[0].session.sessionId, owner: "agent-a" });
    const third = await createSession({ owner: "agent-c" });
    opened.push({ owner: "agent-c", ...third });
    assert.notEqual(third.session.sessionId, opened[0].session.sessionId);
    assert.notEqual(third.handle.contextId, opened[0].handle.contextId);
  } finally {
    for (const { session, owner } of opened) {
      await closeSession({ sessionId: session.sessionId, owner }).catch(() => {});
    }
    config.maxSessions = original;
  }

  assert.equal(getOpenSessionCount(), 0);
});

test("an idle session is reaped and stops resolving", async () => {
  const { session } = await createSession({
    owner: "agent-a",
    idleTimeoutMs: 1000,
  });

  try {
    assert.equal(await sweepAt(1500), 1);
    assert.equal(sessionExists(session.sessionId), false);
    assert.equal(getOpenContextCount(), 0);
    await assert.rejects(
      getSession({ sessionId: session.sessionId, owner: "agent-a" }),
      SessionNotFoundError,
    );
  } finally {
    await closeSession({ sessionId: session.sessionId, owner: "agent-a" }).catch(
      () => {},
    );
  }
});

test("no session survives its absolute lifetime, however recently it was used", async () => {
  const { session } = await createSession({
    owner: "agent-a",
    idleTimeoutMs: 600000,
    maxAgeMs: 60000,
  });

  try {
    // Active until the last moment: only the lifetime can retire it.
    const handle = await checkoutSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    handle.release();

    assert.equal(await sweepAt(61000), 1, "max lifetime wins over recent activity");
    assert.equal(sessionExists(session.sessionId), false);
    assert.equal(getOpenContextCount(), 0);
  } finally {
    await closeSession({ sessionId: session.sessionId, owner: "agent-a" }).catch(
      () => {},
    );
  }
});

test("a checked-out session survives sweeps in budget and is reclaimed after its lease lapses", async () => {
  const { session, handle } = await createSession({
    owner: "agent-a",
    idleTimeoutMs: 1,
  });

  try {
    const held = await checkoutSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });

    assert.equal(await sweepAt(100), 0, "an in-budget lease is never reaped");
    assert.equal(sessionExists(session.sessionId), true);

    assert.equal(await sweepAt(config.sessionMaxLeaseMs + 1), 1);
    assert.equal(sessionExists(session.sessionId), false);

    // Releasing a context the sweep already retired must not close it twice.
    assert.equal(held.release(), false);
    await held.close();
    assert.equal(getOpenContextCount(), 0);
  } finally {
    await handle.close().catch(() => {});
    await closeSession({ sessionId: session.sessionId, owner: "agent-a" }).catch(
      () => {},
    );
  }
});

test("closing a session mid-request waits for the request to finish", async () => {
  const { session, handle } = await createSession({ owner: "agent-a" });

  try {
    const held = await checkoutSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    const navigation = held.page.goto(fixtureUrl("/slow"), {
      waitUntil: "load",
      timeout: 15000,
    });

    const { deferred } = await closeSession({
      sessionId: session.sessionId,
      owner: "agent-a",
    });
    assert.equal(deferred, true, "an in-flight request is not cut off");
    assert.equal(getOpenContextCount(), 1);
    assert.equal(sessionExists(session.sessionId), false, "the id stops resolving at once");

    await navigation;
    held.release();
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(getOpenContextCount(), 0, "the deferred close ran on release");
  } finally {
    await handle.close().catch(() => {});
  }
});

test("a closed session cannot be used again by its own owner", async () => {
  const { session } = await createSession({ owner: "agent-a" });
  await closeSession({ sessionId: session.sessionId, owner: "agent-a" });

  await assert.rejects(
    checkoutSession({ sessionId: session.sessionId, owner: "agent-a" }),
    SessionNotFoundError,
  );
  await assert.rejects(
    closeSession({ sessionId: session.sessionId, owner: "agent-a" }),
    SessionNotFoundError,
  );
  assert.equal(getOpenContextCount(), 0, "no context survived the close");
});

test("a failed context creation leaves no session behind", async () => {
  const browser = await getBrowser();
  const original = browser.createBrowserContext;
  browser.createBrowserContext = async () => {
    throw new Error("fixture: context creation failed");
  };

  try {
    await assert.rejects(createSession({ owner: "agent-a" }));
  } finally {
    browser.createBrowserContext = original;
  }

  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0, "a failed session must not leak a context");

  await withSession("agent-a", {}, async () => {});
});

test("a browser crash invalidates every session and the worker recovers", async () => {
  const created = [
    (await createSession({ owner: "agent-a" })).session,
    (await createSession({ owner: "agent-b" })).session,
  ];
  assert.equal(getOpenSessionCount(), 2);

  const browser = await getBrowser();
  browser.process()?.kill("SIGKILL");
  await new Promise((resolve) => setTimeout(resolve, 300));

  assert.equal(getOpenSessionCount(), 0, "no session outlives the browser process");
  assert.equal(getOpenContextCount(), 0);
  await assert.rejects(
    checkoutSession({ sessionId: created[0].sessionId, owner: "agent-a" }),
    SessionNotFoundError,
  );
  await assert.rejects(
    getSession({ sessionId: created[1].sessionId, owner: "agent-b" }),
    SessionNotFoundError,
  );

  await withSession("agent-a", {}, async ({ session }) => {
    const body = await navigateIn(session, "agent-a", fixtureUrl("/probe"));
    assert.match(body, /NO-COOKIES/, "the relaunched browser carries no stale state");
  });
});

test("shutdown releases every session", async () => {
  const { session, handle } = await createSession({ owner: "agent-a" });
  const held = await checkoutSession({ sessionId: session.sessionId, owner: "agent-a" });

  await closeBrowser();

  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
  assert.equal(held.release(), false, "the shutdown path owns the release");
  await handle.close().catch(() => {});

  await withSession("agent-a", {}, async () => {});
});
