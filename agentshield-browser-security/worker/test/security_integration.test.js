import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import http from "node:http";
import { after, test } from "node:test";

import { createEgressPolicy } from "../../proxy/src/lib/policy.js";
import {
  createEgressProxy,
  createProxyHealthServer,
} from "../../proxy/src/lib/proxy.js";

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  server.closeAllConnections?.();
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

const targetHits = [];
const proxyEvents = [];
const targetServer = http.createServer((request, response) => {
  targetHits.push({ host: request.headers.host, path: request.url });
  if (request.url === "/set-cookie") {
    response.setHeader("set-cookie", "session=isolated; Path=/; SameSite=Lax");
  }
  if (request.url === "/cookie-probe") {
    // Reports the browser context's own cookie jar, so a navigation that
    // inherited another request's state would say so in the returned content.
    response.setHeader("content-type", "text/html");
    response.end(
      "<!doctype html><title>cookie probe</title><body><p id=c></p>" +
        "<script>document.getElementById('c').textContent=" +
        "document.cookie || 'NO-COOKIES';</script></body>",
    );
    return;
  }
  if (request.url === "/popup-test") {
    response.setHeader("content-type", "text/html");
    response.end(
      `<a id="popup" target="_blank" href="http://blocked.test:${targetPort}/popup">open</a>`,
    );
    return;
  }
  if (request.url === "/inline-nav-test") {
    response.setHeader("content-type", "text/html");
    response.end(
      "<!doctype html><title>inline navigation</title><body>" +
        '<a id="data" href="data:text/html,%3Ctitle%3Edata-ok%3C/title%3E">data</a>' +
        '<a id="blob" href="#">blob</a>' +
        "<script>try { document.getElementById('blob').href=URL.createObjectURL(" +
        'new Blob(["<title>blob-ok</title>"], {type: "text/html"})); } catch {}</script>' +
        "</body>",
    );
    return;
  }
  if (request.url === "/slow") {
    // Holds a navigation open long enough to span many cleanup sweeps.
    setTimeout(() => {
      response.setHeader("content-type", "text/html");
      response.end("<!doctype html><title>slow fixture</title><body>slow-ok</body>");
    }, 700);
    return;
  }
  if (request.url === "/stall") {
    // Never responds, so a navigation times out after its context exists.
    return;
  }
  response.setHeader("content-type", "text/html");
  response.end("<!doctype html><title>controlled fixture</title><body>ok</body>");
});

const targetPort = await listen(targetServer);
const policy = createEgressPolicy({
  allowedDomains: "allowed.test",
  blockedDomains: "blocked.test",
  allowedPorts: String(targetPort),
  defaultDomainPolicy: "deny",
  allowPrivateNetworks: true,
  resolver: async () => [{ address: "127.0.0.1", family: 4 }],
});
const proxy = createEgressProxy({
  policy,
  authToken: "integration-proxy-token",
  logger: {
    warn(event, fields) {
      proxyEvents.push({ level: "warn", event, fields });
    },
    debug(event, fields) {
      proxyEvents.push({ level: "debug", event, fields });
    },
  },
});
const proxyPort = await listen(proxy);
const health = createProxyHealthServer({ policy });
const healthPort = await listen(health);

Object.assign(process.env, {
  ALLOWED_DOMAINS: "allowed.test",
  BLOCKED_DOMAINS: "blocked.test",
  DEFAULT_DOMAIN_POLICY: "deny",
  ALLOWED_PORTS: String(targetPort),
  BROWSER_ALLOW_PRIVATE_NETWORKS: "true",
  BROWSER_ALLOW_WEBRTC: "false",
  BROWSER_HEADLESS: "true",
  EGRESS_PROXY_URL: `http://127.0.0.1:${proxyPort}`,
  EGRESS_PROXY_HEALTH_URL: `http://127.0.0.1:${healthPort}/health/ready`,
  PROXY_AUTH_TOKEN: "integration-proxy-token",
  REQUIRE_EGRESS_PROXY: "true",
});

const { config } = await import("../src/config.js");
const {
  closeBrowser,
  closeExpiredContexts,
  createIsolatedPage,
  getBrowser,
  getOpenContextCount,
} = await import("../src/lib/browser.js");
const { installPageSecurity } = await import("../src/lib/page_security.js");
const { startSessionCleanupTimer } = await import("../src/lib/session_cleanup.js");
const { createApp } = await import("../src/app.js");
const baseUrl = `http://allowed.test:${targetPort}`;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** POST JSON to the worker HTTP app and return the status plus body text. */
function postJson(port, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const request = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(data),
          ...headers,
        },
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          text += chunk;
        });
        response.on("end", () =>
          resolve({ status: response.statusCode, body: text }),
        );
      },
    );
    request.on("error", reject);
    request.end(data);
  });
}

after(async () => {
  await closeBrowser();
  await close(proxy);
  await close(health);
  await close(targetServer);
});

test("isolates cookies and local storage between browser contexts", async () => {
  const first = await createIsolatedPage({ sessionId: "session-a" });
  try {
    await first.page.goto(`${baseUrl}/set-cookie`, { waitUntil: "load" });
    await first.page.evaluate(() =>
      localStorage.setItem("session-secret", "session-a-value"),
    );
  } finally {
    await first.close();
  }

  const second = await createIsolatedPage({ sessionId: "session-b" });
  try {
    await second.page.goto(`${baseUrl}/blank`, { waitUntil: "load" });
    const state = await second.page.evaluate(() => ({
      cookie: document.cookie,
      localStorage: localStorage.getItem("session-secret"),
    }));
    assert.deepEqual(state, { cookie: "", localStorage: null });
  } finally {
    await second.close();
  }

  assert.equal(getOpenContextCount(), 0);
});

test("carries a session identity through a real navigation without echoing it", async () => {
  const server = http.createServer(createApp());
  const appPort = await listen(server);

  try {
    const response = await postJson(
      appPort,
      "/v1/navigate",
      { url: `${baseUrl}/blank`, wait_until: "load" },
      { "x-agent-session": "conv-secret-42" },
    );

    assert.equal(response.status, 200, response.body);
    // The identity is metadata for the worker, not part of any response body.
    assert.ok(!response.body.includes("conv-secret-42"), response.body);
    assert.equal(getOpenContextCount(), 0, "a completed request must release its context");
  } finally {
    await close(server);
  }
});

test("rejects a malformed session identity over HTTP without launching a context", async () => {
  const server = http.createServer(createApp());
  const appPort = await listen(server);

  try {
    const response = await postJson(
      appPort,
      "/v1/navigate",
      { url: `${baseUrl}/blank`, wait_until: "load" },
      { "x-agent-session": "conv 42" },
    );

    assert.equal(response.status, 400);
    assert.match(response.body, /INVALID_SESSION_ID/);
    assert.equal(getOpenContextCount(), 0);
  } finally {
    await close(server);
  }
});

test("keeps HTTP navigations under different session IDs isolated", async () => {
  const server = http.createServer(createApp());
  const appPort = await listen(server);

  async function navigate(path, sessionId) {
    const response = await postJson(
      appPort,
      "/v1/navigate",
      { url: `${baseUrl}${path}`, wait_until: "load" },
      { "x-agent-session": sessionId },
    );
    assert.equal(response.status, 200, response.body);
    return response.body;
  }

  try {
    await navigate("/set-cookie", "conv-owner-a");
    const observed = await navigate("/cookie-probe", "conv-owner-b");

    assert.ok(observed.includes("NO-COOKIES"), observed);
    assert.ok(!observed.includes("session=isolated"), observed);
  } finally {
    await close(server);
  }
});

test("a repeated session ID does not resume a previous browser context", async () => {
  const server = http.createServer(createApp());
  const appPort = await listen(server);

  async function navigate(path) {
    const response = await postJson(
      appPort,
      "/v1/navigate",
      { url: `${baseUrl}${path}`, wait_until: "load" },
      { "x-agent-session": "conv-reused-identity" },
    );
    assert.equal(response.status, 200, response.body);
    return response.body;
  }

  try {
    // A2 propagates identity only. If this ever sees the cookie, the worker has
    // started selecting a context by session ID, which is A3 behavior.
    await navigate("/set-cookie");
    const observed = await navigate("/cookie-probe");

    assert.ok(observed.includes("NO-COOKIES"), observed);
    assert.equal(getOpenContextCount(), 0);
  } finally {
    await close(server);
  }
});

test("attaches the session identity to context metadata only", async () => {
  const first = await createIsolatedPage({ sessionId: "shared-identity", requestId: "req-1" });
  const second = await createIsolatedPage({ sessionId: "shared-identity", requestId: "req-2" });

  try {
    assert.equal(first.sessionId, "shared-identity");
    assert.equal(second.sessionId, "shared-identity");
    // Same identity, two unrelated contexts: the ID selects nothing.
    assert.notEqual(first.contextId, second.contextId);
    assert.notEqual(first.page, second.page);
    assert.equal(getOpenContextCount(), 2);
  } finally {
    await first.close();
    await second.close();
  }

  const anonymous = await createIsolatedPage({ requestId: "req-3" });
  try {
    assert.equal(anonymous.sessionId, null);
  } finally {
    await anonymous.close();
  }

  assert.equal(getOpenContextCount(), 0);
});

test("reaps a released real browser context and preserves a checked-out one", async () => {
  const originalIdleTimeoutMs = config.sessionIdleTimeoutMs;
  // Comfortably above the ~100-300ms it takes createIsolatedPage() to return,
  // so the sweep never races a context that is still being constructed.
  const idleTimeoutMs = 1000;
  config.sessionIdleTimeoutMs = idleTimeoutMs;

  let aged;
  let fresh;
  try {
    aged = await createIsolatedPage({ sessionId: "expiration-aged" });
    await aged.page.goto(`${baseUrl}/blank`, { waitUntil: "load" });
    assert.equal(aged.context.closed, false);

    await delay(idleTimeoutMs + 500);

    // Created after the aged context has already passed the idle window.
    fresh = await createIsolatedPage({ sessionId: "expiration-fresh" });

    // A checked-out context is not expiration-eligible at any age: the sweep is
    // a no-op while both requests still hold their leases.
    assert.equal(
      await closeExpiredContexts(),
      0,
      "a checked-out context must not be reaped",
    );
    assert.equal(aged.context.closed, false);

    // Releasing the aged context makes it idle, then eligible.
    assert.equal(aged.release(), true);
    await delay(idleTimeoutMs + 100);

    const closed = await closeExpiredContexts();

    assert.equal(closed, 1, "only the released idle context should be reaped");
    assert.equal(aged.context.closed, true, "the real browser context is closed");
    assert.equal(fresh.context.closed, false, "the checked-out context must survive");
    assert.equal(getOpenContextCount(), 1);

    const liveContexts = (await getBrowser()).browserContexts();
    assert.equal(liveContexts.includes(aged.context), false);
    assert.equal(liveContexts.includes(fresh.context), true);
  } finally {
    config.sessionIdleTimeoutMs = originalIdleTimeoutMs;
    await Promise.allSettled([aged?.close(), fresh?.close()]);
  }

  assert.equal(getOpenContextCount(), 0, "no context may leak into other tests");
});

test("the background timer expires real contexts without any HTTP request", async () => {
  const originalIdleTimeoutMs = config.sessionIdleTimeoutMs;
  config.sessionIdleTimeoutMs = 1000;

  const timer = startSessionCleanupTimer({
    cleanupFn: closeExpiredContexts,
    intervalMs: 50,
  });
  let secured;
  try {
    secured = await createIsolatedPage({ sessionId: "timer-driven" });
    assert.equal(secured.context.closed, false);

    // Held while checked out, even though the sweep is running every 50ms and
    // the idle window is already past.
    secured.release();

    // No request, no /health/ready call: the interval alone must reap it.
    const deadline = Date.now() + 8000;
    while (!secured.context.closed && Date.now() < deadline) {
      await delay(25);
    }

    assert.equal(secured.context.closed, true, "timer must close the idle context");
    assert.equal(getOpenContextCount(), 0);
  } finally {
    await timer.stop();
    config.sessionIdleTimeoutMs = originalIdleTimeoutMs;
    await Promise.allSettled([secured?.close()]);
  }
});

test("an in-flight real navigation survives aggressive cleanup sweeps", async () => {
  // Regression for the failure observed before the lease existed: with
  // BROWSER_SESSION_IDLE_TIMEOUT_MS far below the request duration, sweeps ran
  // the context.close() out from under a live navigation and /v1/navigate
  // answered 500 with browser_context_close_failed in the log.
  const originalIdleTimeoutMs = config.sessionIdleTimeoutMs;
  const originalMaxLeaseMs = config.sessionMaxLeaseMs;
  config.sessionIdleTimeoutMs = 50;
  config.sessionMaxLeaseMs = 30000;

  const server = http.createServer(createApp());
  const appPort = await listen(server);
  const timer = startSessionCleanupTimer({
    cleanupFn: closeExpiredContexts,
    intervalMs: 20,
  });

  try {
    const response = await postJson(appPort, "/v1/navigate", {
      url: `${baseUrl}/slow`,
      wait_until: "load",
      timeout_ms: 9000,
    });

    assert.equal(
      response.status,
      200,
      `in-flight context must survive ~35 sweeps: ${response.status} ${response.body}`,
    );
    assert.match(response.body, /slow-ok/);
    assert.equal(
      getOpenContextCount(),
      0,
      "the request must release its context when it completes",
    );
  } finally {
    await timer.stop();
    config.sessionIdleTimeoutMs = originalIdleTimeoutMs;
    config.sessionMaxLeaseMs = originalMaxLeaseMs;
    await close(server);
  }
});

test("a navigation that fails still releases and closes its context", async () => {
  const browser = await getBrowser();
  const liveContextsBefore = browser.browserContexts().length;
  const server = http.createServer(createApp());
  const appPort = await listen(server);

  try {
    // /stall never responds, so page.goto() times out after the context and
    // page exist — the failure path that could otherwise strand a lease.
    const response = await postJson(appPort, "/v1/navigate", {
      url: `${baseUrl}/stall`,
      wait_until: "load",
      timeout_ms: 1000,
    });

    assert.notEqual(response.status, 200, "a stalled navigation must not succeed");
    assert.equal(
      getOpenContextCount(),
      0,
      "a failed request must not leave a context checked out",
    );

    // The handler's finally closes the context after the response has already
    // been flushed, so wait for Chromium to acknowledge the close rather than
    // asserting against a transient count.
    const deadline = Date.now() + 5000;
    while (
      browser.browserContexts().length > liveContextsBefore &&
      Date.now() < deadline
    ) {
      await delay(50);
    }

    assert.equal(
      browser.browserContexts().length,
      liveContextsBefore,
      `failed navigation leaked ${
        browser.browserContexts().length - liveContextsBefore
      } real browser contexts`,
    );
  } finally {
    await close(server);
  }
});

test("the timeout the route accepts is the value the lease ceiling is floored on", async () => {
  const server = http.createServer(createApp());
  const appPort = await listen(server);

  try {
    const response = await postJson(appPort, "/v1/navigate", {
      url: `${baseUrl}/blank`,
      timeout_ms: config.navigationTimeoutMaxMs + 1,
    });

    assert.equal(response.status, 400);
    // If these two ever disagree, a request could outlive the lease protecting
    // its browser context.
    assert.match(response.body, new RegExp(String(config.navigationTimeoutMaxMs)));
    assert.ok(
      config.sessionMaxLeaseMs > config.navigationTimeoutMaxMs,
      "the lease ceiling must exceed the largest accepted navigation timeout",
    );
    assert.equal(getOpenContextCount(), 0, "a rejected request must not register a context");
  } finally {
    await close(server);
  }
});

test("the lifecycle state machine holds for a real browser context", async () => {
  const originalIdleTimeoutMs = config.sessionIdleTimeoutMs;
  config.sessionIdleTimeoutMs = 50;

  const secured = await createIsolatedPage({ sessionId: "state-machine" });
  let closeCalls = 0;
  const realClose = secured.context.close.bind(secured.context);
  secured.context.close = async () => {
    closeCalls += 1;
    return realClose();
  };

  try {
    assert.equal(
      secured.checkOut(),
      false,
      "a context already checked out cannot be leased twice",
    );

    assert.equal(secured.release(), true);
    assert.equal(secured.release(), false, "release is idempotent");
    assert.equal(secured.checkOut(), true, "an idle context can be leased again");
    assert.equal(secured.checkOut(), false, "re-lease is exclusive");
    assert.equal(secured.release(), true);

    // Idle past the timeout: the sweep wins the race against the request.
    await delay(150);
    assert.equal(await closeExpiredContexts(), 1);
    assert.equal(secured.context.closed, true);

    // The request handle now closes the same context it no longer owns.
    await secured.close();
    await secured.close();
    assert.equal(closeCalls, 1, "the real context is closed exactly once");
    assert.equal(getOpenContextCount(), 0);
  } finally {
    config.sessionIdleTimeoutMs = originalIdleTimeoutMs;
    await secured.close();
  }
});



test("blocks page-triggered data navigation and document blob creation", async () => {
  const secured = await createIsolatedPage({ requestId: "inline-nav-test" });
  try {
    await installPageSecurity(secured.page, { requestId: "inline-nav-test" });
    await secured.page.goto(`${baseUrl}/inline-nav-test`, { waitUntil: "load" });
    const originalUrl = secured.page.url();

    await secured.page.click("#data").catch(() => {});
    await delay(150);
    assert.equal(secured.page.url(), originalUrl, "data: navigation must be blocked");

    const blobResult = await secured.page.evaluate(() => {
      try {
        URL.createObjectURL(
          new Blob(["<title>blob-ok</title>"], { type: "text/html" }),
        );
        return "allowed";
      } catch (error) {
        return error.name;
      }
    });
    assert.equal(blobResult, "SecurityError", "document blob creation must be blocked");
  } finally {
    await secured.close();
  }
});

test("blocks popup destinations at the proxy before the fixture receives them", async () => {
  targetHits.length = 0;
  proxyEvents.length = 0;

  const secured = await createIsolatedPage({ requestId: "popup-test" });
  try {
    await installPageSecurity(secured.page, { requestId: "popup-test" });
    await secured.page.goto(`${baseUrl}/popup-test`, { waitUntil: "load" });

    const popupPromise = new Promise((resolve) =>
      secured.page.once("popup", resolve),
    );
    await secured.page.click("#popup");
    const popup = await popupPromise;
    if (!popup.isClosed()) {
      await new Promise((resolve) => popup.once("close", resolve));
    }

    assert.equal(
      targetHits.some((hit) => hit.path === "/popup"),
      false,
    );
    assert.equal(
      proxyEvents.some(
        ({ event, fields }) =>
          event === "egress_blocked" && fields.code === "DOMAIN_BLOCKED",
      ),
      true,
      "the proxy must reject the popup destination",
    );
  } finally {
    await secured.close();
  }
});

test("disables WebRTC APIs and refuses configuration without a UDP policy", async () => {
  const secured = await createIsolatedPage({ requestId: "webrtc-test" });
  try {
    await installPageSecurity(secured.page, { requestId: "webrtc-test" });
    await secured.page.goto(`${baseUrl}/blank`, { waitUntil: "load" });
    const peerConnection = await secured.page.evaluate(
      () => typeof window.RTCPeerConnection,
    );
    assert.equal(peerConnection, "undefined");
  } finally {
    await secured.close();
  }

  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const { getBrowser } = await import(${JSON.stringify(
        new URL("../src/lib/browser.js", import.meta.url).href,
      )}); try { await getBrowser(); process.exitCode = 1; } catch (error) { console.log(error.code); }`,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        BROWSER_ALLOW_WEBRTC: "true",
      },
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /WEBRTC_POLICY_UNAVAILABLE/);
});

test("fails closed when the required egress proxy is missing or unavailable", () => {
  const egressModule = new URL("../src/lib/egress.js", import.meta.url).href;
  for (const [proxyUrl, healthUrl, expectedCode] of [
    ["", "", "NETWORK_EGRESS_BLOCKED"],
    [
      "http://127.0.0.1:1",
      "http://127.0.0.1:1/health/ready",
      "EGRESS_PROXY_UNAVAILABLE",
    ],
  ]) {
    const result = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `const { assertEgressEnforcement } = await import(${JSON.stringify(egressModule)}); try { await assertEgressEnforcement({ force: true }); process.exitCode = 1; } catch (error) { console.log(error.code); }`,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          EGRESS_PROXY_URL: proxyUrl,
          EGRESS_PROXY_HEALTH_URL: healthUrl,
          EGRESS_PROXY_HEALTH_TIMEOUT_MS: "100",
          REQUIRE_EGRESS_PROXY: "true",
        },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(expectedCode));
  }
});

test("shutdown retires checked-out and idle contexts without double-closing", async () => {
  const originalIdleTimeoutMs = config.sessionIdleTimeoutMs;
  config.sessionIdleTimeoutMs = 40;

  const held = await createIsolatedPage({ sessionId: "shutdown-held" });
  const idle = await createIsolatedPage({ sessionId: "shutdown-idle" });

  try {
    idle.release();
    await delay(120);

    // The sweep may only take the released context; the lease holds the other.
    assert.equal(await closeExpiredContexts(), 1);
    assert.equal(held.context.closed, false, "shutdown-unrelated sweep keeps the lease");
    assert.equal(getOpenContextCount(), 1);

    // Shutdown is unconditional and must retire what the sweep could not.
    await closeBrowser();
    assert.equal(held.context.closed, true);
    assert.equal(getOpenContextCount(), 0);

    // Handles belonging to a torn-down browser must not close anything twice.
    await held.close();
    await idle.close();
    assert.equal(getOpenContextCount(), 0);
  } finally {
    config.sessionIdleTimeoutMs = originalIdleTimeoutMs;
    // closeBrowser() already disconnected; relaunching for later tests is
    // handled lazily by getBrowser().
  }
});
