/**
 * A3 — session routes over HTTP, with a real browser behind them.
 *
 * These exercise the worker's public surface: authentication still applies to
 * every session route, the owner header is mandatory for session operations, an
 * identity the registry never issued cannot open a session, and a registered
 * session keeps its state across two `/v1/navigate` calls while an ordinary
 * navigation still closes its context.
 */

import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";

const fixture = http.createServer((request, response) => {
  const path = request.url.split("?")[0];
  response.setHeader("content-type", "text/html");

  if (path === "/seed") {
    response.setHeader("set-cookie", "route_state=from-route; Path=/");
    response.end("<!doctype html><title>seed</title><body><p>seeded</p></body>");
    return;
  }

  if (path === "/probe") {
    response.end(
      "<!doctype html><title>probe</title><body><p id=c></p>" +
        "<script>document.getElementById('c').textContent=" +
        "document.cookie || 'NO-COOKIES';</script></body>",
    );
    return;
  }

  if (path === "/slow") {
    setTimeout(
      () => response.end("<!doctype html><title>slow</title><body>slow</body>"),
      800,
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
  WORKER_AUTH_TOKEN: "route-test-token",
  NODE_ENV: "test",
});

const { config } = await import("../src/config.js");
const {
  closeBrowser,
  getOpenContextCount,
  getOpenSessionCount,
} = await import("../src/lib/browser.js");
const { createApp } = await import("../src/app.js");

const fixtureUrl = (path) => `http://127.0.0.1:${fixturePort}${path}`;
const AUTH = { authorization: "Bearer route-test-token" };

const server = http.createServer(createApp());
const appPort = await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => resolve(server.address().port));
});

function request(method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: appPort,
        path,
        method,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...headers,
        },
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          text += chunk;
        });
        response.on("end", () => {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* keep raw text */
          }
          resolve({ status: response.statusCode, text, json });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

const post = (path, options) => request("POST", path, options);
const get = (path, options) => request("GET", path, options);
const del = (path, options) => request("DELETE", path, options);

async function createSessionViaApi(agentId, body) {
  const response = await post("/v1/session", {
    headers: { ...AUTH, "x-agent-id": agentId },
    body: body ?? {},
  });
  assert.equal(response.status, 201, response.text);
  return response.json;
}

async function closeSessionViaApi(sessionId, agentId) {
  return del(`/v1/session/${sessionId}`, {
    headers: { ...AUTH, "x-agent-id": agentId },
  });
}

before(async () => {
  config.workerAuthToken = "route-test-token";
});

after(async () => {
  await closeBrowser();
  fixture.closeAllConnections?.();
  await new Promise((resolve) => fixture.close(resolve));
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
});

test("session routes are behind worker authentication", async () => {
  const unauthenticated = await post("/v1/session", {
    headers: { "x-agent-id": "agent-a" },
    body: {},
  });
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.json.code, "WORKER_AUTH_FAILED");

  const wrongToken = await post("/v1/session", {
    headers: { ...AUTH, authorization: "Bearer nope", "x-agent-id": "agent-a" },
    body: {},
  });
  assert.equal(wrongToken.status, 401);

  // A session id is not a credential: presenting one cannot unlock a route.
  const created = await createSessionViaApi("agent-a");
  try {
    const forged = await get(`/v1/session/${created.session_id}`, {
      headers: { "x-agent-session": created.session_id, "x-agent-id": "agent-a" },
    });
    assert.equal(forged.status, 401);
  } finally {
    await closeSessionViaApi(created.session_id, "agent-a");
  }

  assert.equal(getOpenContextCount(), 0);
});

test("session operations require an owner identity", async () => {
  const missing = await post("/v1/session", { headers: { ...AUTH }, body: {} });
  assert.equal(missing.status, 400);
  assert.equal(missing.json.code, "INVALID_AGENT_ID");

  const malformed = await post("/v1/session", {
    headers: { ...AUTH, "x-agent-id": "agent a;drop" },
    body: {},
  });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.json.code, "INVALID_AGENT_ID");
  // Nothing caller-supplied is echoed back.
  assert.ok(!malformed.text.includes("agent a;drop"));

  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
});

test("create, read and close a session over HTTP", async () => {
  const created = await createSessionViaApi("agent-a");

  assert.match(created.session_id, /^[0-9a-f-]{36}$/);
  assert.equal(created.state, "idle");
  assert.equal(created.active_requests, 0);
  assert.equal(created.agent_id, undefined, "the owner is never in a response body");
  assert.ok(Date.parse(created.expires_at) > Date.parse(created.created_at));
  assert.equal(getOpenSessionCount(), 1);
  assert.equal(getOpenContextCount(), 1, "the session holds a real browser context");

  const status = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(status.status, 200);
  assert.equal(status.json.session_id, created.session_id);
  assert.equal(status.json.idle_timeout_ms, config.sessionIdleTimeoutMs);
  assert.equal(status.json.max_age_ms, config.sessionMaxAgeMs);

  const closed = await closeSessionViaApi(created.session_id, "agent-a");
  assert.equal(closed.status, 200);
  assert.equal(closed.json.closed, true);
  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);

  const gone = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(gone.status, 404);
  assert.equal(gone.json.code, "SESSION_NOT_FOUND");
});

test("another owner cannot read or close a session", async () => {
  const created = await createSessionViaApi("agent-a");

  const foreignRead = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-b" },
  });
  assert.equal(foreignRead.status, 403);
  assert.equal(foreignRead.json.code, "SESSION_FORBIDDEN");

  const foreignClose = await closeSessionViaApi(created.session_id, "agent-b");
  assert.equal(foreignClose.status, 403);
  assert.equal(foreignClose.json.code, "SESSION_FORBIDDEN");

  const stillThere = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(stillThere.status, 200, "a refused close changed nothing");

  await closeSessionViaApi(created.session_id, "agent-a");
});

test("a malformed or unknown session id in the path is refused", async () => {
  const malformed = await get("/v1/session/not%20an%20id", {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.json.code, "INVALID_SESSION_ID");

  const unknown = await get(
    "/v1/session/00000000-0000-4000-8000-000000000000",
    { headers: { ...AUTH, "x-agent-id": "agent-a" } },
  );
  assert.equal(unknown.status, 404);
  assert.equal(unknown.json.code, "SESSION_NOT_FOUND");
});

test("lifetime requests may shorten but never extend the operator limits", async () => {
  const tooShort = await post("/v1/session", {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
    body: { idle_timeout_ms: 1000 },
  });
  assert.equal(tooShort.status, 400);
  assert.equal(tooShort.json.code, "INVALID_REQUEST");

  const tooLong = await post("/v1/session", {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
    body: { max_age_ms: config.sessionMaxAgeMs + 1 },
  });
  assert.equal(tooLong.status, 400);

  const shorter = await createSessionViaApi("agent-a", {
    idle_timeout_ms: 60000,
    max_age_ms: 120000,
  });
  try {
    assert.equal(shorter.idle_timeout_ms, 60000);
    assert.equal(shorter.max_age_ms, 120000);
  } finally {
    await closeSessionViaApi(shorter.session_id, "agent-a");
  }

  assert.equal(getOpenContextCount(), 0);
});

test("navigations inside a session keep state; ordinary navigations do not", async () => {
  const created = await createSessionViaApi("agent-a");
  const sessionHeaders = {
    ...AUTH,
    "x-agent-id": "agent-a",
    "x-agent-session": created.session_id,
  };

  const seeded = await post("/v1/navigate", {
    headers: sessionHeaders,
    body: { url: fixtureUrl("/seed"), wait_until: "load" },
  });
  assert.equal(seeded.status, 200, seeded.text);
  assert.equal(getOpenContextCount(), 1, "the session context is still registered");

  const probe = await post("/v1/navigate", {
    headers: sessionHeaders,
    body: { url: fixtureUrl("/probe"), wait_until: "load" },
  });
  assert.equal(probe.status, 200, probe.text);
  assert.match(probe.json.content, /route_state=from-route/, "state persisted");
  assert.equal(getOpenSessionCount(), 1);

  const status = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(status.json.active_requests, 0, "the lease was handed back");
  assert.equal(status.json.current_url, fixtureUrl("/probe"));

  await closeSessionViaApi(created.session_id, "agent-a");

  // The same header pair with no registered session is an ordinary navigation:
  // nothing is created and nothing survives.
  const anonymous = await post("/v1/navigate", {
    headers: { ...AUTH, "x-agent-id": "agent-a", "x-agent-session": "ad-hoc-identity" },
    body: { url: fixtureUrl("/seed"), wait_until: "load" },
  });
  assert.equal(anonymous.status, 200, anonymous.text);
  const anonymousProbe = await post("/v1/navigate", {
    headers: { ...AUTH, "x-agent-id": "agent-a", "x-agent-session": "ad-hoc-identity" },
    body: { url: fixtureUrl("/probe"), wait_until: "load" },
  });
  assert.match(anonymousProbe.json.content, /NO-COOKIES/, "no session was created");
  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
});

test("navigation cannot use another caller's session", async () => {
  const created = await createSessionViaApi("agent-a");

  const wrongOwner = await post("/v1/navigate", {
    headers: {
      ...AUTH,
      "x-agent-id": "agent-b",
      "x-agent-session": created.session_id,
    },
    body: { url: fixtureUrl("/blank"), wait_until: "load" },
  });
  assert.equal(wrongOwner.status, 403);
  assert.equal(wrongOwner.json.code, "SESSION_FORBIDDEN");

  const noOwner = await post("/v1/navigate", {
    headers: { ...AUTH, "x-agent-session": created.session_id },
    body: { url: fixtureUrl("/blank"), wait_until: "load" },
  });
  assert.equal(noOwner.status, 403);
  assert.equal(noOwner.json.code, "SESSION_FORBIDDEN");

  const status = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(status.json.state, "idle", "a refused navigation took no lease");

  await closeSessionViaApi(created.session_id, "agent-a");
  assert.equal(getOpenContextCount(), 0);
});

test("two concurrent navigations on one session conflict, not corrupt", async () => {
  const created = await createSessionViaApi("agent-a");
  const headers = {
    ...AUTH,
    "x-agent-id": "agent-a",
    "x-agent-session": created.session_id,
  };

  const first = post("/v1/navigate", {
    headers,
    body: { url: fixtureUrl("/slow"), wait_until: "load" },
  });
  await new Promise((resolve) => setTimeout(resolve, 150));

  const second = await post("/v1/navigate", {
    headers,
    body: { url: fixtureUrl("/blank"), wait_until: "load" },
  });
  const firstResponse = await first;

  assert.equal(firstResponse.status, 200, firstResponse.text);
  assert.equal(second.status, 409);
  assert.equal(second.json.code, "SESSION_CHECKED_OUT");

  const status = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(status.json.state, "idle");
  assert.equal(status.json.active_requests, 0);

  await closeSessionViaApi(created.session_id, "agent-a");
});

test("a session navigation still enforces the egress and URL guards", async () => {
  const created = await createSessionViaApi("agent-a");
  const headers = {
    ...AUTH,
    "x-agent-id": "agent-a",
    "x-agent-session": created.session_id,
  };

  const blockedDomain = await post("/v1/navigate", {
    headers,
    body: { url: "http://not-allowed.test/", wait_until: "load" },
  });
  assert.equal(blockedDomain.status, 403);

  const malformedUrl = await post("/v1/navigate", {
    headers,
    body: { url: "file:///etc/passwd", wait_until: "load" },
  });
  assert.equal(malformedUrl.status, 400);

  const loopbackMetadata = await post("/v1/navigate", {
    headers,
    body: { url: "http://169.254.169.254/latest/meta-data/", wait_until: "load" },
  });
  assert.equal(loopbackMetadata.status, 403);

  const status = await get(`/v1/session/${created.session_id}`, {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
  });
  assert.equal(status.json.state, "idle", "refused navigations left the lease alone");

  await closeSessionViaApi(created.session_id, "agent-a");
});

test("closing a session mid-navigation is deferred, and the id stops resolving", async () => {
  const created = await createSessionViaApi("agent-a");
  const headers = {
    ...AUTH,
    "x-agent-id": "agent-a",
    "x-agent-session": created.session_id,
  };

  const navigation = post("/v1/navigate", {
    headers,
    body: { url: fixtureUrl("/slow"), wait_until: "load" },
  });
  await new Promise((resolve) => setTimeout(resolve, 150));

  const closed = await closeSessionViaApi(created.session_id, "agent-a");
  assert.equal(closed.status, 200);
  assert.equal(closed.json.closing, true);
  assert.equal(getOpenContextCount(), 1, "the in-flight request keeps its context");

  const done = await navigation;
  assert.equal(done.status, 200, done.text);
  await new Promise((resolve) => setTimeout(resolve, 50));

  assert.equal(getOpenContextCount(), 0, "the deferred close ran when the lease lapsed");
  assert.equal(getOpenSessionCount(), 0);
});
