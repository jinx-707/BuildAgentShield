/**
 * Worker authentication middleware tests.
 *
 * Tests the inbound Bearer-token auth applied to all /v1/* routes.
 * Uses only Node built-ins + the Express app under test — no Puppeteer,
 * no proxy, no real browser required.
 *
 * Coverage:
 *   - Valid token accepted with 200 / non-401 response
 *   - Missing Authorization header rejected with 401
 *   - Malformed header (no "Bearer " prefix) rejected with 401
 *   - Wrong token rejected with 401
 *   - Empty token value rejected with 401
 *   - Auth disabled (empty WORKER_AUTH_TOKEN) passes in non-production
 *   - Production + empty token → createApp() throws at startup
 *   - Production + empty token → hasValidWorkerToken denies in-flight requests
 *   - 401 responses carry WWW-Authenticate: Bearer header
 *   - Navigation logic is unreachable without a valid token
 *   - Health endpoints (/health/live, /health, /health/ready-alias) are
 *     always reachable without a token
 *   - Request-ID header is echoed on 401 responses
 */

import assert from "node:assert/strict";
import http from "node:http";
import { after, before, describe, it } from "node:test";

import { config } from "../src/config.js";
import { createApp } from "../src/app.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function listen(app) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.closeAllConnections?.();
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Sends a single HTTP request to the running server and returns
 * { statusCode, headers, body (parsed JSON) }.
 */
function request(server, { method = "GET", path, headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const { port } = server.address();
    const payload =
      body !== undefined ? JSON.stringify(body) : undefined;

    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        headers: {
          "content-type": "application/json",
          ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          let parsed;
          try {
            parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } catch {
            parsed = null;
          }
          resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed });
        });
      },
    );
    req.on("error", reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Auth-token suite — token is "test-secret-token"
// ---------------------------------------------------------------------------

describe("worker auth middleware — token configured", () => {
  const TOKEN = "test-secret-token";
  let server;

  before(async () => {
    // Temporarily override config for this suite
    config.workerAuthToken = TOKEN;
    config.environment = "test";
    server = await listen(createApp());
  });

  after(async () => {
    config.workerAuthToken = "";
    await close(server);
  });

  // --- 401 cases -----------------------------------------------------------

  it("rejects a request with no Authorization header", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
    assert.equal(res.body?.error, "unauthorized");
  });

  it("rejects a request with malformed header (no Bearer prefix)", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: TOKEN },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
  });

  it("rejects a request with wrong token", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: "Bearer wrong-token" },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
  });

  it("rejects a request with empty token value", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: "Bearer " },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
  });

  it("rejects a request with token that is a prefix of the correct token", async () => {
    const prefix = TOKEN.slice(0, TOKEN.length - 1);
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: `Bearer ${prefix}` },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
  });

  it("rejects a request with token that has extra characters appended", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: `Bearer ${TOKEN}x` },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
  });

  // --- 401 response quality ------------------------------------------------

  it("includes WWW-Authenticate: Bearer on every 401", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers["www-authenticate"], "Bearer");
  });

  it("echoes X-Request-ID on 401 responses", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { "x-request-id": "auth-test-req-1" },
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers["x-request-id"], "auth-test-req-1");
  });

  // --- navigation logic unreachable without valid token --------------------

  it("does not reach navigation logic without a valid token", async () => {
    // Without auth the server must not attempt to launch a browser or
    // call any egress check — the 401 is returned at middleware boundary.
    // Confirmed by: no 400 (which would mean the URL was parsed), no 503
    // (egress check), only 401.
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: "Bearer definitely-wrong" },
    });
    assert.equal(res.statusCode, 401);
    // Must not be a 400 (URL validation ran) or 503 (egress check ran)
    assert.notEqual(res.statusCode, 400);
    assert.notEqual(res.statusCode, 503);
  });

  // --- valid token passes through ------------------------------------------

  it("allows a request with the correct token to reach the next handler", async () => {
    // With a valid token the request proceeds past auth. Navigation will fail
    // (no real browser/proxy in unit tests) but it must NOT return 401.
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    // Any non-401 means auth passed. 400/403/503/504 are all acceptable here
    // since the worker is not fully initialised in a unit-test context.
    assert.notEqual(res.statusCode, 401);
  });
});

// ---------------------------------------------------------------------------
// No-token suite — auth disabled in non-production
// ---------------------------------------------------------------------------

describe("worker auth middleware — no token configured (non-production)", () => {
  let server;

  before(async () => {
    config.workerAuthToken = "";
    config.environment = "test";
    server = await listen(createApp());
  });

  after(async () => {
    await close(server);
  });

  it("passes requests without a token when auth is disabled", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
    });
    // Auth is disabled so the request must NOT return 401.
    assert.notEqual(res.statusCode, 401);
  });

  it("also passes requests that include a token when auth is disabled", async () => {
    const res = await request(server, {
      method: "POST",
      path: "/v1/navigate",
      body: { url: "https://example.com/" },
      headers: { authorization: "Bearer any-token-value" },
    });
    assert.notEqual(res.statusCode, 401);
  });
});

// ---------------------------------------------------------------------------
// Production fail-closed suite
// ---------------------------------------------------------------------------

describe("worker auth middleware — production fail-closed", () => {
  it("createApp() throws when environment=production and token is empty", () => {
    const saved = config.environment;
    const savedToken = config.workerAuthToken;
    try {
      config.environment = "production";
      config.workerAuthToken = "";
      assert.throws(
        () => createApp(),
        (err) => {
          assert.ok(err instanceof Error);
          assert.match(err.message, /WORKER_AUTH_REQUIRED/);
          return true;
        },
      );
    } finally {
      config.environment = saved;
      config.workerAuthToken = savedToken;
    }
  });

  it("createApp() succeeds when environment=production and token is set", async () => {
    const saved = config.environment;
    const savedToken = config.workerAuthToken;
    let server;
    try {
      config.environment = "production";
      config.workerAuthToken = "prod-secret-token";
      // Must not throw
      const app = createApp();
      server = await listen(app);
      assert.ok(server.listening);
    } finally {
      config.environment = saved;
      config.workerAuthToken = savedToken;
      if (server) {
        await close(server);
      }
    }
  });

  it("denies requests at runtime even if token somehow becomes empty in production", async () => {
    // Simulate the in-flight guard: hasValidWorkerToken is called with
    // environment=production and workerAuthToken="" — must deny.
    // We test this by creating a server in test mode, then briefly
    // patching the config to mimic the production+empty-token state
    // that the defence-in-depth check covers.
    const saved = config.environment;
    const savedToken = config.workerAuthToken;
    let server;
    try {
      config.environment = "test";
      config.workerAuthToken = "initial-token";
      server = await listen(createApp());

      // Patch to production + empty (simulates runtime misconfiguration)
      config.environment = "production";
      config.workerAuthToken = "";

      const res = await request(server, {
        method: "POST",
        path: "/v1/navigate",
        body: { url: "https://example.com/" },
      });
      assert.equal(res.statusCode, 401);
      assert.equal(res.body?.code, "WORKER_AUTH_FAILED");
    } finally {
      config.environment = saved;
      config.workerAuthToken = savedToken;
      if (server) {
        await close(server);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Health endpoint exemption suite
// ---------------------------------------------------------------------------

describe("health endpoints are exempt from authentication", () => {
  const TOKEN = "health-test-token";
  let server;

  before(async () => {
    config.workerAuthToken = TOKEN;
    config.environment = "test";
    server = await listen(createApp());
  });

  after(async () => {
    config.workerAuthToken = "";
    await close(server);
  });

  it("/health/live returns 200 without a token", async () => {
    const res = await request(server, { path: "/health/live" });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body?.status, "ok");
  });

  it("/health (alias) returns 200 without a token", async () => {
    const res = await request(server, { path: "/health" });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body?.status, "ok");
  });

  it("/health/live still returns 200 even when a wrong token is supplied", async () => {
    const res = await request(server, {
      path: "/health/live",
      headers: { authorization: "Bearer wrong" },
    });
    assert.equal(res.statusCode, 200);
  });

  it("/health/ready returns non-401 without a token (status depends on browser state)", async () => {
    // The readiness check may return 200 or 503 depending on whether the
    // browser/egress proxy is available, but it must never return 401.
    const res = await request(server, { path: "/health/ready" });
    assert.notEqual(res.statusCode, 401);
  });
});
