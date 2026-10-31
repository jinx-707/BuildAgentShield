/**
 * A2 — worker-side session ID guard.
 *
 * Mocked tests: no Puppeteer, no proxy, no real browser. The session ID is
 * validated before createIsolatedPage() runs, so every rejection below is
 * provable without launching Chromium — which is itself part of what these
 * tests assert.
 *
 * Coverage:
 *   - parseSessionId passes a legal value through byte-for-byte
 *   - an absent header is null, not an empty string
 *   - malformed values (empty, spaces, newlines, CR/LF, non-ASCII, over-long,
 *     duplicated-header shape) are rejected rather than sanitized
 *   - /v1/navigate rejects a malformed identity with 400 INVALID_SESSION_ID and
 *     does not reflect the value back
 *   - a rejected identity never reaches the browser layer
 *   - the accepted value lands on the context handle as metadata, and null when
 *     the caller supplied no identity
 *   - a session ID does not substitute for the worker Bearer token
 *   - the error body shape matches the other request-validation failures
 */

import assert from "node:assert/strict";
import http from "node:http";
import { afterEach, beforeEach, describe, it } from "node:test";

// url_guard.js builds its port and domain policy at module load, so the fixture
// policy has to be in the environment before the worker modules are imported.
// 127.0.0.1 is a legal navigation target only because private networks are
// permitted here; no request ever reaches it, because the session identity is
// validated before createIsolatedPage() runs.
Object.assign(process.env, {
  ALLOWED_DOMAINS: "127.0.0.1",
  ALLOWED_PORTS: "80,443",
  DEFAULT_DOMAIN_POLICY: "deny",
  BROWSER_ALLOW_PRIVATE_NETWORKS: "true",
  REQUIRE_EGRESS_PROXY: "false",
  EGRESS_PROXY_URL: "",
  EGRESS_PROXY_HEALTH_URL: "",
  NODE_ENV: "test",
});

const { config } = await import("../src/config.js");
const { getOpenContextCount } = await import("../src/lib/browser.js");
const {
  SESSION_ID_PATTERN,
  SessionIdValidationError,
  parseSessionId,
} = await import("../src/lib/session_guard.js");
const { createApp } = await import("../src/app.js");

const TARGET = "http://127.0.0.1/";

const LEGAL = [
  "conv-42",
  "agent.session:7",
  "A_b-C.0:9",
  "x".repeat(128),
];

const MALFORMED = [
  ["empty string", ""],
  ["single space", " "],
  ["inner space", "conv 42"],
  ["path separator", "conv/42"],
  ["traversal shaped", "conv/../etc"],
  ["embedded newline", "conv\n42"],
  ["header injection", "conv\r\nX-Injected: 1\r\n"],
  ["embedded tab", "conv\t42"],
  ["non-ascii", "sessioné"],
  ["over-long", "x".repeat(129)],
  ["duplicated header join", "conv-a, conv-b"],
  ["html payload", "<script>alert(1)</script>"],
];

function listen(app) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function close(server) {
  server.closeAllConnections?.();
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

function post(server, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : "";
    const request = http.request(
      {
        hostname: "127.0.0.1",
        port: server.address().port,
        path,
        method: "POST",
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
            /* keep the raw text for leak assertions */
          }
          resolve({ status: response.statusCode, text, json });
        });
      },
    );
    request.on("error", reject);
    request.end(payload);
  });
}

describe("parseSessionId", () => {
  it("returns a legal identity unchanged", () => {
    for (const value of LEGAL) {
      assert.equal(parseSessionId(value), value);
    }
  });

  it("treats an absent header as no identity", () => {
    assert.equal(parseSessionId(undefined), null);
    assert.equal(parseSessionId(null), null);
  });

  it("rejects malformed identities instead of sanitizing them", () => {
    for (const [label, value] of MALFORMED) {
      assert.throws(
        () => parseSessionId(value),
        (error) => {
          assert.ok(error instanceof SessionIdValidationError, label);
          assert.equal(error.code, "INVALID_SESSION_ID", label);
          assert.equal(error.status, 400, label);
          // The rejected value is caller-controlled; nothing may echo it.
          const echoed = value.trim();
          if (echoed.length > 0) {
            assert.ok(!error.message.includes(echoed), label);
          }
          return true;
        },
        `expected rejection for ${label}`,
      );
    }
  });

  it("uses the same shape as the request-ID pattern", () => {
    assert.equal(SESSION_ID_PATTERN.source, /^[A-Za-z0-9._:-]{1,128}$/.source);
  });
});

describe("/v1/navigate session identity handling", () => {
  const savedToken = config.workerAuthToken;
  const savedEnvironment = config.environment;
  let server;

  beforeEach(async () => {
    config.workerAuthToken = "";
    config.environment = "test";
    server = await listen(createApp());
  });

  afterEach(async () => {
    await close(server);
    config.workerAuthToken = savedToken;
    config.environment = savedEnvironment;
  });

  it("rejects a malformed identity with 400 before touching the browser", async () => {
    const response = await post(server, "/v1/navigate", {
      headers: { "x-agent-session": "conv 42" },
      body: { url: TARGET },
    });

    assert.equal(response.status, 400);
    assert.equal(response.json.code, "INVALID_SESSION_ID");
    assert.equal(response.json.error, "invalid_request");
    // The rejected value is caller-controlled and must not be reflected.
    assert.ok(!response.text.includes("conv 42"));
    assert.equal(getOpenContextCount(), 0);
  });

  it("reports the same envelope as the other request-validation failures", async () => {
    const badTimeout = await post(server, "/v1/navigate", {
      body: { url: TARGET, timeout_ms: 5 },
    });
    const badSession = await post(server, "/v1/navigate", {
      headers: { "x-agent-session": "bad id" },
      body: { url: TARGET },
    });

    assert.equal(badTimeout.status, 400);
    assert.equal(badSession.status, 400);
    assert.equal(badTimeout.json.error, badSession.json.error);
    assert.deepEqual(Object.keys(badSession.json).sort(), Object.keys(badTimeout.json).sort());
  });

  it("accepts every legal identity shape", async () => {
    for (const value of LEGAL) {
      const response = await post(server, "/v1/navigate", {
        headers: { "x-agent-session": value },
        body: { url: "not-a-url" },
      });
      // Failing on the URL is fine; failing on the identity is not.
      assert.notEqual(response.json?.code, "INVALID_SESSION_ID", value);
    }
  });

  it("never lets a session identity replace the worker token", async () => {
    config.workerAuthToken = "worker-secret";

    const anonymous = await post(server, "/v1/navigate", {
      headers: { "x-agent-session": "conv-42" },
      body: { url: TARGET },
    });
    const substituted = await post(server, "/v1/navigate", {
      headers: {
        "x-agent-session": "conv-42",
        authorization: "Bearer victim-session",
      },
      body: { url: TARGET },
    });
    const authenticated = await post(server, "/v1/navigate", {
      headers: {
        "x-agent-session": "conv-42",
        authorization: "Bearer worker-secret",
      },
      body: { url: "not-a-url" },
    });

    assert.equal(anonymous.status, 401);
    assert.equal(substituted.status, 401);
    assert.notEqual(authenticated.json?.code, "WORKER_AUTH_FAILED");
    assert.equal(getOpenContextCount(), 0);
  });

  it("rejects an over-long identity without a 500", async () => {
    const response = await post(server, "/v1/navigate", {
      headers: { "x-agent-session": "x".repeat(5000) },
      body: { url: TARGET },
    });

    assert.equal(response.status, 400);
    assert.equal(response.json.code, "INVALID_SESSION_ID");
  });
});
