import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";

const fixture = http.createServer((request, response) => {
  const path = request.url.split("?")[0];
  response.setHeader("content-type", "text/html");

  if (path === "/page") {
    response.end(`<!doctype html>
      <html><head><title>Screenshot fixture</title></head>
      <body style="margin:0;background:#fff">
        <h1>SCREENSHOT_PAGE</h1>
        <div style="height:1800px;background:linear-gradient(#fff,#888)">tall</div>
      </body></html>`);
    return;
  }

  if (path === "/large") {
    response.end(`<!doctype html>
      <html><head><title>Large fixture</title></head>
      <body><div style="height:5000px">large</div></body></html>`);
    return;
  }

  if (path === "/noise") {
    response.end(`<!doctype html>
      <html><head><title>Noise fixture</title></head>
      <body style="margin:0">
        <canvas id="c" width="800" height="600"></canvas>
        <script>
          const canvas = document.getElementById('c');
          const context = canvas.getContext('2d');
          const image = context.createImageData(canvas.width, canvas.height);
          for (let i = 0; i < image.data.length; i += 4) {
            image.data[i] = Math.floor(Math.random() * 256);
            image.data[i + 1] = Math.floor(Math.random() * 256);
            image.data[i + 2] = Math.floor(Math.random() * 256);
            image.data[i + 3] = 255;
          }
          context.putImageData(image, 0, 0);
        </script>
      </body></html>`);
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
  WORKER_AUTH_TOKEN: "screenshot-test-token",
  BROWSER_SCREENSHOT_MAX_WIDTH: "1400",
  BROWSER_SCREENSHOT_MAX_HEIGHT: "900",
  BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT: "2000",
  BROWSER_SCREENSHOT_MAX_BYTES: "200000",
  BROWSER_SCREENSHOT_MAX_CONCURRENT: "1",
  BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE: "100",
  BROWSER_SCREENSHOT_MAX_PER_SESSION: "100",
  NODE_ENV: "test",
});

const { config } = await import("../src/config.js");
const {
  closeBrowser,
  getOpenContextCount,
  getOpenSessionCount,
} = await import("../src/lib/browser.js");
const {
  ScreenshotTimeoutError,
  beginScreenshot,
  withScreenshotTimeout,
} = await import("../src/lib/screenshot.js");
const { createApp } = await import("../src/app.js");

const fixtureUrl = (path) => `http://127.0.0.1:${fixturePort}${path}`;
const AUTH = { authorization: "Bearer screenshot-test-token" };

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
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks);
          let json = null;
          try {
            json = JSON.parse(raw.toString("utf8"));
          } catch {
            /* binary response */
          }
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: raw,
            text: raw.toString("utf8"),
            json,
          });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

async function createSession(agentId = "screenshot-agent") {
  const response = await request("POST", "/v1/session", {
    headers: { ...AUTH, "x-agent-id": agentId },
    body: {},
  });
  assert.equal(response.status, 201, response.text);
  return response.json;
}

async function navigate(sessionId, agentId, url) {
  const response = await request("POST", "/v1/navigate", {
    headers: {
      ...AUTH,
      "x-agent-session": sessionId,
      "x-agent-id": agentId,
    },
    body: { url, wait_until: "load", timeout_ms: 10000 },
  });
  assert.equal(response.status, 200, response.text);
  return response.json;
}

function screenshot(sessionId, agentId, body = {}) {
  return request("POST", "/v1/screenshot", {
    headers: {
      ...AUTH,
      "x-agent-session": sessionId,
      "x-agent-id": agentId,
    },
    body,
  });
}

async function closeSession(sessionId, agentId) {
  return request("DELETE", `/v1/session/${sessionId}`, {
    headers: { ...AUTH, "x-agent-id": agentId },
  });
}

async function withPage(agentId = "screenshot-agent", path = "/page") {
  const created = await createSession(agentId);
  await navigate(created.session_id, agentId, fixtureUrl(path));
  return created.session_id;
}

before(async () => {
  config.workerAuthToken = "screenshot-test-token";
});

after(async () => {
  await closeBrowser();
  fixture.closeAllConnections?.();
  await new Promise((resolve) => fixture.close(resolve));
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
});

test("screenshot route is behind worker authentication", async () => {
  const response = await request("POST", "/v1/screenshot", {
    headers: { "x-agent-id": "agent-a" },
    body: {},
  });
  assert.equal(response.status, 401);
  assert.equal(response.json.code, "WORKER_AUTH_FAILED");
});

test("screenshot requires an owned session", async () => {
  const created = await createSession("owner-a");
  try {
    const foreign = await screenshot(created.session_id, "owner-b");
    assert.equal(foreign.status, 403);
    assert.equal(foreign.json.code, "SESSION_FORBIDDEN");
  } finally {
    await closeSession(created.session_id, "owner-a");
  }
});

test("viewport screenshot returns a bounded PNG with metadata", async () => {
  const sessionId = await withPage();
  try {
    const response = await screenshot(sessionId, "screenshot-agent");
    assert.equal(response.status, 200, response.text);
    assert.match(response.headers["content-type"], /^image\/png/);
    assert.equal(response.body.subarray(1, 4).toString("ascii"), "PNG");
    assert.equal(response.headers["cache-control"], "no-store, max-age=0");
    assert.equal(response.headers["x-screenshot-width"], "1280");
    assert.equal(response.headers["x-screenshot-height"], "720");
    assert.equal(response.headers["x-screenshot-full-page"], "false");
    assert.equal(Number(response.headers["x-screenshot-bytes"]), response.body.length);
    assert.equal(response.body.length <= 200000, true);
    assert.ok(!response.text.includes("SCREENSHOT_PAGE"));
  } finally {
    await closeSession(sessionId, "screenshot-agent");
  }
});

test("clip screenshots use the requested rectangle", async () => {
  const sessionId = await withPage();
  try {
    const response = await screenshot(sessionId, "screenshot-agent", {
      clip: { x: 10, y: 10, width: 100, height: 50 },
    });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.headers["x-screenshot-width"], "100");
    assert.equal(response.headers["x-screenshot-height"], "50");
  } finally {
    await closeSession(sessionId, "screenshot-agent");
  }
});

test("full-page screenshots are captured within the configured height", async () => {
  const sessionId = await withPage();
  try {
    const response = await screenshot(sessionId, "screenshot-agent", {
      full_page: true,
    });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.headers["x-screenshot-full-page"], "true");
    assert.equal(response.headers["x-screenshot-width"], "1280");
    assert.ok(Number(response.headers["x-screenshot-height"]) >= 1800);
  } finally {
    await closeSession(sessionId, "screenshot-agent");
  }
});

test("oversized pages, clips, and images are rejected", async () => {
  const largeSession = await withPage("screenshot-agent", "/large");
  try {
    const tooTall = await screenshot(largeSession, "screenshot-agent", {
      full_page: true,
    });
    assert.equal(tooTall.status, 413);
    assert.equal(tooTall.json.code, "SCREENSHOT_DIMENSIONS_EXCEEDED");
  } finally {
    await closeSession(largeSession, "screenshot-agent");
  }

  const pageSession = await withPage();
  try {
    const tooWide = await screenshot(pageSession, "screenshot-agent", {
      clip: { x: 0, y: 0, width: 1500, height: 10 },
    });
    assert.equal(tooWide.status, 413);
    assert.equal(tooWide.json.code, "SCREENSHOT_DIMENSIONS_EXCEEDED");

    const outOfBounds = await screenshot(pageSession, "screenshot-agent", {
      clip: { x: 10000, y: 0, width: 10, height: 10 },
    });
    assert.equal(outOfBounds.status, 400);
    assert.equal(outOfBounds.json.code, "SCREENSHOT_CLIP_OUT_OF_BOUNDS");

    const both = await screenshot(pageSession, "screenshot-agent", {
      full_page: true,
      clip: { x: 0, y: 0, width: 10, height: 10 },
    });
    assert.equal(both.status, 400);
    assert.equal(both.json.code, "INVALID_SCREENSHOT_OPTIONS");
  } finally {
    await closeSession(pageSession, "screenshot-agent");
  }

  const noiseSession = await withPage("screenshot-agent", "/noise");
  try {
    const tooLarge = await screenshot(noiseSession, "screenshot-agent");
    assert.equal(tooLarge.status, 413);
    assert.equal(tooLarge.json.code, "SCREENSHOT_TOO_LARGE");
  } finally {
    await closeSession(noiseSession, "screenshot-agent");
  }
});

test("per-session screenshot rate limits are enforced", async () => {
  const sessionId = await withPage();
  const originalRate = config.screenshotRateLimitPerMinute;
  config.screenshotRateLimitPerMinute = 2;
  try {
    const first = await screenshot(sessionId, "screenshot-agent");
    const second = await screenshot(sessionId, "screenshot-agent");
    const third = await screenshot(sessionId, "screenshot-agent");
    assert.equal(first.status, 200, first.text);
    assert.equal(second.status, 200, second.text);
    assert.equal(third.status, 429);
    assert.equal(third.json.code, "SCREENSHOT_RATE_LIMITED");
  } finally {
    config.screenshotRateLimitPerMinute = originalRate;
    await closeSession(sessionId, "screenshot-agent");
  }
});

test("screenshot concurrency and timeout guards work without a browser", async () => {
  const release = beginScreenshot("unit-concurrency-a");
  try {
    assert.throws(
      () => beginScreenshot("unit-concurrency-b"),
      (error) => error.code === "SCREENSHOT_CONCURRENCY_LIMIT",
    );
  } finally {
    release();
  }

  const originalSessionLimit = config.screenshotMaxPerSession;
  config.screenshotMaxPerSession = 2;
  try {
    beginScreenshot("unit-total-a")();
    beginScreenshot("unit-total-a")();
    assert.throws(
      () => beginScreenshot("unit-total-a"),
      (error) => error.code === "SCREENSHOT_SESSION_LIMIT",
    );
  } finally {
    config.screenshotMaxPerSession = originalSessionLimit;
  }

  let timedOut = false;
  await assert.rejects(
    withScreenshotTimeout(
      new Promise(() => {}),
      10,
      async () => {
        timedOut = true;
      },
    ),
    (error) => error instanceof ScreenshotTimeoutError,
  );
  assert.equal(timedOut, true);
});

test("screenshot sessions leave no browser contexts behind", async () => {
  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
});
