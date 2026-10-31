/**
 * B1 — extraction over HTTP with a real Chromium page.
 *
 * The fixture page carries visible content, hidden content, links, a list, a
 * table and metadata. Extraction must return bounded plain text and structured
 * records, exclude hidden content, and never navigate the session.
 */

import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";

const fixture = http.createServer((request, response) => {
  const path = request.url.split("?")[0];
  response.setHeader("content-type", "text/html");

  if (path === "/article") {
    response.end(`<!doctype html>
      <html lang="en">
      <head>
        <title>Extraction fixture</title>
        <meta name="description" content="A test article">
        <meta property="og:site_name" content="Fixture Site">
        <link rel="canonical" href="/canonical">
      </head>
      <body>
        <header><h1>Visible heading</h1></header>
        <p>First visible paragraph with <a href="/one">first link</a>.</p>
        <p>Second visible paragraph.</p>
        <p>${"filler ".repeat(100)}</p>
        <div hidden>HIDDEN_ATTRIBUTE_SECRET</div>
        <div style="display:none">HIDDEN_STYLE_SECRET</div>
        <div aria-hidden="true">HIDDEN_ARIA_SECRET</div>
        <ul><li>Alpha</li><li>Beta</li></ul>
        <ol><li>One</li><li>Two</li></ol>
        <table>
          <caption>People</caption>
          <thead><tr><th>Name</th><th>Role</th></tr></thead>
          <tbody><tr><td>Alice</td><td>Engineer</td></tr></tbody>
        </table>
        <a href="https://example.com/second">second link</a>
        <script>window.secret = "SCRIPT_SECRET";</script>
      </body>
      </html>`);
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
  WORKER_AUTH_TOKEN: "extract-test-token",
  BROWSER_MAX_EXTRACTION_LINKS: "1",
  BROWSER_MAX_EXTRACTION_TEXT_BYTES: "300",
  NODE_ENV: "test",
});

const {
  closeBrowser,
  getOpenContextCount,
  getOpenSessionCount,
} = await import("../src/lib/browser.js");
const { createApp } = await import("../src/app.js");

const fixtureUrl = (path) => `http://127.0.0.1:${fixturePort}${path}`;
const AUTH = { authorization: "Bearer extract-test-token" };

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

async function createSession(agentId = "extract-agent") {
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

function extract(sessionId, agentId, body = {}) {
  return request("POST", "/v1/extract", {
    headers: {
      ...AUTH,
      "x-agent-session": sessionId,
      "x-agent-id": agentId,
    },
    body,
  });
}

before(async () => {
  assert.equal(typeof createApp, "function");
});

after(async () => {
  await closeBrowser();
  fixture.closeAllConnections?.();
  await new Promise((resolve) => fixture.close(resolve));
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
});

test("extraction route is behind worker authentication", async () => {
  const response = await request("POST", "/v1/extract", {
    headers: { "x-agent-id": "agent-a" },
    body: {},
  });
  assert.equal(response.status, 401);
  assert.equal(response.json.code, "WORKER_AUTH_FAILED");
});

test("extraction requires a session and an owner identity", async () => {
  const noSession = await request("POST", "/v1/extract", {
    headers: { ...AUTH, "x-agent-id": "agent-a" },
    body: {},
  });
  assert.equal(noSession.status, 400);
  assert.equal(noSession.json.code, "INVALID_REQUEST");

  const created = await createSession("agent-a");
  try {
    const noAgent = await request("POST", "/v1/extract", {
      headers: { ...AUTH, "x-agent-session": created.session_id },
      body: {},
    });
    assert.equal(noAgent.status, 400);
    assert.equal(noAgent.json.code, "INVALID_AGENT_ID");
  } finally {
    await request("DELETE", `/v1/session/${created.session_id}`, {
      headers: { ...AUTH, "x-agent-id": "agent-a" },
    });
  }
});

test("extraction refuses an unknown or foreign session", async () => {
  const created = await createSession("owner-a");
  try {
    const foreign = await extract(created.session_id, "owner-b");
    assert.equal(foreign.status, 403);
    assert.equal(foreign.json.code, "SESSION_FORBIDDEN");

    const unknown = await extract("00000000-0000-0000-0000-000000000000", "owner-a");
    assert.equal(unknown.status, 404);
    assert.equal(unknown.json.code, "SESSION_NOT_FOUND");
  } finally {
    await request("DELETE", `/v1/session/${created.session_id}`, {
      headers: { ...AUTH, "x-agent-id": "owner-a" },
    });
  }
});

test("extraction returns bounded visible text and structured records", async () => {
  const created = await createSession("extract-agent");
  try {
    await navigate(created.session_id, "extract-agent", fixtureUrl("/article"));

    const response = await extract(created.session_id, "extract-agent");
    assert.equal(response.status, 200, response.text);
    const body = response.json;

    assert.equal(body.session_id, created.session_id);
    assert.equal(body.metadata.title, "Extraction fixture");
    assert.equal(body.metadata.description, "A test article");
    assert.equal(body.metadata.site_name, "Fixture Site");
    assert.equal(body.metadata.language, "en");
    assert.equal(body.metadata.url, fixtureUrl("/article"));
    assert.equal(body.metadata.canonical_url, fixtureUrl("/canonical"));

    assert.match(body.text, /Visible heading/);
    assert.match(body.text, /First visible paragraph/);
    assert.match(body.text, /Second visible paragraph/);
    assert.ok(!body.text.includes("HIDDEN_ATTRIBUTE_SECRET"));
    assert.ok(!body.text.includes("HIDDEN_STYLE_SECRET"));
    assert.ok(!body.text.includes("HIDDEN_ARIA_SECRET"));
    assert.ok(!body.text.includes("SCRIPT_SECRET"));
    assert.ok(!body.text.includes("<p>"), "no raw HTML is returned");
    assert.equal(body.hidden_content_excluded, true);
    assert.ok(body.hidden_element_count >= 3);

    assert.equal(body.links.length, 1);
    assert.equal(body.links_truncated, true);
    assert.equal(body.links[0].url, fixtureUrl("/one"));
    assert.equal(body.links[0].text, "first link");

    assert.deepEqual(
      body.lists.map((list) => ({ ordered: list.ordered, items: list.items })),
      [
        { ordered: false, items: ["Alpha", "Beta"] },
        { ordered: true, items: ["One", "Two"] },
      ],
    );

    assert.equal(body.tables.length, 1);
    assert.equal(body.tables[0].caption, "People");
    assert.deepEqual(body.tables[0].headers, ["Name", "Role"]);
    assert.deepEqual(body.tables[0].rows, [["Alice", "Engineer"]]);

    assert.equal(body.text_truncated, true);
    assert.ok(Buffer.byteLength(body.text, "utf8") <= 300);
    assert.ok(body.elapsed_ms >= 0);

    const status = await request("GET", `/v1/session/${created.session_id}`, {
      headers: { ...AUTH, "x-agent-id": "extract-agent" },
    });
    assert.equal(status.json.current_url, fixtureUrl("/article"));
    assert.equal(status.json.active_requests, 0, "extraction releases its lease");
  } finally {
    await request("DELETE", `/v1/session/${created.session_id}`, {
      headers: { ...AUTH, "x-agent-id": "extract-agent" },
    });
  }

  assert.equal(getOpenSessionCount(), 0);
  assert.equal(getOpenContextCount(), 0);
});
