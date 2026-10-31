import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";

let crossPort = 0;

const crossFixture = http.createServer((request, response) => {
  response.setHeader("content-type", "text/html");
  response.end("<!doctype html><title>Cross Submitted</title><body>CROSS_SUBMITTED_PAGE</body>");
});

crossPort = await new Promise((resolve, reject) => {
  crossFixture.once("error", reject);
  crossFixture.listen(0, "127.0.0.1", () => resolve(crossFixture.address().port));
});

const fixture = http.createServer((request, response) => {
  const path = request.url.split("?")[0];
  response.setHeader("content-type", "text/html");

  if (path === "/actions") {
    response.end(`<!doctype html>
      <html><head><title>Action fixture</title></head>
      <body>
        <p>ACTION_PAGE_TEXT</p>
        <button id="nav-button" onclick="location.href='/next'">Navigate</button>
        <button class="ambiguous">Dup</button>
        <button class="ambiguous">Dup</button>
        <button id="hidden-button" hidden>Hidden</button>
        <button id="disabled-button" disabled>Disabled</button>
        <a id="next-link" href="/next">Next link</a>
        <a id="blocked-link" href="http://169.254.169.254/latest">Blocked link</a>
        <input id="name" name="name" type="text">
        <div id="echo"></div>
        <input id="readonly-input" readonly value="fixed">
        <input id="disabled-input" disabled>
        <input id="hidden-input" hidden>
        <input id="max-input" maxlength="3">
        <input id="password-input" type="password" name="password">
        <input id="file-input" type="file">
        <a id="download-link" href="/download" download>Download</a>
        <div id="scroll-container" style="height:100px;overflow:auto">
          <div style="height:1000px">scroll content</div>
        </div>
        <div style="height:2000px"></div>
        <form id="simple-form" action="/submitted" method="get">
          <input name="q" value="hello">
          <button id="submit-button" type="submit">Submit</button>
        </form>
        <form id="sensitive-form" action="/submitted" method="post">
          <input name="password" type="password" value="secret">
          <button type="submit">Submit</button>
        </form>
        <form id="cross-form" action="http://127.0.0.1:${crossPort}/submitted" method="get">
          <input name="q" value="cross">
          <button type="submit">Submit</button>
        </form>
        <form id="blocked-form" action="http://169.254.169.254/latest" method="get">
          <input name="q" value="blocked">
          <button type="submit">Submit</button>
        </form>
        <form id="slow-form" action="/slow" method="get">
          <input name="q" value="slow">
          <button type="submit">Submit</button>
        </form>
        <form id="delete-form" action="/delete" method="post">
          <input name="id" value="42">
          <button type="submit">Delete account</button>
        </form>
        <script>
          const input = document.getElementById('name');
          input.addEventListener('input', () => {
            document.getElementById('echo').textContent = input.value;
          });
        </script>
      </body></html>`);
    return;
  }

  if (path === "/next") {
    response.end("<!doctype html><title>Next</title><body>NEXT_PAGE</body>");
    return;
  }

  if (path === "/submitted") {
    response.end("<!doctype html><title>Submitted</title><body>SUBMITTED_PAGE</body>");
    return;
  }

  if (path === "/slow") {
    setTimeout(() => {
      response.end("<!doctype html><title>Slow</title><body>SLOW_PAGE</body>");
    }, 5000);
    return;
  }

  response.end("<!doctype html><title>blank</title><body>blank</body>");
});

const fixturePort = await new Promise((resolve, reject) => {
  fixture.once("error", reject);
  fixture.listen(0, "127.0.0.1", () => resolve(fixture.address().port));
});

Object.assign(process.env, {
  ALLOWED_DOMAINS: "127.0.0.1,localhost",
  ALLOWED_PORTS: `${fixturePort},${crossPort},80`,
  DEFAULT_DOMAIN_POLICY: "deny",
  BROWSER_ALLOW_PRIVATE_NETWORKS: "true",
  REQUIRE_EGRESS_PROXY: "false",
  EGRESS_PROXY_URL: "",
  EGRESS_PROXY_HEALTH_URL: "",
  WORKER_AUTH_TOKEN: "action-test-token",
  BROWSER_ACTION_MAX_TYPE_BYTES: "20",
  BROWSER_ACTION_MAX_SCROLL_PX: "1000",
  BROWSER_ACTION_MAX_TEXT_BYTES: "1000",
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
const AUTH = { authorization: "Bearer action-test-token" };

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

async function createSession(agentId = "action-agent") {
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

function action(sessionId, agentId, body) {
  return request("POST", "/v1/action", {
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

async function withActionPage(agentId = "action-agent", path = "/actions") {
  const created = await createSession(agentId);
  await navigate(created.session_id, agentId, fixtureUrl(path));
  return created.session_id;
}

before(async () => {
  config.workerAuthToken = "action-test-token";
});

after(async () => {
  await closeBrowser();
  fixture.closeAllConnections?.();
  await new Promise((resolve) => fixture.close(resolve));
  crossFixture.closeAllConnections?.();
  await new Promise((resolve) => crossFixture.close(resolve));
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
});

test("action route is behind worker authentication", async () => {
  const response = await request("POST", "/v1/action", {
    headers: { "x-agent-id": "agent-a" },
    body: { action: "page_state" },
  });
  assert.equal(response.status, 401);
  assert.equal(response.json.code, "WORKER_AUTH_FAILED");
});

test("action requires an owned session", async () => {
  const noSession = await action("session-123", "agent-a", { action: "page_state" });
  assert.equal(noSession.status, 404);
  assert.equal(noSession.json.code, "SESSION_NOT_FOUND");

  const created = await createSession("owner-a");
  try {
    const foreign = await action(created.session_id, "owner-b", { action: "page_state" });
    assert.equal(foreign.status, 403);
    assert.equal(foreign.json.code, "SESSION_FORBIDDEN");
  } finally {
    await closeSession(created.session_id, "owner-a");
  }
});

test("click navigates, and role targeting works", async () => {
  const sessionId = await withActionPage();
  try {
    const response = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#nav-button" },
    });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.json.final_url, fixtureUrl("/next"));
    assert.equal(response.json.title, "Next");
    assert.match(response.json.text, /NEXT_PAGE/);
    assert.ok(response.json.warnings.includes("NAVIGATION_OCCURRED"));
    assert.equal(response.json.target.tag, "button");
  } finally {
    await closeSession(sessionId, "action-agent");
  }

  const roleSession = await withActionPage();
  try {
    const response = await action(roleSession, "action-agent", {
      action: "click",
      target: { role: "button", name: "Navigate" },
    });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.json.final_url, fixtureUrl("/next"));
  } finally {
    await closeSession(roleSession, "action-agent");
  }
});

test("click rejects ambiguous, hidden, disabled and submit controls", async () => {
  const sessionId = await withActionPage();
  try {
    const ambiguous = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: ".ambiguous" },
    });
    assert.equal(ambiguous.status, 409);
    assert.equal(ambiguous.json.code, "TARGET_AMBIGUOUS");

    const indexed = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: ".ambiguous", index: 1 },
    });
    assert.equal(indexed.status, 200, indexed.text);

    const hidden = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#hidden-button" },
    });
    assert.equal(hidden.status, 400);
    assert.equal(hidden.json.code, "TARGET_NOT_VISIBLE");

    const disabled = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#disabled-button" },
    });
    assert.equal(disabled.status, 400);
    assert.equal(disabled.json.code, "TARGET_DISABLED");

    const submit = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#submit-button" },
    });
    assert.equal(submit.status, 403);
    assert.equal(submit.json.code, "FORM_SUBMIT_REQUIRES_GUARDED_OPERATION");

    const fileInput = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#file-input" },
    });
    assert.equal(fileInput.status, 403);
    assert.equal(fileInput.json.code, "FILE_INPUT_NOT_ALLOWED");

    const download = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#download-link" },
    });
    assert.equal(download.status, 403);
    assert.equal(download.json.code, "DOWNLOAD_NOT_ALLOWED");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("type writes editable fields, rejects unsafe targets, and redacts secrets", async () => {
  const sessionId = await withActionPage();
  try {
    const typed = await action(sessionId, "action-agent", {
      action: "type",
      target: { selector: "#name" },
      text: "TOPSECRET",
    });
    assert.equal(typed.status, 200, typed.text);
    assert.ok(!typed.text.includes("TOPSECRET"));
    assert.match(typed.text, /\[REDACTED\]/);
    assert.ok(typed.json.warnings.includes("TYPED_VALUE_REDACTED"));

    const readonly = await action(sessionId, "action-agent", {
      action: "type",
      target: { selector: "#readonly-input" },
      text: "x",
    });
    assert.equal(readonly.status, 400);
    assert.equal(readonly.json.code, "TARGET_READ_ONLY");

    const disabled = await action(sessionId, "action-agent", {
      action: "type",
      target: { selector: "#disabled-input" },
      text: "x",
    });
    assert.equal(disabled.status, 400);
    assert.equal(disabled.json.code, "TARGET_DISABLED");

    const hidden = await action(sessionId, "action-agent", {
      action: "type",
      target: { selector: "#hidden-input" },
      text: "x",
    });
    assert.equal(hidden.status, 400);
    assert.equal(hidden.json.code, "TARGET_NOT_VISIBLE");

    const tooLong = await action(sessionId, "action-agent", {
      action: "type",
      target: { selector: "#max-input" },
      text: "abcd",
    });
    assert.equal(tooLong.status, 400);
    assert.equal(tooLong.json.code, "INPUT_LENGTH_EXCEEDED");

    const tooManyBytes = await action(sessionId, "action-agent", {
      action: "type",
      target: { selector: "#name" },
      text: "123456789012345678901",
    });
    assert.equal(tooManyBytes.status, 400);
    assert.equal(tooManyBytes.json.code, "INPUT_LENGTH_EXCEEDED");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("scroll is bounded and reports positions for the page and containers", async () => {
  const sessionId = await withActionPage();
  try {
    const pageScroll = await action(sessionId, "action-agent", {
      action: "scroll",
      direction: "down",
      amount: 400,
    });
    assert.equal(pageScroll.status, 200, pageScroll.text);
    assert.equal(pageScroll.json.scroll.y, 400);

    const containerScroll = await action(sessionId, "action-agent", {
      action: "scroll",
      direction: "down",
      amount: 300,
      target: { selector: "#scroll-container" },
    });
    assert.equal(containerScroll.status, 200, containerScroll.text);
    assert.equal(containerScroll.json.scroll.y, 300);

    const legacyContainer = await action(sessionId, "action-agent", {
      action: "scroll",
      direction: "down",
      distance: 200,
      selector: "#scroll-container",
    });
    assert.equal(legacyContainer.status, 200, legacyContainer.text);
    assert.equal(legacyContainer.json.scroll.y, 500);

    const tooFar = await action(sessionId, "action-agent", {
      action: "scroll",
      direction: "down",
      amount: 1001,
    });
    assert.equal(tooFar.status, 400);
    assert.equal(tooFar.json.code, "INVALID_SCROLL_AMOUNT");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("page state returns untrusted text and scroll metadata", async () => {
  const sessionId = await withActionPage();
  try {
    const response = await action(sessionId, "action-agent", { action: "page_state" });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.json.action, "page_state");
    assert.equal(response.json.final_url, fixtureUrl("/actions"));
    assert.match(response.json.text, /ACTION_PAGE_TEXT/);
    assert.ok(response.json.warnings.includes("UNTRUSTED_PAGE_CONTENT"));
    assert.equal(typeof response.json.scroll.client_height, "number");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("guarded submit succeeds for same-origin non-sensitive forms", async () => {
  const sessionId = await withActionPage();
  try {
    const response = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#simple-form" },
    });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.json.final_url.startsWith(fixtureUrl("/submitted")), true);
    assert.match(response.json.text, /SUBMITTED_PAGE/);
    assert.equal(response.json.form.method, "get");
    assert.equal(response.json.form.cross_origin, false);
    assert.equal(response.json.form.confirmed, false);
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("destructive form submissions require explicit confirmation", async () => {
  const sessionId = await withActionPage();
  try {
    const blocked = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#delete-form" },
    });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.code, "FORM_CONFIRMATION_REQUIRED");
    assert.ok(blocked.json.details.reasons.includes("destructive_action"));

    const confirmed = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#delete-form" },
      confirm: true,
    });
    assert.equal(confirmed.status, 200, confirmed.text);
    assert.equal(confirmed.json.form.destructive, true);
    assert.equal(confirmed.json.form.confirmed, true);
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});


test("sensitive form submissions require confirmation and withhold text", async () => {
  const sessionId = await withActionPage();
  try {
    const refused = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#sensitive-form" },
    });
    assert.equal(refused.status, 409);
    assert.equal(refused.json.code, "FORM_CONFIRMATION_REQUIRED");
    assert.ok(refused.json.details.reasons.includes("sensitive_fields"));
    assert.ok(refused.json.details.sensitive_fields.includes("password"));

    const confirmed = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#sensitive-form" },
      confirm: true,
    });
    assert.equal(confirmed.status, 200, confirmed.text);
    assert.equal(confirmed.json.text, "");
    assert.ok(confirmed.json.warnings.includes("SENSITIVE_FORM_TEXT_WITHHELD"));
    assert.equal(confirmed.json.form.sensitive_field_count, 1);
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("cross-origin form submissions require confirmation", async () => {
  const sessionId = await withActionPage();
  try {
    const refused = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#cross-form" },
    });
    assert.equal(refused.status, 409);
    assert.equal(refused.json.code, "FORM_CONFIRMATION_REQUIRED");
    assert.ok(refused.json.details.reasons.includes("cross_origin"));

    const confirmed = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#cross-form" },
      confirm: true,
    });
    assert.equal(confirmed.status, 200, confirmed.text);
    assert.ok(confirmed.json.final_url.startsWith(`http://127.0.0.1:${crossPort}/submitted`));
    assert.ok(confirmed.json.warnings.includes("CROSS_ORIGIN_FORM_SUBMISSION"));
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("form destinations are validated before submission", async () => {
  const sessionId = await withActionPage();
  try {
    const blocked = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#blocked-form" },
      confirm: true,
    });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.json.code, "DOMAIN_BLOCKED");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("click-triggered navigation is subject to URL policy", async () => {
  const sessionId = await withActionPage();
  try {
    const response = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#blocked-link" },
    });
    assert.equal(response.status, 403);
    assert.equal(response.json.code, "DOMAIN_BLOCKED");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("action timeout closes the checked-out context", async () => {
  const sessionId = await withActionPage();
  try {
    const response = await action(sessionId, "action-agent", {
      action: "submit_form",
      target: { selector: "#slow-form" },
      timeout_ms: 1000,
    });
    assert.equal(response.status, 504);
    assert.equal(response.json.code, "ACTION_TIMEOUT");
    assert.equal(getOpenSessionCount(), 0);
    assert.equal(getOpenContextCount(), 0);
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});

test("malformed actions and targets are rejected", async () => {
  const sessionId = await withActionPage();
  try {
    const missing = await action(sessionId, "action-agent", {});
    assert.equal(missing.status, 400);
    assert.equal(missing.json.code, "INVALID_REQUEST");

    const unknown = await action(sessionId, "action-agent", { action: "evaluate" });
    assert.equal(unknown.status, 400);
    assert.equal(unknown.json.code, "INVALID_ACTION");

    const both = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "#nav-button", role: "button" },
    });
    assert.equal(both.status, 400);
    assert.equal(both.json.code, "INVALID_TARGET");

    const puppeteerSelector = await action(sessionId, "action-agent", {
      action: "click",
      target: { selector: "aria/Navigate" },
    });
    assert.equal(puppeteerSelector.status, 400);
    assert.equal(puppeteerSelector.json.code, "INVALID_TARGET");
  } finally {
    await closeSession(sessionId, "action-agent");
  }
});
