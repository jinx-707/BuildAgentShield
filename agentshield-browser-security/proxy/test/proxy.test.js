import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import test from "node:test";

import { createEgressPolicy } from "../src/lib/policy.js";
import { createEgressProxy, createProxyHealthServer } from "../src/lib/proxy.js";

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function httpThroughProxy({ proxyPort, targetUrl, headers = {}, method = "GET" }) {
  return new Promise((resolve, reject) => {
    const target = new URL(targetUrl);
    const request = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method,
        path: targetUrl,
        headers: { host: target.host, ...headers },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            statusCode: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    request.on("error", reject);
    request.end();
  });
}

function connectThroughProxy({ proxyPort, authority }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, "127.0.0.1");
    let buffer = "";
    socket.on("connect", () => {
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
      );
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString("latin1");
      if (buffer.includes("\r\n\r\n")) {
        const statusLine = buffer.split("\r\n")[0];
        resolve({ socket, statusLine, buffer });
      }
    });
    socket.on("error", reject);
  });
}

function websocketThroughProxy({ proxyPort, targetUrl }) {
  return new Promise((resolve, reject) => {
    const target = new URL(targetUrl);
    const request = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "GET",
      path: targetUrl,
      headers: {
        host: target.host,
        connection: "Upgrade",
        upgrade: "websocket",
        "sec-websocket-version": "13",
        "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
      },
    });
    const timer = setTimeout(() => {
      request.destroy();
      reject(new Error("websocket proxy response timed out"));
    }, 5000);
    request.on("upgrade", (response, socket) => {
      clearTimeout(timer);
      resolve({ response, socket });
    });
    request.on("response", (response) => {
      clearTimeout(timer);
      response.resume();
      resolve({ response, socket: response.socket });
    });
    request.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    request.end();
  });
}

async function buildHarness({
  allowedDomains = "127.0.0.1",
  allowedPorts,
  allowPrivateNetworks = true,
  authToken = "",
  allowWebSocketPort = false,
  resolver,
} = {}) {
  const targetHits = [];
  const openSockets = new Set();
  const target = http.createServer((req, res) => {
    targetHits.push(req.url);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });

  const upgradeHits = [];
  const websocketTarget = http.createServer();
  websocketTarget.on("connection", (socket) => {
    openSockets.add(socket);
    socket.once("close", () => openSockets.delete(socket));
  });
  websocketTarget.on("upgrade", (req, socket) => {
    upgradeHits.push(req.url);
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "connection: Upgrade\r\n" +
        "upgrade: websocket\r\n" +
        "\r\n",
    );
    socket.on("data", (chunk) => socket.write(chunk));
  });

  const targetPort = await listen(target);
  const websocketPort = await listen(websocketTarget);

  const effectivePorts =
    allowedPorts ||
    (allowWebSocketPort ? `${websocketPort}` : `${targetPort}`);

  const policy = createEgressPolicy({
    allowedDomains,
    allowedPorts: effectivePorts,
    defaultDomainPolicy: "deny",
    allowPrivateNetworks,
    resolver,
  });

  const proxy = createEgressProxy({ policy, authToken });
  proxy.on("connection", (socket) => {
    openSockets.add(socket);
    socket.once("close", () => openSockets.delete(socket));
  });
  const proxyPort = await listen(proxy);
  const health = createProxyHealthServer({ policy });
  const healthPort = await listen(health);

  return {
    targetHits,
    upgradeHits,
    targetPort,
    websocketPort,
    proxyPort,
    healthPort,
    async close() {
      for (const socket of openSockets) {
        socket.destroy();
      }
      proxy.closeAllConnections?.();
      websocketTarget.closeAllConnections?.();
      await close(proxy);
      await close(health);
      await close(target);
      await close(websocketTarget);
    },
  };
}

test("forwards an allowed HTTP destination and blocks a disallowed port", async () => {
  const harness = await buildHarness();
  try {
    const allowed = await httpThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `http://127.0.0.1:${harness.targetPort}/allowed`,
    });
    assert.equal(allowed.statusCode, 200);
    assert.equal(allowed.body, "ok");

    const blocked = await httpThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `http://127.0.0.1:${harness.websocketPort}/blocked`,
    });
    assert.equal(blocked.statusCode, 403);
    assert.equal(blocked.headers["x-agentshield-blocked"], "PORT_NOT_ALLOWED");
    assert.deepEqual(harness.targetHits, ["/allowed"]);
  } finally {
    await harness.close();
  }
});

test("blocks loopback and metadata through CONNECT and allows the approved port", async () => {
  const harness = await buildHarness();
  try {
    const allowed = await connectThroughProxy({
      proxyPort: harness.proxyPort,
      authority: `127.0.0.1:${harness.targetPort}`,
    });
    assert.match(allowed.statusLine, /200/);
    allowed.socket.destroy();

    const blocked = await connectThroughProxy({
      proxyPort: harness.proxyPort,
      authority: `127.0.0.1:${harness.websocketPort}`,
    });
    assert.match(blocked.statusLine, /403/);
    blocked.socket.destroy();

    const metadata = await connectThroughProxy({
      proxyPort: harness.proxyPort,
      authority: "169.254.169.254:80",
    });
    assert.match(metadata.statusLine, /403/);
    metadata.socket.destroy();
  } finally {
    await harness.close();
  }
});

test("forwards an allowed WebSocket upgrade and blocks a disallowed one", async () => {
  const harness = await buildHarness({ allowWebSocketPort: true });
  try {
    const allowed = await websocketThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `ws://127.0.0.1:${harness.websocketPort}/ws`,
    });
    assert.equal(allowed.response.statusCode, 101);
    const echoed = await new Promise((resolve) => {
      allowed.socket.once("data", (chunk) => resolve(chunk.toString("utf8")));
      allowed.socket.write("ping");
    });
    assert.equal(echoed, "ping");
    allowed.socket.destroy();

    const blocked = await websocketThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `ws://127.0.0.1:${harness.targetPort}/ws`,
    });
    assert.equal(blocked.response.statusCode, 403);
    assert.deepEqual(harness.upgradeHits, ["/ws"]);
  } finally {
    await harness.close();
  }
});

test("blocks WebSocket upgrades to private IPs before connecting upstream", async () => {
  const harness = await buildHarness({
    allowPrivateNetworks: false,
    allowedDomains: "127.0.0.1",
    allowedPorts: "80,443,1024-65535",
  });
  try {
    const blocked = await websocketThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `ws://127.0.0.1:${harness.websocketPort}/private`,
    });
    assert.equal(blocked.response.statusCode, 403);
    assert.equal(blocked.response.headers["x-agentshield-blocked"], "PRIVATE_IP_BLOCKED");
    assert.deepEqual(harness.upgradeHits, []);
  } finally {
    await harness.close();
  }
});

test("requires proxy authentication when configured", async () => {
  const harness = await buildHarness({ authToken: "proxy-secret" });
  try {
    const unauthenticated = await httpThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `http://127.0.0.1:${harness.targetPort}/auth`,
    });
    assert.equal(unauthenticated.statusCode, 407);

    const wrong = await httpThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `http://127.0.0.1:${harness.targetPort}/auth`,
      headers: {
        "proxy-authorization": `Basic ${Buffer.from("agentshield:wrong").toString("base64")}`,
      },
    });
    assert.equal(wrong.statusCode, 407);

    const correct = await httpThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: `http://127.0.0.1:${harness.targetPort}/auth`,
      headers: {
        "proxy-authorization": `Basic ${Buffer.from("agentshield:proxy-secret").toString("base64")}`,
      },
    });
    assert.equal(correct.statusCode, 200);
  } finally {
    await harness.close();
  }
});

test("blocks DNS rebinding answers at connection time", async () => {
  const harness = await buildHarness({
    allowedDomains: "rebind.test",
    allowedPorts: "80",
    allowPrivateNetworks: false,
    resolver: async () => [{ address: "127.0.0.1", family: 4 }],
  });
  try {
    const blocked = await httpThroughProxy({
      proxyPort: harness.proxyPort,
      targetUrl: "http://rebind.test/",
    });
    assert.equal(blocked.statusCode, 403);
    assert.equal(blocked.headers["x-agentshield-blocked"], "PRIVATE_IP_BLOCKED");
  } finally {
    await harness.close();
  }
});

test("health endpoint reports enforcing mode", async () => {
  const harness = await buildHarness();
  try {
    const body = await new Promise((resolve, reject) => {
      const request = http.get(
        {
          host: "127.0.0.1",
          port: harness.healthPort,
          path: "/health/ready",
        },
        (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () =>
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))),
          );
        },
      );
      request.on("error", reject);
    });

    assert.equal(body.status, "ok");
    assert.equal(body.mode, "enforcing");
    assert.equal(body.checks.policy, "ok");
  } finally {
    await harness.close();
  }
});

test("health endpoint returns degraded when default policy is allow", async () => {
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "80,443",
    defaultDomainPolicy: "allow",
    allowPrivateNetworks: false,
  });
  const health = createProxyHealthServer({ policy });
  try {
    const port = await listen(health);
    const body = await new Promise((resolve, reject) => {
      const request = http.get(
        { host: "127.0.0.1", port, path: "/health/ready" },
        (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () =>
            resolve({
              status: response.statusCode,
              body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
            }),
          );
        },
      );
      request.on("error", reject);
    });

    assert.equal(body.status, 503);
    assert.equal(body.body.status, "degraded");
    assert.equal(body.body.mode, "permissive");
  } finally {
    await close(health);
  }
});

test("HTTP upstream timeout returns 504 UPSTREAM_TIMEOUT not 403 PORT_NOT_ALLOWED", async () => {
  const slowTarget = http.createServer((req, res) => {
    // Never respond — triggers upstream timeout
  });
  try {
    const targetPort = await listen(slowTarget);
    const policy = createEgressPolicy({
      allowedDomains: "allowed.test",
      allowedPorts: String(targetPort),
      defaultDomainPolicy: "deny",
      allowPrivateNetworks: true,
      resolver: async () => [{ address: "127.0.0.1", family: 4 }],
    });
    const proxy = createEgressProxy({
      policy,
      connectTimeoutMs: 200,
    });
    const proxyPort = await listen(proxy);
    try {
      const result = await httpThroughProxy({
        proxyPort,
        targetUrl: `http://allowed.test:${targetPort}/`,
      });
      assert.equal(result.statusCode, 504);
      assert.equal(result.headers["x-agentshield-blocked"], "UPSTREAM_TIMEOUT");
    } finally {
      await close(proxy);
    }
  } finally {
    await close(slowTarget);
  }
});

test("blocks HTTP requests to metadata IP via proxy", async () => {
  // Use a custom policy that allows port 80 so the IP check is reached
  const policy = createEgressPolicy({
    allowedDomains: "example.com",
    allowedPorts: "80",
    defaultDomainPolicy: "allow",
    allowPrivateNetworks: false,
  });
  const proxy = createEgressProxy({ policy });
  const proxyPort = await listen(proxy);
  try {
    const result = await httpThroughProxy({
      proxyPort,
      targetUrl: "http://169.254.169.254/",
    });
    assert.equal(result.statusCode, 403);
    assert.equal(result.headers["x-agentshield-blocked"], "PRIVATE_IP_BLOCKED");
  } finally {
    await close(proxy);
  }
});
