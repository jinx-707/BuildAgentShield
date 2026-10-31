import http from "node:http";
import https from "node:https";
import net from "node:net";
import { timingSafeEqual } from "node:crypto";

import { EgressPolicyError, normalizeHostname } from "./policy.js";
import { logger } from "./logger.js";

const HOP_BY_HOP_HEADERS = new Set([
  "proxy-authorization",
  "proxy-connection",
  "proxy-authenticate",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left ?? ""));
  const rightBuffer = Buffer.from(String(right ?? ""));
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function readProxyCredentials(header) {
  if (typeof header !== "string" || !header.startsWith("Basic ")) {
    return null;
  }
  try {
    const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString(
      "utf8",
    );
    const separator = decoded.indexOf(":");
    if (separator < 0) {
      return null;
    }
    return {
      username: decoded.slice(0, separator),
      password: decoded.slice(separator + 1),
    };
  } catch {
    return null;
  }
}

function createAuthenticator({ authToken }) {
  if (!authToken) {
    return () => true;
  }

  return (req) => {
    const credentials = readProxyCredentials(req.headers["proxy-authorization"]);
    if (!credentials) {
      return false;
    }
    return (
      safeEqual(credentials.username, "agentshield") &&
      safeEqual(credentials.password, authToken)
    );
  };
}

function parseAuthority(authority) {
  if (typeof authority !== "string" || authority === "") {
    throw new EgressPolicyError(
      "INVALID_DESTINATION",
      "proxy request is missing a destination authority",
    );
  }

  let parsed;
  try {
    parsed = new URL(`http://${authority}`);
  } catch {
    throw new EgressPolicyError(
      "INVALID_DESTINATION",
      "proxy request contains an invalid destination authority",
    );
  }

  const port = parsed.port
    ? Number.parseInt(parsed.port, 10)
    : 443;
  return {
    hostname: normalizeHostname(parsed.hostname),
    port,
  };
}

function destinationFromAbsoluteUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new EgressPolicyError(
      "INVALID_DESTINATION",
      "proxy request contains an invalid URL",
    );
  }

  let protocol = parsed.protocol.toLowerCase();
  if (protocol === "ws:") {
    protocol = "http:";
  } else if (protocol === "wss:") {
    protocol = "https:";
  }

  if (!["http:", "https:"].includes(protocol)) {
    throw new EgressPolicyError(
      "URL_SCHEME_NOT_ALLOWED",
      "only http, https, ws and wss destinations are permitted",
    );
  }

  const defaultPort = protocol === "https:" ? 443 : 80;
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : defaultPort;
  return {
    protocol,
    hostname: normalizeHostname(parsed.hostname),
    port,
    path: `${parsed.pathname || "/"}${parsed.search}`,
    hostHeader: parsed.port ? parsed.host : parsed.hostname,
  };
}

function writeJsonResponse(res, status, code, message) {
  const body = JSON.stringify({ error: "egress_blocked", code, message });
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "x-agentshield-blocked": code,
    "proxy-connection": "close",
  });
  res.end(body);
}

function writeConnectError(socket, status, code, message) {
  if (!socket || socket.destroyed) {
    return;
  }
  const body = JSON.stringify({ error: "egress_blocked", code, message });
  const reason = http.STATUS_CODES[status] || "Blocked";
  socket.write(
    `HTTP/1.1 ${status} ${reason}\r\n` +
      "content-type: application/json\r\n" +
      `content-length: ${Buffer.byteLength(body)}\r\n` +
      `x-agentshield-blocked: ${code}\r\n` +
      "proxy-connection: close\r\n" +
      "\r\n" +
      body,
  );
  socket.end();
}

function writeConnectSuccess(socket, head, upstream) {
  socket.write(
    "HTTP/1.1 200 Connection Established\r\n" +
      "proxy-agent: agentshield-egress-proxy\r\n" +
      "\r\n",
  );
  if (head && head.length > 0) {
    upstream.write(head);
  }
  socket.once("close", () => upstream.destroy());
  upstream.once("close", () => socket.destroy());
  upstream.pipe(socket);
  socket.pipe(upstream);
}

function connectWithFallback({ destination, timeoutMs, onConnect, onError }) {
  const candidates = destination.addresses.length
    ? destination.addresses
    : [{ address: destination.address, family: destination.family }];
  let index = 0;

  const attempt = () => {
    const candidate = candidates[index];
    index += 1;

    const socket = net.connect({
      host: candidate.address,
      port: destination.port,
      family: candidate.family,
    });

    const timer = setTimeout(() => {
      socket.destroy(new Error("upstream connection timed out"));
    }, timeoutMs);
    timer.unref?.();

    socket.once("connect", () => {
      clearTimeout(timer);
      onConnect(socket);
    });

    socket.once("error", (error) => {
      clearTimeout(timer);
      if (index < candidates.length) {
        attempt();
        return;
      }
      onError(error);
    });
  };

  attempt();
}

function formatUpgradeResponseHead(statusCode, headers) {
  const lines = [
    `HTTP/1.1 ${statusCode} ${http.STATUS_CODES[statusCode] || ""}\r\n`,
  ];
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const entry of value) {
        lines.push(`${name}: ${entry}\r\n`);
      }
    } else {
      lines.push(`${name}: ${value}\r\n`);
    }
  }
  lines.push("\r\n");
  return lines.join("");
}

function forwardableHeaders(req, hostHeader, includeUpgrade = false) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (lower === "connection" && includeUpgrade) {
      headers[name] = value;
      continue;
    }
    if (HOP_BY_HOP_HEADERS.has(lower) && !(includeUpgrade && lower === "upgrade")) {
      continue;
    }
    if (lower === "proxy-authorization") {
      continue;
    }
    headers[name] = value;
  }
  headers.host = hostHeader;
  return headers;
}

export function createEgressProxy({
  policy,
  authToken = "",
  connectTimeoutMs = 10000,
  logger: log = logger,
}) {
  const isAuthenticated = createAuthenticator({ authToken });

  function block(req, res, error) {
    const code = error instanceof EgressPolicyError ? error.code : "EGRESS_BLOCKED";
    const message =
      error instanceof EgressPolicyError
        ? error.message
        : "the destination is not permitted by egress policy";
    const status = error instanceof EgressPolicyError ? error.status : 403;
    log.warn("egress_blocked", {
      code,
      method: req.method,
      destination: req.headers.host,
    });
    writeJsonResponse(res, status, code, message);
  }

  async function handleHttpRequest(req, res) {
    if (!isAuthenticated(req)) {
      res.writeHead(407, {
        "proxy-authenticate": 'Basic realm="AgentShield Egress"',
        "content-type": "application/json",
        "proxy-connection": "close",
      });
      res.end(
        JSON.stringify({
          error: "proxy_auth_required",
          code: "PROXY_AUTH_FAILED",
          message: "proxy authentication is required",
        }),
      );
      log.warn("proxy_auth_failed", { method: req.method });
      return;
    }

    let destination;
    try {
      destination = destinationFromAbsoluteUrl(req.url);
      const resolved = await policy.resolveDestination(
        destination.hostname,
        destination.port,
      );
      destination.resolved = resolved;
    } catch (error) {
      block(req, res, error);
      return;
    }

    const isTls = destination.protocol === "https:";
    const transport = isTls ? https : http;
    const requestOptions = {
      host: destination.resolved.address,
      port: destination.port,
      method: req.method,
      path: destination.path,
      headers: forwardableHeaders(req, destination.hostHeader),
      agent: false,
      timeout: connectTimeoutMs,
    };
    if (isTls) {
      requestOptions.servername = destination.hostname;
    }

    const upstreamRequest = transport.request(requestOptions);

    upstreamRequest.on("response", (upstreamResponse) => {
      const responseHeaders = { ...upstreamResponse.headers };
      delete responseHeaders["proxy-authenticate"];
      delete responseHeaders.connection;
      res.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
      upstreamResponse.pipe(res);
    });

    upstreamRequest.on("timeout", () => {
      upstreamRequest.destroy(new Error("upstream request timed out"));
      if (!res.headersSent) {
        writeJsonResponse(
          res,
          504,
          "UPSTREAM_TIMEOUT",
          "the upstream server did not respond within the timeout period",
        );
      }
    });

    upstreamRequest.on("error", () => {
      if (!res.headersSent) {
        writeJsonResponse(
          res,
          502,
          "UPSTREAM_CONNECTION_FAILED",
          "the approved upstream connection failed",
        );
      } else {
        res.destroy();
      }
    });

    req.pipe(upstreamRequest);
  }

  function handleConnect(req, clientSocket, head) {
    if (!isAuthenticated(req)) {
      clientSocket.write(
        "HTTP/1.1 407 Proxy Authentication Required\r\n" +
          'proxy-authenticate: Basic realm="AgentShield Egress"\r\n' +
          "content-length: 0\r\n" +
          "proxy-connection: close\r\n" +
          "\r\n",
      );
      clientSocket.destroy();
      log.warn("proxy_auth_failed", { method: "CONNECT" });
      return;
    }

    let destination;
    try {
      destination = parseAuthority(req.url);
    } catch (error) {
      const code =
        error instanceof EgressPolicyError ? error.code : "INVALID_DESTINATION";
      log.warn("egress_blocked", {
        code,
        method: "CONNECT",
        destination: req.url,
      });
      writeConnectError(clientSocket, 403, code, error.message);
      return;
    }

    policy
      .resolveDestination(destination.hostname, destination.port)
      .then((resolved) => {
        connectWithFallback({
          destination: resolved,
          timeoutMs: connectTimeoutMs,
          onConnect: (upstream) => {
            log.debug("egress_allowed", {
              method: "CONNECT",
              hostname: destination.hostname,
              port: destination.port,
              address: upstream.remoteAddress,
            });
            writeConnectSuccess(clientSocket, head, upstream);
          },
          onError: () => {
            writeConnectError(
              clientSocket,
              502,
              "UPSTREAM_CONNECTION_FAILED",
              "the approved upstream connection failed",
            );
          },
        });
      })
      .catch((error) => {
        const code =
          error instanceof EgressPolicyError ? error.code : "EGRESS_BLOCKED";
        log.warn("egress_blocked", {
          code,
          method: "CONNECT",
          destination: req.url,
        });
        writeConnectError(clientSocket, 403, code, error.message);
      });
  }

  function handleUpgrade(req, clientSocket, head) {
    if (!isAuthenticated(req)) {
      writeConnectError(
        clientSocket,
        407,
        "PROXY_AUTH_FAILED",
        "proxy authentication is required",
      );
      log.warn("proxy_auth_failed", { method: "UPGRADE" });
      return;
    }

    let destination;
    try {
      destination = destinationFromAbsoluteUrl(req.url);
    } catch (error) {
      const code =
        error instanceof EgressPolicyError ? error.code : "INVALID_DESTINATION";
      log.warn("egress_blocked", {
        code,
        method: "UPGRADE",
        destination: req.headers.host,
      });
      writeConnectError(clientSocket, 403, code, error.message);
      return;
    }

    policy
      .resolveDestination(destination.hostname, destination.port)
      .then((resolved) => {
        const isTls = destination.protocol === "https:";
        const transport = isTls ? https : http;
        const requestOptions = {
          host: resolved.address,
          port: destination.port,
          method: req.method,
          path: destination.path,
          headers: forwardableHeaders(req, destination.hostHeader, true),
          agent: false,
        };
        if (isTls) {
          requestOptions.servername = destination.hostname;
        }

        const upstreamRequest = transport.request(requestOptions);

        const upgradeTimer = setTimeout(() => {
          upstreamRequest.destroy(new Error("upstream upgrade timed out"));
        }, connectTimeoutMs);
        upgradeTimer.unref?.();

        upstreamRequest.on("upgrade", (upstreamResponse, upstreamSocket, upstreamHead) => {
          clearTimeout(upgradeTimer);
          log.debug("egress_allowed", {
            method: "UPGRADE",
            hostname: destination.hostname,
            port: destination.port,
            address: upstreamSocket.remoteAddress,
          });
          clientSocket.write(
            formatUpgradeResponseHead(
              upstreamResponse.statusCode || 101,
              upstreamResponse.headers,
            ),
          );
          if (upstreamHead && upstreamHead.length > 0) {
            clientSocket.write(upstreamHead);
          }
          if (head && head.length > 0) {
            upstreamSocket.write(head);
          }
          clientSocket.once("close", () => upstreamSocket.destroy());
          upstreamSocket.once("close", () => clientSocket.destroy());
          upstreamSocket.pipe(clientSocket);
          clientSocket.pipe(upstreamSocket);
        });

        upstreamRequest.on("response", (upstreamResponse) => {
          clearTimeout(upgradeTimer);
          clientSocket.write(
            formatUpgradeResponseHead(
              upstreamResponse.statusCode || 502,
              upstreamResponse.headers,
            ),
          );
          upstreamResponse.pipe(clientSocket);
        });

        upstreamRequest.on("error", () => {
          clearTimeout(upgradeTimer);
          clientSocket.destroy();
        });

        upstreamRequest.end();
      })
      .catch((error) => {
        const code =
          error instanceof EgressPolicyError ? error.code : "EGRESS_BLOCKED";
        log.warn("egress_blocked", {
          code,
          method: "UPGRADE",
          destination: req.headers.host,
        });
        const status =
          error instanceof EgressPolicyError ? error.status : 403;
        const message =
          error instanceof EgressPolicyError
            ? error.message
            : "the destination is not permitted by egress policy";
        writeConnectError(clientSocket, status, code, message);
      });
  }

  const server = http.createServer((req, res) => {
    void handleHttpRequest(req, res);
  });
  server.on("connect", handleConnect);
  server.on("upgrade", handleUpgrade);
  server.on("clientError", (error, socket) => {
    if (socket.writable) {
      socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    }
  });

  return server;
}

export function createProxyHealthServer({ policy, version = "0.1.0" }) {
  return http.createServer((req, res) => {
    const path = new URL(req.url || "/", "http://proxy.local").pathname;
    if (path !== "/health/live" && path !== "/health/ready" && path !== "/health") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }

    if (path === "/health/live") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          service: "agentshield-egress-proxy",
          checks: { process: "ok" },
        }),
      );
      return;
    }

    // Derive enforcement mode from actual policy configuration.
    // "enforcing" only when default-deny; a permissive default would allow
    // arbitrary destinations not on the blocklist.
    const enforcing = policy.defaultDomainPolicy === "deny";

    if (!enforcing) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          status: "degraded",
          service: "agentshield-egress-proxy",
          version,
          mode: "permissive",
          reason: "default domain policy is not deny — egress is not enforcing",
          checks: {
            policy: "degraded",
            allow_private_networks: Boolean(policy.allowPrivateNetworks),
          },
        }),
      );
      return;
    }

    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        service: "agentshield-egress-proxy",
        version,
        mode: "enforcing",
        checks: {
          policy: "ok",
          allow_private_networks: Boolean(policy.allowPrivateNetworks),
        },
      }),
    );
  });
}
