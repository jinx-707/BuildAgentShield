import { randomUUID, timingSafeEqual } from "node:crypto";

import express from "express";
import pinoHttp from "pino-http";

import { config } from "./config.js";
import { logger } from "./lib/logger.js";
import actionRouter from "./routes/actions.js";
import extractRouter from "./routes/extract.js";
import healthRouter from "./routes/health.js";
import navigateRouter from "./routes/navigate.js";
import screenshotRouter from "./routes/screenshot.js";
import sessionRouter from "./routes/session.js";

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Validate the inbound Authorization: Bearer header against the configured
 * worker authentication token.
 *
 * Returns true when:
 *   - auth is disabled (workerAuthToken is empty string) AND environment is
 *     not production, OR
 *   - the supplied token matches the configured token via timing-safe comparison.
 *
 * Always returns false (enforces auth) in all other cases.
 */
function hasValidWorkerToken(req) {
  if (!config.workerAuthToken) {
    // Production fail-closed: a missing token in production is a
    // misconfiguration that must have been caught at startup (see createApp).
    // If we somehow reach here without a token in production, deny by default.
    return config.environment !== "production";
  }

  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    return false;
  }

  const supplied = Buffer.from(header.slice("Bearer ".length));
  const expected = Buffer.from(config.workerAuthToken);
  return (
    supplied.length === expected.length && timingSafeEqual(supplied, expected)
  );
}

export function createApp() {
  // Fail closed: production deployments must configure a worker auth token.
  // An empty token in production would silently disable authentication.
  if (config.environment === "production" && !config.workerAuthToken) {
    throw new Error(
      "WORKER_AUTH_REQUIRED: WORKER_AUTH_TOKEN must be set in production. " +
        "Refusing to start with unauthenticated worker endpoints.",
    );
  }

  const app = express();
  app.disable("x-powered-by");

  app.use(
    pinoHttp({
      logger,
      genReqId(req, res) {
        const incoming = req.headers["x-request-id"];
        const requestId =
          typeof incoming === "string" && REQUEST_ID_PATTERN.test(incoming)
            ? incoming
            : randomUUID();
        res.setHeader("x-request-id", requestId);
        return requestId;
      },
      customLogLevel(req, res, error) {
        if (error || res.statusCode >= 500) {
          return "error";
        }
        if (res.statusCode >= 400) {
          return "warn";
        }
        return "info";
      },
      customSuccessMessage() {
        return "request_completed";
      },
      customErrorMessage() {
        return "request_failed";
      },
      serializers: {
        req(req) {
          return { id: req.id, method: req.method, url: req.url };
        },
        res(res) {
          return { status_code: res.statusCode };
        },
      },
    }),
  );

  app.use(express.json({ limit: "32kb" }));

  app.use("/health", healthRouter);
  app.use("/v1", (req, res, next) => {
    if (!hasValidWorkerToken(req)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).json({
        error: "unauthorized",
        code: "WORKER_AUTH_FAILED",
        message: "worker authentication failed",
        request_id: req.id,
      });
      return;
    }
    next();
  });
  app.use("/v1", navigateRouter);
  app.use("/v1", sessionRouter);
  app.use("/v1", extractRouter);
  app.use("/v1", actionRouter);
  app.use("/v1", screenshotRouter);

  app.use((req, res) => {
    res.status(404).json({
      error: "not_found",
      message: "route not found",
      request_id: req.id,
    });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }

    if (error?.type === "entity.parse.failed") {
      res.status(400).json({
        error: "invalid_json",
        message: "request body is not valid JSON",
        request_id: req.id,
      });
      return;
    }

    if (error?.type === "entity.too.large") {
      res.status(413).json({
        error: "payload_too_large",
        message: "request body is too large",
        request_id: req.id,
      });
      return;
    }

    req.log.error({ err: error }, "unhandled_request_error");
    res.status(500).json({
      error: "internal_error",
      message: "internal server error",
      request_id: req.id,
    });
  });

  return app;
}
