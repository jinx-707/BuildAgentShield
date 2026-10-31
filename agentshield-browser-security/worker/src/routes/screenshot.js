import { Router } from "express";

import { config } from "../config.js";
import {
  ContextLimitExceededError,
  SessionBusyError,
  SessionForbiddenError,
  SessionNotFoundError,
  checkoutSession,
} from "../lib/browser.js";
import {
  ScreenshotError,
  ScreenshotTimeoutError,
  beginScreenshot,
  captureScreenshot,
  withScreenshotTimeout,
} from "../lib/screenshot.js";
import {
  AGENT_ID_HEADER,
  AgentIdValidationError,
  SESSION_ID_HEADER,
  SessionIdValidationError,
  parseAgentId,
  parseSessionId,
} from "../lib/session_guard.js";

const MIN_SCREENSHOT_TIMEOUT_MS = 1000;

class RequestValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RequestValidationError";
    this.code = "INVALID_REQUEST";
    this.status = 400;
  }
}

function parseTimeout(value) {
  if (value === undefined) {
    return config.screenshotTimeoutMs;
  }
  if (
    !Number.isInteger(value) ||
    value < MIN_SCREENSHOT_TIMEOUT_MS ||
    value > config.screenshotTimeoutMaxMs
  ) {
    throw new RequestValidationError(
      `timeout_ms must be an integer between ${MIN_SCREENSHOT_TIMEOUT_MS} and ${config.screenshotTimeoutMaxMs}`,
    );
  }
  return value;
}

function isBrowserDisconnectedError(error) {
  const message = String(error?.message ?? "");
  return /target closed|session closed|protocol error|detached|browser closed|browser has disconnected|connection closed|page closed/i.test(
    message,
  );
}

function envelope(error, req) {
  const status = error.status || 400;
  const payload = {
    error:
      status === 403
        ? "blocked"
        : status === 404
          ? "not_found"
          : status === 409
            ? "conflict"
            : status === 413
              ? "payload_too_large"
              : status === 429
                ? "rate_limited"
                : status === 503
                  ? "service_unavailable"
                  : status === 504
                    ? "timeout"
                    : "invalid_request",
    code: error.code,
    message: error.message,
    request_id: req.id,
  };
  if (error.details && typeof error.details === "object") {
    payload.details = error.details;
  }
  return payload;
}

const router = Router();

router.post("/screenshot", async (req, res) => {
  let secured;
  let releaseCapture;
  try {
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new RequestValidationError("request body must be a JSON object");
    }

    const sessionId = parseSessionId(req.get(SESSION_ID_HEADER));
    if (sessionId === null) {
      throw new RequestValidationError("session id is required for screenshots");
    }
    const agentId = parseAgentId(req.get(AGENT_ID_HEADER));
    const timeoutMs = parseTimeout(body.timeout_ms);

    secured = await checkoutSession({
      sessionId,
      owner: agentId,
      requestId: req.id,
    });

    releaseCapture = beginScreenshot(sessionId);

    const result = await withScreenshotTimeout(
      captureScreenshot(secured.page, {
        fullPage: body.full_page === true,
        clip: body.clip ?? null,
      }),
      timeoutMs,
      () => secured.close(),
    );

    res.status(200);
    res.set({
      "Content-Type": "image/png",
      "Content-Disposition": 'inline; filename="screenshot.png"',
      "Cache-Control": "no-store, max-age=0",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "X-Screenshot-Width": String(result.width),
      "X-Screenshot-Height": String(result.height),
      "X-Screenshot-Bytes": String(result.bytes),
      "X-Screenshot-Full-Page": result.full_page ? "true" : "false",
      "X-Screenshot-Elapsed-Ms": String(result.elapsed_ms),
    });
    res.send(result.buffer);
  } catch (error) {
    if (
      error instanceof SessionNotFoundError ||
      error instanceof SessionForbiddenError ||
      error instanceof SessionBusyError
    ) {
      req.log.warn(
        { event: "screenshot_session_refused", code: error.code, request_id: req.id },
        "screenshot_session_refused",
      );
      res.status(error.status).json(envelope(error, req));
      return;
    }

    if (error instanceof ScreenshotError) {
      req.log.warn(
        {
          event: "screenshot_refused",
          code: error.code,
          status: error.status,
          request_id: req.id,
        },
        "screenshot_refused",
      );
      res.status(error.status).json(envelope(error, req));
      return;
    }

    if (
      error instanceof RequestValidationError ||
      error instanceof SessionIdValidationError ||
      error instanceof AgentIdValidationError
    ) {
      res.status(error.status || 400).json(envelope(error, req));
      return;
    }

    if (
      error instanceof ContextLimitExceededError ||
      error?.code === "SESSION_LIMIT_EXCEEDED"
    ) {
      res.status(503).json(envelope(error, req));
      return;
    }

    if (error instanceof ScreenshotTimeoutError) {
      res.status(504).json(envelope(error, req));
      return;
    }

    if (isBrowserDisconnectedError(error)) {
      req.log.warn(
        { event: "screenshot_disconnected", request_id: req.id },
        "screenshot_disconnected",
      );
      res.status(503).json({
        error: "service_unavailable",
        code: "BROWSER_CONTEXT_UNAVAILABLE",
        message: "the browser context is no longer available",
        request_id: req.id,
      });
      return;
    }

    req.log.error({ err: error }, "screenshot_failed");
    res.status(500).json({
      error: "internal_error",
      message: "internal server error",
      request_id: req.id,
    });
  } finally {
    if (releaseCapture) releaseCapture();
    if (secured) secured.release();
  }
});

export default router;
