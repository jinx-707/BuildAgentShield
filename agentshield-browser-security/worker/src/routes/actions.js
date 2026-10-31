import { Router } from "express";

import { config } from "../config.js";
import {
  EgressProxyError,
  assertEgressEnforcement,
} from "../lib/egress.js";
import {
  ActionError,
  ActionTimeoutError,
  runAction,
} from "../lib/actions.js";
import {
  ContextLimitExceededError,
  SessionBusyError,
  SessionForbiddenError,
  SessionNotFoundError,
  checkoutSession,
} from "../lib/browser.js";
import { installPageSecurity } from "../lib/page_security.js";
import {
  AGENT_ID_HEADER,
  AgentIdValidationError,
  SESSION_ID_HEADER,
  SessionIdValidationError,
  parseAgentId,
  parseSessionId,
} from "../lib/session_guard.js";
import { UrlValidationError } from "../lib/url_guard.js";

const MIN_ACTION_TIMEOUT_MS = 1000;

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
    return config.actionTimeoutMs;
  }
  if (
    !Number.isInteger(value) ||
    value < MIN_ACTION_TIMEOUT_MS ||
    value > config.actionTimeoutMaxMs
  ) {
    throw new RequestValidationError(
      `timeout_ms must be an integer between ${MIN_ACTION_TIMEOUT_MS} and ${config.actionTimeoutMaxMs}`,
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

async function withTimeout(promise, timeoutMs, onTimeout) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ActionTimeoutError()), timeoutMs);
    timer.unref?.();
  });

  try {
    return await Promise.race([promise, timeout]);
  } catch (error) {
    if (error instanceof ActionTimeoutError) {
      await onTimeout().catch(() => {});
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

const router = Router();

router.post("/action", async (req, res) => {
  let secured;
  try {
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new RequestValidationError("request body must be a JSON object");
    }

    const sessionId = parseSessionId(req.get(SESSION_ID_HEADER));
    if (sessionId === null) {
      throw new RequestValidationError("session id is required for browser actions");
    }
    const agentId = parseAgentId(req.get(AGENT_ID_HEADER));
    const timeoutMs = parseTimeout(body.timeout_ms);

    await assertEgressEnforcement();

    secured = await checkoutSession({
      sessionId,
      owner: agentId,
      requestId: req.id,
    });

    const security =
      secured.security ?? (await installPageSecurity(secured.page, { requestId: req.id }));

    const action = { ...body };
    delete action.timeout_ms;

    const result = await withTimeout(
      runAction({
        page: secured.page,
        security,
        action,
        requestId: req.id,
        sessionId,
        timeoutMs,
      }),
      timeoutMs,
      () => secured.close(),
    );

    res.json(result);
  } catch (error) {
    if (error instanceof EgressProxyError) {
      req.log.error(
        {
          event: "egress_policy_violation",
          code: error.code,
          request_id: req.id,
        },
        "egress_proxy_unavailable",
      );
      res.status(error.status || 503).json(envelope(error, req));
      return;
    }

    if (
      error instanceof SessionNotFoundError ||
      error instanceof SessionForbiddenError ||
      error instanceof SessionBusyError
    ) {
      req.log.warn(
        { event: "action_session_refused", code: error.code, request_id: req.id },
        "action_session_refused",
      );
      res.status(error.status).json(envelope(error, req));
      return;
    }

    if (error instanceof ActionError) {
      if (error.status >= 400) {
        req.log.warn(
          {
            event: "browser_action_refused",
            code: error.code,
            status: error.status,
            request_id: req.id,
          },
          "browser_action_refused",
        );
      }
      res.status(error.status).json(envelope(error, req));
      return;
    }

    if (
      error instanceof UrlValidationError ||
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

    if (error instanceof ActionTimeoutError) {
      res.status(504).json(envelope(error, req));
      return;
    }

    if (isBrowserDisconnectedError(error)) {
      req.log.warn(
        { event: "browser_action_disconnected", request_id: req.id },
        "browser_action_disconnected",
      );
      res.status(503).json({
        error: "service_unavailable",
        code: "BROWSER_CONTEXT_UNAVAILABLE",
        message: "the browser context is no longer available",
        request_id: req.id,
      });
      return;
    }

    req.log.error({ err: error }, "browser_action_failed");
    res.status(500).json({
      error: "internal_error",
      message: "internal server error",
      request_id: req.id,
    });
  } finally {
    if (secured) {
      secured.release();
    }
  }
});

export default router;
