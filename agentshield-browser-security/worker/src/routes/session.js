import { Router } from "express";

import { config } from "../config.js";
import {
  ContextLimitExceededError,
  SessionBusyError,
  SessionForbiddenError,
  SessionLimitExceededError,
  SessionNotFoundError,
  closeSession,
  createSession,
  getSession,
} from "../lib/browser.js";
import {
  SESSION_ID_PATTERN,
  AGENT_ID_HEADER,
  AgentIdValidationError,
  SessionIdValidationError,
  parseAgentId,
} from "../lib/session_guard.js";

/**
 * A3 — persistent browser sessions.
 *
 * Every route here resolves the session through the registry and the owner
 * identity before it touches a browser context, so a session ID on its own
 * authorizes nothing. The response bodies carry lifecycle metadata only: no
 * cookies, no page content, no browser internals.
 */

const MIN_SESSION_TIMEOUT_MS = 30000;

class RequestValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RequestValidationError";
    this.code = "INVALID_REQUEST";
    this.status = 400;
  }
}

function parseBody(req) {
  const body = req.body;
  if (body === undefined || body === null) {
    return {};
  }
  if (typeof body !== "object" || Array.isArray(body)) {
    throw new RequestValidationError("request body must be a JSON object");
  }
  return body;
}

/**
 * A caller may ask for a shorter lifetime than the operator allows, never a
 * longer one: clamping up would let a request outlive the sweep that bounds it.
 */
function parseSessionTimeout(value, { name, ceiling }) {
  if (value === undefined) {
    return ceiling;
  }
  if (
    !Number.isInteger(value) ||
    value < MIN_SESSION_TIMEOUT_MS ||
    value > ceiling
  ) {
    throw new RequestValidationError(
      `${name} must be an integer between ${MIN_SESSION_TIMEOUT_MS} and ${ceiling}`,
    );
  }
  return value;
}

function parseSessionIdParam(req) {
  const raw = req.params.sessionId;
  if (typeof raw !== "string" || !SESSION_ID_PATTERN.test(raw)) {
    throw new SessionIdValidationError();
  }
  return raw;
}

function failureFor(error, req, res) {
  if (error instanceof SessionNotFoundError) {
    res.status(404).json(envelope(error, req));
    return true;
  }
  if (error instanceof SessionForbiddenError) {
    res.status(403).json(envelope(error, req));
    return true;
  }
  if (error instanceof SessionBusyError) {
    res.status(409).json(envelope(error, req));
    return true;
  }
  if (
    error instanceof SessionLimitExceededError ||
    error instanceof ContextLimitExceededError
  ) {
    res.status(503).json(envelope(error, req));
    return true;
  }
  if (
    error instanceof AgentIdValidationError ||
    error instanceof SessionIdValidationError ||
    error instanceof RequestValidationError
  ) {
    res.status(400).json(envelope(error, req));
    return true;
  }
  return false;
}

function envelope(error, req) {
  const status = error.status || 400;
  return {
    error:
      status === 403
        ? "forbidden"
        : status === 404
          ? "not_found"
          : status === 409
            ? "conflict"
            : status === 503
              ? "service_unavailable"
              : "invalid_request",
    code: error.code,
    message: error.message,
    request_id: req.id,
  };
}

function sessionPayload(session) {
  return {
    session_id: session.sessionId,
    state: session.state,
    status: session.state,
    created_at: new Date(session.createdAt).toISOString(),
    last_used_at: new Date(session.lastUsedAt).toISOString(),
    expires_at: new Date(session.expiresAt).toISOString(),
    idle_timeout_ms: session.idleTimeoutMs,
    max_age_ms: session.maxAgeMs,
    active_requests: session.activeRequests,
    closing_requested: session.closingRequested,
    current_url: session.currentUrl,
  };
}

const router = Router();

router.post("/session", async (req, res) => {
  try {
    const owner = parseAgentId(req.get(AGENT_ID_HEADER));
    const body = parseBody(req);
    const idleTimeoutMs = parseSessionTimeout(body.idle_timeout_ms, {
      name: "idle_timeout_ms",
      ceiling: config.sessionIdleTimeoutMs,
    });
    const maxAgeMs = parseSessionTimeout(body.max_age_ms, {
      name: "max_age_ms",
      ceiling: config.sessionMaxAgeMs,
    });

    const { session } = await createSession({
      owner,
      requestId: req.id,
      idleTimeoutMs,
      maxAgeMs,
    });

    res.status(201).json(sessionPayload(session));
  } catch (error) {
    if (failureFor(error, req, res)) {
      return;
    }
    req.log.error({ err: error }, "session_create_failed");
    res.status(500).json({
      error: "internal_error",
      message: "internal server error",
      request_id: req.id,
    });
  }
});

router.get("/session/:sessionId", async (req, res) => {
  try {
    const owner = parseAgentId(req.get(AGENT_ID_HEADER));
    const sessionId = parseSessionIdParam(req);
    const session = await getSession({ sessionId, owner });
    res.json(sessionPayload(session));
  } catch (error) {
    if (failureFor(error, req, res)) {
      return;
    }
    req.log.error({ err: error }, "session_status_failed");
    res.status(500).json({
      error: "internal_error",
      message: "internal server error",
      request_id: req.id,
    });
  }
});

router.delete("/session/:sessionId", async (req, res) => {
  try {
    const owner = parseAgentId(req.get(AGENT_ID_HEADER));
    const sessionId = parseSessionIdParam(req);
    const { deferred } = await closeSession({ sessionId, owner });
    res.json({
      session_id: sessionId,
      closed: !deferred,
      closing: deferred,
      request_id: req.id,
    });
  } catch (error) {
    if (failureFor(error, req, res)) {
      return;
    }
    req.log.error({ err: error }, "session_close_failed");
    res.status(500).json({
      error: "internal_error",
      message: "internal server error",
      request_id: req.id,
    });
  }
});

export default router;
