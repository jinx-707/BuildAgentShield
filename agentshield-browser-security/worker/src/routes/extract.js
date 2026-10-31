import { Router } from "express";

import {
  ContextLimitExceededError,
  SessionBusyError,
  SessionForbiddenError,
  SessionNotFoundError,
  checkoutSession,
} from "../lib/browser.js";
import { extractPage } from "../lib/extractor.js";
import { installPageSecurity } from "../lib/page_security.js";
import {
  AGENT_ID_HEADER,
  AgentIdValidationError,
  SESSION_ID_HEADER,
  SessionIdValidationError,
  parseAgentId,
  parseSessionId,
} from "../lib/session_guard.js";

/**
 * B1 — extract bounded text from an owned persistent session.
 *
 * Extraction never navigates. It operates on the page already loaded into the
 * caller's session, which is why an owner identity and a live session are both
 * required: there is no request URL here to authorize independently.
 */

class RequestValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RequestValidationError";
    this.code = "INVALID_REQUEST";
    this.status = 400;
  }
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

const router = Router();

router.post("/extract", async (req, res) => {
  let secured;
  try {
    const body = req.body;
    if (
      body !== undefined &&
      body !== null &&
      (typeof body !== "object" || Array.isArray(body))
    ) {
      throw new RequestValidationError("request body must be a JSON object");
    }

    const sessionId = parseSessionId(req.get(SESSION_ID_HEADER));
    if (sessionId === null) {
      throw new RequestValidationError("session id is required for extraction");
    }
    const agentId = parseAgentId(req.get(AGENT_ID_HEADER));

    secured = await checkoutSession({
      sessionId,
      owner: agentId,
      requestId: req.id,
    });

    const security =
      secured.security ?? (await installPageSecurity(secured.page, { requestId: req.id }));
    void security;

    const extracted = await extractPage(secured.page);

    res.json({
      request_id: req.id,
      session_id: sessionId,
      ...extracted,
    });
  } catch (error) {
    if (
      error instanceof SessionNotFoundError ||
      error instanceof SessionForbiddenError ||
      error instanceof SessionBusyError
    ) {
      req.log.warn(
        { event: "extract_session_refused", code: error.code, request_id: req.id },
        "extract_session_refused",
      );
      res.status(error.status).json(envelope(error, req));
      return;
    }

    if (
      error instanceof SessionIdValidationError ||
      error instanceof AgentIdValidationError ||
      error instanceof RequestValidationError
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

    req.log.error({ err: error }, "extract_failed");
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
