import { Router } from "express";

import { config } from "../config.js";
import {
  EgressProxyError,
  assertEgressEnforcement,
  describeEgressProxy,
} from "../lib/egress.js";
import {
  ContextLimitExceededError,
  SessionBusyError,
  SessionForbiddenError,
  SessionNotFoundError,
  checkoutSession,
  createIsolatedPage,
  sessionExists,
} from "../lib/browser.js";
import { truncateUtf8 } from "../lib/content.js";
import { installPageSecurity } from "../lib/page_security.js";
import {
  AGENT_ID_HEADER,
  AgentIdValidationError,
  SESSION_ID_HEADER,
  SessionIdValidationError,
  parseOptionalAgentId,
  parseSessionId,
} from "../lib/session_guard.js";
import { UrlValidationError, validateNavigationUrl } from "../lib/url_guard.js";

const WAIT_UNTIL_VALUES = new Set([
  "load",
  "domcontentloaded",
  "networkidle0",
  "networkidle2",
]);

class RequestValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RequestValidationError";
    this.code = "INVALID_REQUEST";
    this.status = 400;
  }
}

function parseWaitUntil(value) {
  if (value === undefined) {
    return "networkidle2";
  }
  if (typeof value !== "string" || !WAIT_UNTIL_VALUES.has(value)) {
    throw new RequestValidationError(
      "wait_until must be one of load, domcontentloaded, networkidle0, networkidle2",
    );
  }
  return value;
}

const MIN_NAVIGATION_TIMEOUT_MS = 1000;

function parseTimeout(value) {
  if (value === undefined) {
    return config.navigationTimeoutMs;
  }
  // The upper bound is the value config.js floors the session lease ceiling on,
  // so no request can outlive the lease that protects its browser context.
  if (
    !Number.isInteger(value) ||
    value < MIN_NAVIGATION_TIMEOUT_MS ||
    value > config.navigationTimeoutMaxMs
  ) {
    throw new RequestValidationError(
      `timeout_ms must be an integer between ${MIN_NAVIGATION_TIMEOUT_MS} and ${config.navigationTimeoutMaxMs}`,
    );
  }
  return value;
}

function isTimeoutError(error) {
  return error?.name === "TimeoutError" || /timeout/i.test(error?.message ?? "");
}

function isChromeErrorPage(url) {
  return typeof url === "string" && url.startsWith("chrome-error://");
}

/**
 * Counters for one navigation.
 *
 * A session page installs its request handlers once and keeps them for the
 * lifetime of the session, so its counters are cumulative. Snapshotting before
 * `goto()` and reporting the difference keeps each response about the navigation
 * it served, without mutating state another request could still observe.
 */
function snapshotSecurity(state) {
  return {
    redirectCount: state.redirectCount,
    blockedRequestCount: state.blockedRequestCount,
    blockedTargetCount: state.blockedTargetCount,
    navigationError: state.navigationError,
  };
}

const router = Router();

router.post("/navigate", async (req, res, next) => {
  let secured;
  let reusedSession = false;

  try {
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new RequestValidationError("request body must be a JSON object");
    }

    const target = await validateNavigationUrl(body.url);
    await assertEgressEnforcement();

    const waitUntil = parseWaitUntil(body.wait_until);
    const timeoutMs = parseTimeout(body.timeout_ms);
    // Validated before any browser context exists, so a rejected identity costs
    // nothing and cannot leave a half-built context behind.
    const sessionId = parseSessionId(req.get(SESSION_ID_HEADER));
    const agentId = parseOptionalAgentId(req.get(AGENT_ID_HEADER));

    // A3: an id the session registry issued reuses its own browser context.
    // Anything else — including a caller-invented identity the registry has
    // never seen — keeps the A2 behaviour of a fresh per-request context, so
    // ordinary navigation is unchanged and cannot attach to a session.
    reusedSession = sessionId !== null && sessionExists(sessionId);
    secured = reusedSession
      ? await checkoutSession({ sessionId, owner: agentId, requestId: req.id })
      : await createIsolatedPage({ requestId: req.id, sessionId });
    const page = secured.page;

    const security =
      secured.security ?? (await installPageSecurity(page, { requestId: req.id }));
    const baseline = snapshotSecurity(security);
    const startedAt = Date.now();

    try {
      const response = await page.goto(target.href, {
        waitUntil,
        timeout: timeoutMs,
      });
      const finalUrl = page.url();

      if (isChromeErrorPage(finalUrl)) {
        req.log.warn(
          {
            event: "navigation_egress_blocked",
            request_id: req.id,
            requested_host: target.host,
          },
          "navigation_egress_blocked",
        );
        throw buildNavigationBlockedError();
      }

      const title = await page.title();
      const rawContent = await page.content();
      const { content, truncated } = truncateUtf8(
        rawContent,
        config.maxContentBytes,
      );

      res.json({
        request_id: req.id,
        requested_url: target.href,
        final_url: finalUrl,
        status_code: response ? response.status() : null,
        title,
        content,
        content_truncated: truncated,
        elapsed_ms: Date.now() - startedAt,
        redirect_count: security.redirectCount - baseline.redirectCount,
        blocked_request_count:
          security.blockedRequestCount - baseline.blockedRequestCount,
        blocked_target_count:
          security.blockedTargetCount - baseline.blockedTargetCount,
        egress_proxy: describeEgressProxy(),
      });
    } catch (error) {
      if (error instanceof UrlValidationError) {
        throw error;
      }
      if (security.navigationError !== baseline.navigationError) {
        throw security.navigationError;
      }
      if (isChromeErrorPage(page.url())) {
        throw buildNavigationBlockedError();
      }
      throw error;
    }
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
      res.status(error.status || 503).json({
        error: "egress_unavailable",
        code: error.code,
        message: error.message,
        request_id: req.id,
      });
      return;
    }

    if (
      error instanceof SessionNotFoundError ||
      error instanceof SessionForbiddenError ||
      error instanceof SessionBusyError
    ) {
      req.log.warn(
        { event: "navigation_session_refused", code: error.code, request_id: req.id },
        "navigation_session_refused",
      );
      res
        .status(error.status)
        .json({
          error:
            error.status === 403
              ? "forbidden"
              : error.status === 404
                ? "not_found"
                : "conflict",
          code: error.code,
          message: error.message,
          request_id: req.id,
        });
      return;
    }

    if (
      error instanceof UrlValidationError ||
      error instanceof RequestValidationError ||
      error instanceof SessionIdValidationError ||
      error instanceof AgentIdValidationError
    ) {
      const status = error.status || 400;
      res.status(status).json({
        error: status === 403 ? "blocked" : "invalid_request",
        code: error.code,
        message: error.message,
        request_id: req.id,
      });
      return;
    }

    if (isTimeoutError(error)) {
      res.status(504).json({
        error: "navigation_timeout",
        code: "NAVIGATION_TIMEOUT",
        message: "browser navigation timed out",
        request_id: req.id,
      });
      return;
    }

    if (error instanceof ContextLimitExceededError) {
      res.status(503).json({
        error: "service_unavailable",
        code: error.code,
        message: error.message,
        request_id: req.id,
      });
      return;
    }

    next(error);
  } finally {
    if (secured) {
      if (reusedSession) {
        // The session keeps its context; only the lease is given back. A close
        // that arrived while this request held the session is applied here.
        secured.release();
      } else {
        await secured.close();
      }
    }
  }
});

function buildNavigationBlockedError() {
  return new UrlValidationError(
    "EGRESS_BLOCKED",
    "the navigation was blocked by the egress policy",
    403,
  );
}

export default router;
