/**
 * Session and owner identity guards.
 *
 * A2 makes the caller's session ID request metadata only: it is validated here,
 * stored on the browser context entry, and never selects a context on its own.
 * A3 adds the registry in `lib/browser.js`, and it keys that registry by the
 * server-generated session ID returned from `POST /v1/session` — never by a
 * caller-supplied identity. `x-agent-id` is the owner identity a session
 * operation is attributed to; it is checked against the registered owner before
 * any context is touched.
 */

// Deliberately the same shape as the request-ID pattern in app.js and the API's
// session_id field: a value that passes here is byte-identical to the value the
// API validated, so the two boundaries can never disagree about what is legal.
export const SESSION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export const SESSION_ID_HEADER = "x-agent-session";

export class SessionIdValidationError extends Error {
  constructor() {
    // Fixed message: the rejected value is caller-controlled and must not be
    // reflected back in an error body.
    super("session id is invalid");
    this.name = "SessionIdValidationError";
    this.code = "INVALID_SESSION_ID";
    this.status = 400;
  }
}

/**
 * Validate the inbound `x-agent-session` header.
 *
 * Returns the value unchanged, or null when the caller supplied no session
 * identity. Anything else — including an empty value, a duplicated header
 * (Express joins them with ", "), embedded newlines, or an over-long ID — is
 * rejected rather than sanitized, so an unrecognized identity cannot be
 * silently rewritten into something the API never sent.
 */
export function parseSessionId(rawValue) {
  if (rawValue === undefined || rawValue === null) {
    return null;
  }
  if (typeof rawValue !== "string" || !SESSION_ID_PATTERN.test(rawValue)) {
    throw new SessionIdValidationError();
  }
  return rawValue;
}

export const AGENT_ID_HEADER = "x-agent-id";

export class AgentIdValidationError extends Error {
  constructor(message) {
    // Fixed messages: nothing caller-supplied is echoed back.
    super(message);
    this.name = "AgentIdValidationError";
    this.code = "INVALID_AGENT_ID";
    this.status = 400;
  }
}

/**
 * Validate the owner identity a session operation must be attributed to.
 *
 * Session operations always require an owner (`x-agent-id`); ordinary
 * navigation may go without one, so the optional form is separate. The value is
 * the caller identity as presented by the control plane, which the worker trusts
 * to authenticate its callers — see README "Session ownership".
 */
export function parseAgentId(rawValue) {
  if (rawValue === undefined || rawValue === null || rawValue === "") {
    throw new AgentIdValidationError("agent id is required for session operations");
  }
  if (typeof rawValue !== "string" || !SESSION_ID_PATTERN.test(rawValue)) {
    throw new AgentIdValidationError("agent id is invalid");
  }
  return rawValue;
}

export function parseOptionalAgentId(rawValue) {
  if (rawValue === undefined || rawValue === null || rawValue === "") {
    return null;
  }
  if (typeof rawValue !== "string" || !SESSION_ID_PATTERN.test(rawValue)) {
    throw new AgentIdValidationError("agent id is invalid");
  }
  return rawValue;
}
