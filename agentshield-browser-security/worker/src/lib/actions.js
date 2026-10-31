import { config } from "../config.js";
import { truncateUtf8 } from "./content.js";
import { extractPage } from "./extractor.js";
import { logger } from "./logger.js";
import { UrlValidationError, validateNavigationUrl } from "./url_guard.js";

const ACTIONS = new Set(["click", "type", "scroll", "page_state", "submit_form"]);
const SELECTOR_MAX_LENGTH = 500;
const TARGET_INDEX_MAX = 999;
const NAVIGATION_SETTLE_MS = 1500;
const SUBMIT_NAVIGATION_SETTLE_MS = 5000;

export class ActionError extends Error {
  constructor(code, message, status = 400, details = null) {
    super(message);
    this.name = "ActionError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export class ActionTimeoutError extends Error {
  constructor() {
    super("browser action timed out");
    this.name = "ActionTimeoutError";
    this.code = "ACTION_TIMEOUT";
    this.status = 504;
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateSelector(selector) {
  if (typeof selector !== "string" || selector.trim() === "") {
    throw new ActionError("INVALID_TARGET", "target selector must be a non-empty string");
  }
  if (selector.length > SELECTOR_MAX_LENGTH) {
    throw new ActionError("INVALID_TARGET", "target selector is too long");
  }
  if (/[\u0000-\u001f\u007f]/.test(selector)) {
    throw new ActionError("INVALID_TARGET", "target selector contains control characters");
  }
  if (
    selector.includes(">>>") ||
    selector.startsWith("aria/") ||
    selector.startsWith("text/") ||
    selector.startsWith("xpath/") ||
    selector.startsWith("pierce/") ||
    selector.includes("::-p-")
  ) {
    throw new ActionError("INVALID_TARGET", "only plain CSS selectors are supported");
  }
}

function normalizeTarget(target) {
  if (!isObject(target)) {
    throw new ActionError("INVALID_TARGET", "target must be an object");
  }

  const hasSelector = target.selector !== undefined && target.selector !== null;
  const hasRole = target.role !== undefined && target.role !== null;

  if (hasSelector === hasRole) {
    throw new ActionError(
      "INVALID_TARGET",
      "target must contain either a selector or an accessible role",
    );
  }

  if (hasSelector) {
    validateSelector(target.selector);
    if (target.name !== undefined && target.name !== null) {
      throw new ActionError("INVALID_TARGET", "target name requires an accessible role");
    }
  }

  if (hasRole) {
    if (
      typeof target.role !== "string" ||
      !/^[a-z][a-z0-9-]{0,31}$/.test(target.role)
    ) {
      throw new ActionError("INVALID_TARGET", "target role is invalid");
    }
    if (
      target.name !== undefined &&
      target.name !== null &&
      (typeof target.name !== "string" ||
        target.name.trim() === "" ||
        target.name.length > 200)
    ) {
      throw new ActionError("INVALID_TARGET", "target name is invalid");
    }
  }

  if (target.index !== undefined && target.index !== null) {
    if (
      !Number.isInteger(target.index) ||
      target.index < 0 ||
      target.index > TARGET_INDEX_MAX
    ) {
      throw new ActionError("INVALID_TARGET", "target index is invalid");
    }
  }

  return {
    selector: hasSelector ? target.selector : null,
    role: hasRole ? target.role : null,
    name: hasRole && target.name ? target.name : null,
    index:
      target.index === undefined || target.index === null ? null : target.index,
  };
}

function describeElement(element) {
  const tag = element.tagName.toLowerCase();
  const type = (element.getAttribute("type") || "").toLowerCase();
  const role = (element.getAttribute("role") || "").trim().split(/\s+/)[0];

  function implicitRole() {
    if (tag === "button") return "button";
    if (tag === "a" && element.hasAttribute("href")) return "link";
    if (tag === "textarea") return "textbox";
    if (tag === "select") return element.multiple ? "listbox" : "combobox";
    if (tag === "form") return "form";
    if (tag === "img") return "img";
    if (tag === "nav") return "navigation";
    if (tag === "main") return "main";
    if (tag === "header") return "banner";
    if (tag === "footer") return "contentinfo";
    if (/^h[1-6]$/.test(tag)) return "heading";
    if (tag === "ul" || tag === "ol") return "list";
    if (tag === "li") return "listitem";
    if (tag === "table") return "table";
    if (tag === "tr") return "row";
    if (tag === "td" || tag === "th") return "cell";
    if (tag === "input") {
      if (["button", "submit", "reset"].includes(type)) return "button";
      if (type === "checkbox") return "checkbox";
      if (type === "radio") return "radio";
      if (type === "range") return "slider";
      if (type === "number") return "spinbutton";
      if (
        !type ||
        ["text", "search", "email", "tel", "url", "password"].includes(type)
      ) {
        return "textbox";
      }
    }
    return null;
  }

  function accessibleName() {
    const ariaLabel = element.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel.trim().slice(0, 200);

    const labelledBy = element.getAttribute("aria-labelledby");
    if (labelledBy) {
      const parts = [];
      for (const id of labelledBy.split(/\s+/)) {
        const node = document.getElementById(id);
        if (node) parts.push(node.textContent || "");
      }
      const joined = parts.join(" ").replace(/\s+/g, " ").trim();
      if (joined) return joined.slice(0, 200);
    }

    if (element.labels && element.labels.length > 0) {
      const joined = Array.from(element.labels)
        .map((label) => label.innerText || label.textContent || "")
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      if (joined) return joined.slice(0, 200);
    }

    if (tag === "input" && ["button", "submit", "reset"].includes(type)) {
      return String(element.value || "").trim().slice(0, 200);
    }
    if (tag === "img") {
      return String(element.getAttribute("alt") || "").trim().slice(0, 200);
    }

    const title = element.getAttribute("title");
    if (title) return title.trim().slice(0, 200);

    return String(element.innerText || element.textContent || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 200);
  }

  return {
    tag,
    role: role || implicitRole() || null,
    name: accessibleName(),
    type: type || null,
    id: element.id ? String(element.id).slice(0, 100) : null,
    download: element.hasAttribute("download"),
  };
}

function findByRole({ role, name }) {
  function implicitRole(element) {
    const tag = element.tagName.toLowerCase();
    const type = (element.getAttribute("type") || "").toLowerCase();
    if (tag === "button") return "button";
    if (tag === "a" && element.hasAttribute("href")) return "link";
    if (tag === "textarea") return "textbox";
    if (tag === "select") return element.multiple ? "listbox" : "combobox";
    if (tag === "form") return "form";
    if (tag === "img") return "img";
    if (tag === "nav") return "navigation";
    if (tag === "main") return "main";
    if (tag === "header") return "banner";
    if (tag === "footer") return "contentinfo";
    if (/^h[1-6]$/.test(tag)) return "heading";
    if (tag === "ul" || tag === "ol") return "list";
    if (tag === "li") return "listitem";
    if (tag === "table") return "table";
    if (tag === "tr") return "row";
    if (tag === "td" || tag === "th") return "cell";
    if (tag === "input") {
      if (["button", "submit", "reset"].includes(type)) return "button";
      if (type === "checkbox") return "checkbox";
      if (type === "radio") return "radio";
      if (type === "range") return "slider";
      if (type === "number") return "spinbutton";
      if (
        !type ||
        ["text", "search", "email", "tel", "url", "password"].includes(type)
      ) {
        return "textbox";
      }
    }
    return null;
  }

  function accessibleName(element) {
    const ariaLabel = element.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel.trim();
    const labelledBy = element.getAttribute("aria-labelledby");
    if (labelledBy) {
      const parts = [];
      for (const id of labelledBy.split(/\s+/)) {
        const node = document.getElementById(id);
        if (node) parts.push(node.textContent || "");
      }
      const joined = parts.join(" ").replace(/\s+/g, " ").trim();
      if (joined) return joined;
    }
    if (element.labels && element.labels.length > 0) {
      const joined = Array.from(element.labels)
        .map((label) => label.innerText || label.textContent || "")
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      if (joined) return joined;
    }
    if (element.tagName.toLowerCase() === "input") {
      const type = (element.getAttribute("type") || "").toLowerCase();
      if (["button", "submit", "reset"].includes(type)) {
        return String(element.value || "").trim();
      }
    }
    if (element.tagName.toLowerCase() === "img") {
      return String(element.getAttribute("alt") || "").trim();
    }
    const title = element.getAttribute("title");
    if (title) return title.trim();
    return String(element.innerText || element.textContent || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  const candidates = document.querySelectorAll(
    "[role],button,a[href],input,textarea,select,form,img,nav,main,header,footer,h1,h2,h3,h4,h5,h6,ul,ol,li,table,tr,td,th",
  );
  const wantedName = typeof name === "string" ? name.trim().toLowerCase() : null;
  const matches = [];

  for (const element of candidates) {
    const explicit = (element.getAttribute("role") || "").trim().split(/\s+/)[0];
    const actualRole = explicit || implicitRole(element);
    if (actualRole !== role) continue;
    if (wantedName !== null && accessibleName(element).toLowerCase() !== wantedName) {
      continue;
    }
    if (matches.length < 101) {
      matches.push(element);
    }
  }

  return matches;
}

function elementState(element) {
  const tag = element.tagName.toLowerCase();
  const type = (element.getAttribute("type") || "").toLowerCase();
  const style = window.getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  const visible =
    element.isConnected &&
    !element.hidden &&
    style.display !== "none" &&
    style.visibility !== "hidden" &&
    style.visibility !== "collapse" &&
    Number(style.opacity) !== 0 &&
    style.contentVisibility !== "hidden" &&
    rect.width > 0 &&
    rect.height > 0 &&
    element.getClientRects().length > 0;
  const inert = Boolean(element.closest("[inert]"));
  const disabled =
    Boolean(element.disabled) ||
    element.getAttribute("aria-disabled") === "true" ||
    inert;
  const textInputTypes = new Set([
    "text",
    "search",
    "email",
    "url",
    "tel",
    "password",
    "number",
  ]);
  const editable =
    tag === "textarea" ||
    (tag === "input" && textInputTypes.has(type || "text"));
  const submitsForm =
    Boolean(element.form) &&
    ((tag === "button" && (type === "" || type === "submit")) ||
      (tag === "input" && (type === "submit" || type === "image")));
  const maxLength = typeof element.maxLength === "number" ? element.maxLength : -1;
  const valueLength =
    typeof element.value === "string" ? element.value.length : 0;

  return {
    tag,
    type: type || null,
    visible,
    disabled,
    readOnly: Boolean(element.readOnly),
    editable,
    submitsForm,
    pointerEvents: style.pointerEvents,
    maxLength,
    valueLength,
  };
}

function setInputValue(element, { text, clear }) {
  const proto =
    element.tagName.toLowerCase() === "textarea"
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
  const next = (clear ? "" : String(element.value || "")) + text;
  if (descriptor && descriptor.set) {
    descriptor.set.call(element, next);
  } else {
    element.value = next;
  }
  element.focus();
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
}

function scrollWindow({ dx, dy }) {
  window.scrollBy(dx, dy);
  const root = document.documentElement;
  const body = document.body;
  return {
    x: Math.round(window.scrollX),
    y: Math.round(window.scrollY),
    scroll_width: Math.max(root ? root.scrollWidth : 0, body ? body.scrollWidth : 0),
    scroll_height: Math.max(root ? root.scrollHeight : 0, body ? body.scrollHeight : 0),
    client_width: window.innerWidth,
    client_height: window.innerHeight,
  };
}

function scrollElement(element, { dx, dy }) {
  element.scrollLeft += dx;
  element.scrollTop += dy;
  return {
    x: Math.round(element.scrollLeft),
    y: Math.round(element.scrollTop),
    scroll_width: element.scrollWidth,
    scroll_height: element.scrollHeight,
    client_width: element.clientWidth,
    client_height: element.clientHeight,
  };
}

function readScrollState() {
  const root = document.documentElement;
  const body = document.body;
  return {
    x: Math.round(window.scrollX),
    y: Math.round(window.scrollY),
    scroll_width: Math.max(root ? root.scrollWidth : 0, body ? body.scrollWidth : 0),
    scroll_height: Math.max(root ? root.scrollHeight : 0, body ? body.scrollHeight : 0),
    client_width: window.innerWidth,
    client_height: window.innerHeight,
  };
}

function inspectForm(form) {
  const sensitive = [];
  let fieldCount = 0;
  let hasFileInput = false;

  for (const field of Array.from(form.elements)) {
    if (!field || !field.tagName) continue;
    const tag = field.tagName.toLowerCase();
    if (!["input", "textarea", "select"].includes(tag)) continue;
    fieldCount += 1;
    const type = (field.type || tag).toLowerCase();
    if (type === "file") hasFileInput = true;
    const autocomplete = (field.getAttribute("autocomplete") || "").toLowerCase();
    const rawName = field.getAttribute("name") || field.id || "";
    const name = String(rawName).slice(0, 64);
    const haystack = `${name} ${field.id || ""} ${autocomplete}`.toLowerCase();
    const sensitiveField =
      type === "password" ||
      /(?:current-password|new-password|cc-number|cc-csc|cc-exp|one-time-code|webauthn)/.test(
        autocomplete,
      ) ||
      /(?:pass(?:word|wd)?|secret|token|api[-_]?key|credit|card|cvv|cvc|ssn|social|iban|routing|account[-_]?number|otp|pin)/.test(
        haystack,
      );
    if (sensitiveField) {
      sensitive.push({
        name: name || type,
        type,
        autocomplete: autocomplete || null,
      });
    }
  }

  let destination = null;
  try {
    destination = new URL(form.action || location.href, location.href).href;
  } catch {
    destination = null;
  }

  const intentParts = [
    form.id,
    form.getAttribute("name"),
    form.getAttribute("action"),
    form.getAttribute("aria-label"),
  ];
  for (const control of Array.from(
    form.querySelectorAll('button, input[type="submit"], input[type="button"]'),
  )) {
    intentParts.push(
      control.id,
      control.getAttribute("name"),
      control.getAttribute("value"),
      control.getAttribute("aria-label"),
      control.innerText,
    );
  }
  const intent = intentParts.filter(Boolean).join(" ").toLowerCase();
  const destructive = /(?:\b(?:delete|remove|destroy|deactivate|revoke|unsubscribe)\b|close[-_ ]?account|cancel[-_ ]?account)/.test(
    intent,
  );
  const payment = /\b(?:pay|payment|checkout|purchase|buy|refund|billing|invoice)\b/.test(
    intent,
  );

  return {
    action: destination,
    method: (form.getAttribute("method") || "get").toLowerCase(),
    target: (form.getAttribute("target") || "").toLowerCase(),
    sensitive_fields: sensitive.slice(0, 20),
    sensitive_field_count: sensitive.length,
    field_count: fieldCount,
    has_file_input: hasFileInput,
    destructive,
    payment,
  };
}

function isChromeErrorPage(url) {
  return typeof url === "string" && url.startsWith("chrome-error://");
}

function snapshotSecurity(state) {
  return {
    redirectCount: state.redirectCount,
    blockedRequestCount: state.blockedRequestCount,
    blockedTargetCount: state.blockedTargetCount,
    navigationError: state.navigationError,
  };
}

function assertNavigationAllowed(page, security, baseline) {
  if (security.navigationError !== baseline.navigationError) {
    throw security.navigationError;
  }
  if (isChromeErrorPage(page.url())) {
    throw new UrlValidationError(
      "EGRESS_BLOCKED",
      "the navigation was blocked by the egress policy",
      403,
    );
  }
}

async function resolveTarget(page, rawTarget, options) {
  const target = normalizeTarget(rawTarget);
  let handles = [];
  let arrayHandle = null;
  let selected = null;

  try {
    if (target.selector) {
      try {
        handles = await page.$$(target.selector);
      } catch {
        throw new ActionError("INVALID_TARGET", "target selector is invalid");
      }
    } else {
      arrayHandle = await page.evaluateHandle(findByRole, {
        role: target.role,
        name: target.name,
      });
      const count = await arrayHandle.evaluate((items) => items.length);
      if (count === 0) {
        throw new ActionError("TARGET_NOT_FOUND", "target was not found", 404);
      }
      if (count > 101) {
        throw new ActionError(
          "TARGET_AMBIGUOUS",
          "target matches too many elements; refine the target",
          409,
          { match_count: count },
        );
      }
      if (count > 1 && target.index === null) {
        throw new ActionError(
          "TARGET_AMBIGUOUS",
          "target matches multiple elements; supply an index",
          409,
          { match_count: count },
        );
      }
      if (target.index !== null && target.index >= count) {
        throw new ActionError(
          "TARGET_INDEX_OUT_OF_RANGE",
          "target index is outside the number of matches",
          400,
          { match_count: count },
        );
      }
      selected = await arrayHandle.evaluateHandle(
        (items, index) => items[index] ?? null,
        target.index ?? 0,
      );
      const element = selected.asElement();
      if (!element) {
        throw new ActionError("TARGET_NOT_FOUND", "target was not found", 404);
      }
      try {
        const summary = await element.evaluate(describeElement);
        const state = await element.evaluate(elementState);
        validateElementState(state, options);
        return { handle: element, summary, state, count };
      } catch (error) {
        await element.dispose().catch(() => {});
        throw error;
      }
    }

    if (handles.length === 0) {
      throw new ActionError("TARGET_NOT_FOUND", "target was not found", 404);
    }
    if (handles.length > 1 && target.index === null) {
      throw new ActionError(
        "TARGET_AMBIGUOUS",
        "target matches multiple elements; supply an index",
        409,
        { match_count: handles.length },
      );
    }
    const index = target.index ?? 0;
    if (index >= handles.length) {
      throw new ActionError(
        "TARGET_INDEX_OUT_OF_RANGE",
        "target index is outside the number of matches",
        400,
        { match_count: handles.length },
      );
    }
    selected = handles[index];
    const count = handles.length;
    for (let i = 0; i < handles.length; i += 1) {
      if (i !== index) await handles[i].dispose();
    }
    handles = [];
    try {
      const summary = await selected.evaluate(describeElement);
      const state = await selected.evaluate(elementState);
      validateElementState(state, options);
      return { handle: selected, summary, state, count };
    } catch (error) {
      await selected.dispose().catch(() => {});
      throw error;
    }
  } finally {
    if (arrayHandle) await arrayHandle.dispose().catch(() => {});
    for (const handle of handles) await handle.dispose().catch(() => {});
  }
}

function validateElementState(state, options) {
  if (!state.visible && options.requireVisible !== false) {
    throw new ActionError("TARGET_NOT_VISIBLE", "target is not visible", 400);
  }
  if (state.disabled && options.requireEnabled !== false) {
    throw new ActionError("TARGET_DISABLED", "target is disabled", 400);
  }
  if (options.requireEditable && (!state.editable || state.readOnly)) {
    throw new ActionError(
      state.readOnly ? "TARGET_READ_ONLY" : "TARGET_NOT_EDITABLE",
      state.readOnly
        ? "target is read-only"
        : "target is not an editable text field",
      400,
    );
  }
  if (options.requireForm && state.tag !== "form") {
    throw new ActionError("TARGET_NOT_FORM", "target is not a form", 400);
  }
}

async function buildResult({
  page,
  security,
  baseline,
  requestId,
  sessionId,
  actionName,
  target,
  startedAt,
  scroll = null,
  form = null,
  withholdText = false,
  typedText = null,
}) {
  const finalUrl = page.url();
  const title = await page.title().catch(() => "");
  let text = "";
  let textTruncated = false;
  let hiddenContentExcluded = false;
  let hiddenElementCount = 0;
  const warnings = ["UNTRUSTED_PAGE_CONTENT"];

  if (!withholdText) {
    const extracted = await extractPage(page);
    const bounded = truncateUtf8(extracted.text, config.actionMaxTextBytes);
    text = bounded.content;
    textTruncated = bounded.truncated || extracted.text_truncated;
    hiddenContentExcluded = extracted.hidden_content_excluded;
    hiddenElementCount = extracted.hidden_element_count;

    if (typeof typedText === "string" && typedText.length > 0) {
      if (typedText.length >= 4) {
        text = text.split(typedText).join("[REDACTED]");
        warnings.push("TYPED_VALUE_REDACTED");
      } else {
        text = "";
        textTruncated = true;
        warnings.push("TYPED_VALUE_TEXT_WITHHELD");
      }
    }
  }

  if (withholdText) warnings.push("SENSITIVE_FORM_TEXT_WITHHELD");
  if (textTruncated) warnings.push("TEXT_TRUNCATED");
  if (hiddenContentExcluded) warnings.push("HIDDEN_CONTENT_EXCLUDED");

  return {
    request_id: requestId,
    session_id: sessionId,
    action: actionName,
    success: true,
    target: target ?? null,
    final_url: finalUrl,
    title,
    text,
    text_truncated: textTruncated,
    scroll,
    form,
    warnings,
    hidden_content_excluded: hiddenContentExcluded,
    hidden_element_count: hiddenElementCount,
    elapsed_ms: Date.now() - startedAt,
    redirect_count: security.redirectCount - baseline.redirectCount,
    blocked_request_count: security.blockedRequestCount - baseline.blockedRequestCount,
    blocked_target_count: security.blockedTargetCount - baseline.blockedTargetCount,
  };
}

async function runClick({ page, security, action, requestId, sessionId, timeoutMs }) {
  const startedAt = Date.now();
  const baseline = snapshotSecurity(security);
  const resolved = await resolveTarget(page, action.target, {
    requireVisible: true,
    requireEnabled: true,
  });

  try {
    if (resolved.state.tag === "input" && resolved.state.type === "file") {
      throw new ActionError(
        "FILE_INPUT_NOT_ALLOWED",
        "clicking a file input is not permitted",
        403,
      );
    }
    if (resolved.summary.download) {
      throw new ActionError(
        "DOWNLOAD_NOT_ALLOWED",
        "clicking a download link is not permitted",
        403,
      );
    }
    if (resolved.state.submitsForm) {
      throw new ActionError(
        "FORM_SUBMIT_REQUIRES_GUARDED_OPERATION",
        "clicking a submit control is not permitted; use the guarded submit_form action",
        403,
      );
    }

    const beforeUrl = page.url();
    const navigation = page
      .waitForNavigation({
        waitUntil: "load",
        timeout: Math.min(timeoutMs, NAVIGATION_SETTLE_MS),
      })
      .catch(() => null);

    await resolved.handle.click({ timeout: timeoutMs });
    await navigation;
    assertNavigationAllowed(page, security, baseline);

    const result = await buildResult({
      page,
      security,
      baseline,
      requestId,
      sessionId,
      actionName: "click",
      target: resolved.summary,
      startedAt,
    });
    if (page.url() !== beforeUrl) {
      result.warnings.push("NAVIGATION_OCCURRED");
    }
    return result;
  } finally {
    await resolved.handle.dispose().catch(() => {});
  }
}

async function runType({ page, security, action, requestId, sessionId, timeoutMs }) {
  const startedAt = Date.now();
  const baseline = snapshotSecurity(security);
  const text = action.text;

  if (typeof text !== "string" || text.length === 0) {
    throw new ActionError("INVALID_TEXT", "text must be a non-empty string");
  }
  if (Buffer.byteLength(text, "utf8") > config.actionMaxTypeBytes) {
    throw new ActionError(
      "INPUT_LENGTH_EXCEEDED",
      `text exceeds the maximum of ${config.actionMaxTypeBytes} bytes`,
    );
  }

  const resolved = await resolveTarget(page, action.target, {
    requireVisible: true,
    requireEnabled: true,
    requireEditable: true,
  });

  try {
    const clear = action.clear !== false;
    if (resolved.state.maxLength >= 0) {
      const resultingLength = clear
        ? text.length
        : resolved.state.valueLength + text.length;
      if (resultingLength > resolved.state.maxLength) {
        throw new ActionError(
          "INPUT_LENGTH_EXCEEDED",
          "text exceeds the target field maxlength",
          400,
          { max_length: resolved.state.maxLength },
        );
      }
    }

    await resolved.handle.evaluate(setInputValue, { text, clear });

    return await buildResult({
      page,
      security,
      baseline,
      requestId,
      sessionId,
      actionName: "type",
      target: resolved.summary,
      startedAt,
      typedText: text,
    });
  } finally {
    await resolved.handle.dispose().catch(() => {});
  }
}

async function runScroll({ page, security, action, requestId, sessionId }) {
  const startedAt = Date.now();
  const baseline = snapshotSecurity(security);
  const amount = action.amount;
  const direction = action.direction;

  if (!Number.isInteger(amount) || amount < 1 || amount > config.actionMaxScrollPx) {
    throw new ActionError(
      "INVALID_SCROLL_AMOUNT",
      `amount must be an integer between 1 and ${config.actionMaxScrollPx}`,
    );
  }
  if (!["up", "down", "left", "right"].includes(direction)) {
    throw new ActionError("INVALID_SCROLL_DIRECTION", "direction is invalid");
  }

  const dx = direction === "left" ? -amount : direction === "right" ? amount : 0;
  const dy = direction === "up" ? -amount : direction === "down" ? amount : 0;
  let resolved = null;

  try {
    let scroll;
    let target = null;
    if (action.target !== undefined && action.target !== null) {
      resolved = await resolveTarget(page, action.target, {
        requireVisible: true,
        requireEnabled: false,
      });
      scroll = await resolved.handle.evaluate(scrollElement, { dx, dy });
      target = resolved.summary;
    } else {
      scroll = await page.evaluate(scrollWindow, { dx, dy });
    }

    return await buildResult({
      page,
      security,
      baseline,
      requestId,
      sessionId,
      actionName: "scroll",
      target,
      startedAt,
      scroll,
    });
  } finally {
    if (resolved) await resolved.handle.dispose().catch(() => {});
  }
}

async function runPageState({ page, security, requestId, sessionId }) {
  const startedAt = Date.now();
  const baseline = snapshotSecurity(security);
  const scroll = await page.evaluate(readScrollState);
  return buildResult({
    page,
    security,
    baseline,
    requestId,
    sessionId,
    actionName: "page_state",
    target: null,
    startedAt,
    scroll,
  });
}

async function runSubmitForm({ page, security, action, requestId, sessionId, timeoutMs }) {
  const startedAt = Date.now();
  const baseline = snapshotSecurity(security);
  const resolved = await resolveTarget(page, action.target, {
    requireVisible: true,
    requireEnabled: false,
    requireForm: true,
  });

  try {
    const form = await resolved.handle.evaluate(inspectForm);
    if (!form.action) {
      throw new ActionError("FORM_DESTINATION_INVALID", "form destination is invalid");
    }
    if (!["get", "post"].includes(form.method)) {
      throw new ActionError(
        "FORM_METHOD_NOT_ALLOWED",
        "only GET and POST form submissions are permitted",
        403,
      );
    }
    if (form.target && form.target !== "_self") {
      throw new ActionError(
        "FORM_TARGET_NOT_ALLOWED",
        "form submission targets other than _self are not permitted",
        403,
      );
    }

    const destination = new URL(form.action);
    await validateNavigationUrl(destination.href);

    let pageOrigin = null;
    try {
      pageOrigin = new URL(page.url()).origin;
    } catch {
      pageOrigin = null;
    }
    const crossOrigin = pageOrigin !== destination.origin;
    const sensitiveFieldCount = form.sensitive_field_count;
    const reasons = [];
    if (sensitiveFieldCount > 0) reasons.push("sensitive_fields");
    if (crossOrigin) reasons.push("cross_origin");
    if (form.destructive) reasons.push("destructive_action");
    if (form.payment) reasons.push("payment_action");
    const confirmed = action.confirm === true;

    if (reasons.length > 0 && !confirmed) {
      throw new ActionError(
        "FORM_CONFIRMATION_REQUIRED",
        "explicit confirmation is required for this form submission",
        409,
        {
          confirmation_required: true,
          reasons,
          destination_origin: destination.origin,
          cross_origin: crossOrigin,
          sensitive_field_count: sensitiveFieldCount,
          sensitive_fields: form.sensitive_fields.map((field) => field.name),
        },
      );
    }

    logger.info(
      {
        event: "browser_form_submit",
        request_id: requestId,
        destination_origin: destination.origin,
        cross_origin: crossOrigin,
        method: form.method,
        sensitive_field_count: sensitiveFieldCount,
        confirmed,
      },
      "browser_form_submit",
    );

    const navigation = page
      .waitForNavigation({
        waitUntil: "load",
        timeout: Math.min(timeoutMs + 1000, SUBMIT_NAVIGATION_SETTLE_MS),
      })
      .catch(() => null);

    await resolved.handle.evaluate((element) => {
      HTMLFormElement.prototype.submit.call(element);
    });
    await navigation;
    assertNavigationAllowed(page, security, baseline);

    const formSummary = {
      method: form.method,
      destination_origin: destination.origin,
      cross_origin: crossOrigin,
      confirmed,
      confirmation_required: reasons.length > 0,
      sensitive_field_count: sensitiveFieldCount,
      sensitive_fields: form.sensitive_fields.map((field) => field.name),
      field_count: form.field_count,
      has_file_input: form.has_file_input,
      destructive: form.destructive,
      payment: form.payment,
    };

    const result = await buildResult({
      page,
      security,
      baseline,
      requestId,
      sessionId,
      actionName: "submit_form",
      target: resolved.summary,
      startedAt,
      form: formSummary,
      withholdText: sensitiveFieldCount > 0,
    });
    result.warnings.push("NAVIGATION_OCCURRED");
    if (crossOrigin) result.warnings.push("CROSS_ORIGIN_FORM_SUBMISSION");
    return result;
  } finally {
    await resolved.handle.dispose().catch(() => {});
  }
}

export async function runAction({
  page,
  security,
  action,
  requestId,
  sessionId,
  timeoutMs = config.actionTimeoutMs,
}) {
  if (!isObject(action) || typeof action.action !== "string") {
    throw new ActionError("INVALID_REQUEST", "action must be a JSON object with an action field");
  }
  if (!ACTIONS.has(action.action)) {
    throw new ActionError("INVALID_ACTION", "unsupported browser action");
  }

  // Accept the flat selector/distance aliases used by the early API shape.
  // Both forms end up in the same validated target resolver.
  let normalized = action;
  if (
    normalized.target === undefined &&
    typeof normalized.selector === "string"
  ) {
    normalized = {
      ...normalized,
      target: {
        selector: normalized.selector,
        ...(normalized.index !== undefined && normalized.index !== null
          ? { index: normalized.index }
          : {}),
      },
    };
  }
  if (
    normalized.amount === undefined &&
    normalized.distance !== undefined
  ) {
    normalized = { ...normalized, amount: normalized.distance };
  }

  switch (normalized.action) {
    case "click":
      return runClick({ page, security, action: normalized, requestId, sessionId, timeoutMs });
    case "type":
      return runType({ page, security, action: normalized, requestId, sessionId, timeoutMs });
    case "scroll":
      return runScroll({ page, security, action: normalized, requestId, sessionId });
    case "page_state":
      return runPageState({ page, security, requestId, sessionId });
    case "submit_form":
      return runSubmitForm({ page, security, action: normalized, requestId, sessionId, timeoutMs });
    default:
      throw new ActionError("INVALID_ACTION", "unsupported browser action");
  }
}
