import { config } from "../config.js";
import { logger } from "./logger.js";
import { UrlValidationError, validateNavigationUrl } from "./url_guard.js";

const NETWORK_SCHEMES = /^https?:\/\//i;
// Inline schemes remain usable for subresources (images, fonts, downloads),
// but a navigation to them would replace the controlled document with
// caller-authored markup. Only browser-generated about:blank/about:srcdoc
// documents are kept as non-network navigations.
const ALLOWED_NON_NETWORK_NAVIGATION = /^about:(blank|srcdoc)(?:[?#].*)?$/i;

function buildRedirectError(code, message) {
  return new UrlValidationError(code, message, 403);
}

function inspectRedirectChain(request) {
  const chain = request.redirectChain();
  const currentUrl = request.url();

  if (chain.length > config.maxRedirects) {
    throw buildRedirectError(
      "REDIRECT_LIMIT_EXCEEDED",
      "the navigation exceeded the redirect limit",
    );
  }

  if (chain.length === 0) {
    return;
  }

  const previous = new URL(chain[chain.length - 1].url());
  const current = new URL(currentUrl);

  if (
    config.blockHttpsDowngrade &&
    previous.protocol === "https:" &&
    current.protocol === "http:"
  ) {
    throw buildRedirectError(
      "HTTPS_DOWNGRADE_BLOCKED",
      "HTTPS to HTTP redirects are not permitted",
    );
  }

  if (chain.some((entry) => entry.url() === currentUrl)) {
    throw buildRedirectError(
      "REDIRECT_LOOP_DETECTED",
      "the navigation redirect chain contains a loop",
    );
  }
}

async function handleRequest(page, request, state) {
  const url = request.url();
  const isNavigation = request.isNavigationRequest();
  let isMainFrameNavigation = false;

  if (isNavigation) {
    try {
      isMainFrameNavigation = request.frame() === page.mainFrame();
    } catch {
      isMainFrameNavigation = false;
    }
  }

  if (!NETWORK_SCHEMES.test(url)) {
    if (isNavigation && !ALLOWED_NON_NETWORK_NAVIGATION.test(url)) {
      state.blockedRequestCount += 1;
      const error = buildRedirectError(
        "URL_SCHEME_NOT_ALLOWED",
        "navigation is permitted only to http, https, about:blank, or about:srcdoc",
      );
      if (isMainFrameNavigation) {
        state.navigationError = error;
      }
      await request.abort("blockedbyclient").catch(() => {});
      return;
    }
    await request.continue().catch(() => {});
    return;
  }

  try {
    const chain = request.redirectChain();
    state.redirectCount = Math.max(state.redirectCount, chain.length);
    inspectRedirectChain(request);
    await validateNavigationUrl(url);
    await request.continue();
  } catch (error) {
    state.blockedRequestCount += 1;

    if (isMainFrameNavigation) {
      if (request.redirectChain().length > 0 && error.code !== "REDIRECT_LIMIT_EXCEEDED" && error.code !== "REDIRECT_LOOP_DETECTED" && error.code !== "HTTPS_DOWNGRADE_BLOCKED") {
        state.navigationError = buildRedirectError(
          "REDIRECT_DESTINATION_BLOCKED",
          "the redirect destination is not permitted by policy",
        );
      } else {
        state.navigationError =
          error instanceof UrlValidationError
            ? error
            : buildRedirectError(
                "REDIRECT_DESTINATION_BLOCKED",
                "the redirect destination is not permitted by policy",
              );
      }
    }

    await request.abort("blockedbyclient").catch(() => {});
  }
}

function browserHardeningScript() {
  const deny = function () {
    return null;
  };

  // A blob: navigation is same-origin and does not generate a network request,
  // so request interception alone cannot stop it. Refuse document-typed blob
  // creation before any page script runs; non-document blobs (downloads, media)
  // remain available.
  const nativeCreateObjectURL = URL.createObjectURL.bind(URL);
  const documentBlobType = /^(text\/html|application\/xhtml\+xml|image\/svg\+xml)(?:[;\s]|$)/i;
  const guardedCreateObjectURL = function (blob) {
    const type = blob && typeof blob.type === "string" ? blob.type : "";
    if (documentBlobType.test(type)) {
      throw new DOMException(
        "Document blobs are disabled by policy",
        "SecurityError",
      );
    }
    return nativeCreateObjectURL(blob);
  };
  try {
    Object.defineProperty(URL, "createObjectURL", {
      value: guardedCreateObjectURL,
      writable: false,
      configurable: false,
    });
  } catch {
    URL.createObjectURL = guardedCreateObjectURL;
  }

  try {
    Object.defineProperty(window, "open", {
      value: deny,
      writable: false,
      configurable: false,
    });
  } catch {
    window.open = deny;
  }

  const websocketDeny = function WebSocket() {
    throw new DOMException(
      "WebSocket connections are disabled by policy",
      "SecurityError",
    );
  };

  for (const name of ["WebSocket", "MozWebSocket"]) {
    try {
      Object.defineProperty(window, name, {
        value: websocketDeny,
        writable: false,
        configurable: false,
      });
    } catch {
      window[name] = websocketDeny;
    }
  }

  for (const name of [
    "RTCPeerConnection",
    "webkitRTCPeerConnection",
    "RTCDataChannel",
    "webkitRTCDataChannel",
    "RTCSessionDescription",
    "webkitRTCSessionDescription",
    "RTCIceCandidate",
    "webkitRTCIceCandidate",
  ]) {
    try {
      delete window[name];
      Object.defineProperty(window, name, {
        value: undefined,
        writable: false,
        configurable: false,
      });
    } catch {
      // Ignore non-configurable bindings.
    }
  }

  try {
    Object.defineProperty(navigator, "mediaDevices", {
      value: undefined,
      configurable: false,
    });
  } catch {
    // Ignore non-configurable bindings.
  }

  for (const name of [
    "getUserMedia",
    "webkitGetUserMedia",
    "mozGetUserMedia",
  ]) {
    try {
      Object.defineProperty(navigator, name, {
        value: undefined,
        configurable: false,
      });
    } catch {
      // Ignore non-configurable bindings.
    }
  }

  try {
    Object.defineProperty(navigator, "serviceWorker", {
      value: undefined,
      configurable: false,
    });
  } catch {
    // Ignore non-configurable bindings.
  }

  try {
    Object.defineProperty(window, "EventSource", {
      value: undefined,
      configurable: false,
    });
  } catch {
    // Ignore non-configurable bindings.
  }

  // D1: form submission is an explicit, guarded operation. A page-triggered
  // submit event (including one caused by clicking a submit control or by
  // requestSubmit()) is cancelled here. The guarded worker operation validates
  // the destination first and then calls the native form.submit() method,
  // which intentionally bypasses this event listener; request interception
  // still validates the resulting navigation.
  const blockSubmit = function (event) {
    if (event.target && event.target.tagName === "FORM") {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  };

  document.addEventListener("submit", blockSubmit, true);

  const PRERENDER_RELS = new Set([
    "prerender",
    "prefetch",
    "preload",
    "preconnect",
    "dns-prefetch",
    "modulepreload",
  ]);

  const removeSpeculativeResources = function (root) {
    if (!root || !root.querySelectorAll) {
      return;
    }

    for (const link of root.querySelectorAll("link[rel]")) {
      const rels = String(link.getAttribute("rel") || "")
        .toLowerCase()
        .split(/\s+/);
      if (rels.some((rel) => PRERENDER_RELS.has(rel))) {
        link.remove();
      }
    }

    for (const script of root.querySelectorAll(
      'script[type="speculationrules"]',
    )) {
      script.remove();
    }
  };

  if (document.documentElement) {
    removeSpeculativeResources(document);
  }

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          removeSpeculativeResources(node);
        }
      }
    }
  });

  const start = () => observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });

  if (document.documentElement) {
    start();
  } else {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  }
}

async function installBrowserHardening(page) {
  await page.evaluateOnNewDocument(browserHardeningScript);

  try {
    const cdp = await page.createCDPSession();
    await cdp.send("Network.enable");
    await cdp.send("Network.setCacheDisabled", { cacheDisabled: true });
    await cdp.send("Network.setBypassServiceWorker", { bypass: true });
  } catch (error) {
    logger.debug({ err: error }, "browser_hardening_cdp_failed");
  }

  page.on("dialog", (dialog) => {
    void dialog.dismiss().catch(() => {});
  });
}

async function validateBrowserTargetUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.trim() === "") {
    throw new UrlValidationError("INVALID_URL", "target URL is missing");
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UrlValidationError("INVALID_URL", "target URL is invalid");
  }

  if (parsed.protocol === "ws:") {
    parsed.protocol = "http:";
  } else if (parsed.protocol === "wss:") {
    parsed.protocol = "https:";
  }

  await validateNavigationUrl(parsed.href);
}

export async function installPageSecurity(page, { requestId } = {}) {
  const state = {
    blockedRequestCount: 0,
    blockedTargetCount: 0,
    redirectCount: 0,
    navigationError: null,
  };

  await installBrowserHardening(page);

  await page.setRequestInterception(true);
  page.on("request", (request) => {
    void handleRequest(page, request, state);
  });

  page.on("popup", async (popup) => {
    state.blockedRequestCount += 1;
    state.blockedTargetCount += 1;
    try {
      await validateBrowserTargetUrl(popup.url());
    } catch {
      logger.warn(
        { event: "popup_blocked", request_id: requestId, url: popup.url() },
        "popup_blocked",
      );
      await popup.close().catch(() => {});
      return;
    }

    logger.warn(
      { event: "popup_policy_violation", request_id: requestId, url: popup.url() },
      "popup_closed_for_policy",
    );
    await popup.close().catch(() => {});
  });

  page.on("websocket", (websocket) => {
    const url = websocket.url();
    void (async () => {
      try {
        await validateBrowserTargetUrl(url);
      } catch {
        state.blockedRequestCount += 1;
        state.blockedTargetCount += 1;
        logger.warn(
          {
            event: "websocket_blocked",
            request_id: requestId,
            url,
          },
          "websocket_blocked",
        );
        websocket.close();
        return;
      }

      logger.debug(
        {
          event: "websocket_observed",
          request_id: requestId,
          url: (() => {
            try {
              const parsed = new URL(url);
              return parsed.host;
            } catch {
              return "invalid";
            }
          })(),
        },
        "websocket_observed",
      );
    })();
  });

  return state;
}
