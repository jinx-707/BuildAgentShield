import { config } from "../config.js";

const LIMIT_WINDOW_MS = 60000;
const MAX_TRACKED_SESSIONS = 1000;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const screenshotState = new Map();
let activeCaptures = 0;

export class ScreenshotError extends Error {
  constructor(code, message, status = 400, details = null) {
    super(message);
    this.name = "ScreenshotError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export class ScreenshotTimeoutError extends Error {
  constructor() {
    super("browser screenshot timed out");
    this.name = "ScreenshotTimeoutError";
    this.code = "SCREENSHOT_TIMEOUT";
    this.status = 504;
  }
}

function pruneState(now) {
  for (const [sessionId, state] of screenshotState.entries()) {
    // Keep lifetime counters for as long as the session itself can live.
    if (now - state.lastUsed > config.sessionMaxAgeMs) {
      screenshotState.delete(sessionId);
    }
  }

  while (screenshotState.size > MAX_TRACKED_SESSIONS) {
    let oldestId = null;
    let oldestAt = Infinity;
    for (const [sessionId, state] of screenshotState.entries()) {
      if (state.lastUsed < oldestAt) {
        oldestAt = state.lastUsed;
        oldestId = sessionId;
      }
    }
    if (oldestId === null) break;
    screenshotState.delete(oldestId);
  }
}

export function beginScreenshot(sessionId) {
  const now = Date.now();
  pruneState(now);

  let state = screenshotState.get(sessionId);
  if (!state) {
    state = {
      windowStart: now,
      count: 0,
      total: 0,
      lastUsed: now,
    };
    screenshotState.set(sessionId, state);
  }

  if (now - state.windowStart >= LIMIT_WINDOW_MS) {
    state.windowStart = now;
    state.count = 0;
  }

  if (state.total >= config.screenshotMaxPerSession) {
    throw new ScreenshotError(
      "SCREENSHOT_SESSION_LIMIT",
      "the session has reached its screenshot limit",
      429,
      { max_per_session: config.screenshotMaxPerSession },
    );
  }
  if (state.count >= config.screenshotRateLimitPerMinute) {
    throw new ScreenshotError(
      "SCREENSHOT_RATE_LIMITED",
      "the session has reached its screenshot rate limit",
      429,
      { max_per_minute: config.screenshotRateLimitPerMinute },
    );
  }
  if (activeCaptures >= config.screenshotMaxConcurrent) {
    throw new ScreenshotError(
      "SCREENSHOT_CONCURRENCY_LIMIT",
      "too many screenshots are being captured",
      503,
      { max_concurrent: config.screenshotMaxConcurrent },
    );
  }

  state.count += 1;
  state.total += 1;
  state.lastUsed = now;
  activeCaptures += 1;

  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeCaptures = Math.max(0, activeCaptures - 1);
  };
}

function readPageDimensions(page) {
  return page.evaluate(() => {
    const root = document.documentElement;
    const body = document.body;
    return {
      scroll_width: Math.max(
        root ? root.scrollWidth : 0,
        body ? body.scrollWidth : 0,
      ),
      scroll_height: Math.max(
        root ? root.scrollHeight : 0,
        body ? body.scrollHeight : 0,
      ),
      viewport_width: window.innerWidth,
      viewport_height: window.innerHeight,
    };
  });
}

function readPngDimensions(buffer) {
  if (
    buffer.length < 24 ||
    !buffer.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)
  ) {
    throw new ScreenshotError(
      "SCREENSHOT_ENCODING_FAILED",
      "the browser returned an invalid PNG image",
      502,
    );
  }

  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function validateClip(clip) {
  if (clip === undefined || clip === null) {
    return null;
  }
  if (typeof clip !== "object" || Array.isArray(clip)) {
    throw new ScreenshotError("INVALID_SCREENSHOT_CLIP", "clip must be an object");
  }

  const { x, y, width, height } = clip;
  if (!Number.isInteger(x) || x < 0 || !Number.isInteger(y) || y < 0) {
    throw new ScreenshotError(
      "INVALID_SCREENSHOT_CLIP",
      "clip x and y must be non-negative integers",
    );
  }
  if (!Number.isInteger(width) || width < 1 || !Number.isInteger(height) || height < 1) {
    throw new ScreenshotError(
      "INVALID_SCREENSHOT_CLIP",
      "clip width and height must be positive integers",
    );
  }
  if (width > config.screenshotMaxWidth || height > config.screenshotMaxHeight) {
    throw new ScreenshotError(
      "SCREENSHOT_DIMENSIONS_EXCEEDED",
      "the requested clip exceeds the maximum screenshot dimensions",
      413,
      {
        max_width: config.screenshotMaxWidth,
        max_height: config.screenshotMaxHeight,
      },
    );
  }

  return { x, y, width, height };
}

export async function withScreenshotTimeout(promise, timeoutMs, onTimeout) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ScreenshotTimeoutError()), timeoutMs);
    timer.unref?.();
  });

  try {
    return await Promise.race([promise, timeout]);
  } catch (error) {
    if (error instanceof ScreenshotTimeoutError) {
      await onTimeout().catch(() => {});
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export async function captureScreenshot(page, { fullPage = false, clip = null } = {}) {
  const startedAt = Date.now();
  if (typeof fullPage !== "boolean") {
    throw new ScreenshotError("INVALID_SCREENSHOT_OPTIONS", "full_page must be a boolean");
  }
  if (fullPage && clip !== null && clip !== undefined) {
    throw new ScreenshotError(
      "INVALID_SCREENSHOT_OPTIONS",
      "full_page and clip cannot be combined",
    );
  }

  const validatedClip = validateClip(clip);
  const dimensions = await readPageDimensions(page);

  let expectedWidth;
  let expectedHeight;

  if (fullPage) {
    expectedWidth = dimensions.scroll_width;
    expectedHeight = dimensions.scroll_height;

    if (
      expectedWidth > config.screenshotMaxWidth ||
      expectedHeight > config.screenshotMaxFullPageHeight
    ) {
      throw new ScreenshotError(
        "SCREENSHOT_DIMENSIONS_EXCEEDED",
        "the page exceeds the maximum full-page screenshot dimensions",
        413,
        {
          max_width: config.screenshotMaxWidth,
          max_full_page_height: config.screenshotMaxFullPageHeight,
          page_width: expectedWidth,
          page_height: expectedHeight,
        },
      );
    }
  } else if (validatedClip) {
    expectedWidth = validatedClip.width;
    expectedHeight = validatedClip.height;
    const maxDocumentWidth = Math.max(
      dimensions.scroll_width,
      dimensions.viewport_width,
    );
    const maxDocumentHeight = Math.max(
      dimensions.scroll_height,
      dimensions.viewport_height,
    );
    if (
      validatedClip.x + validatedClip.width > maxDocumentWidth ||
      validatedClip.y + validatedClip.height > maxDocumentHeight
    ) {
      throw new ScreenshotError(
        "SCREENSHOT_CLIP_OUT_OF_BOUNDS",
        "the clip rectangle is outside the page bounds",
      );
    }
  } else {
    expectedWidth = dimensions.viewport_width;
    expectedHeight = dimensions.viewport_height;

    if (
      expectedWidth > config.screenshotMaxWidth ||
      expectedHeight > config.screenshotMaxHeight
    ) {
      throw new ScreenshotError(
        "SCREENSHOT_DIMENSIONS_EXCEEDED",
        "the viewport exceeds the maximum screenshot dimensions",
        413,
        {
          max_width: config.screenshotMaxWidth,
          max_height: config.screenshotMaxHeight,
          viewport_width: expectedWidth,
          viewport_height: expectedHeight,
        },
      );
    }
  }

  const raw = await page.screenshot({
    type: "png",
    fullPage,
    clip: validatedClip ?? undefined,
  });
  const buffer = Buffer.from(raw);
  const actual = readPngDimensions(buffer);
  const maxHeight = fullPage
    ? config.screenshotMaxFullPageHeight
    : config.screenshotMaxHeight;

  if (
    actual.width > config.screenshotMaxWidth ||
    actual.height > maxHeight
  ) {
    throw new ScreenshotError(
      "SCREENSHOT_DIMENSIONS_EXCEEDED",
      "the captured image exceeds the maximum screenshot dimensions",
      413,
      {
        max_width: config.screenshotMaxWidth,
        max_height: maxHeight,
        image_width: actual.width,
        image_height: actual.height,
      },
    );
  }

  if (buffer.length > config.screenshotMaxBytes) {
    throw new ScreenshotError(
      "SCREENSHOT_TOO_LARGE",
      "the captured image exceeds the maximum screenshot size",
      413,
      {
        max_bytes: config.screenshotMaxBytes,
        image_bytes: buffer.length,
      },
    );
  }

  return {
    buffer,
    width: actual.width,
    height: actual.height,
    full_page: fullPage,
    bytes: buffer.length,
    elapsed_ms: Date.now() - startedAt,
  };
}
