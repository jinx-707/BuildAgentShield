/**
 * Request interceptor — blocks dangerous browser requests at the network level.
 * Applied to every Puppeteer page as defence-in-depth.
 */
'use strict';

const BLOCKED_URL_PATTERNS = [
  // Private IPv4
  /^https?:\/\/10\.\d+\.\d+\.\d+/,
  /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /^https?:\/\/192\.168\.\d+\.\d+/,
  /^https?:\/\/127\.\d+\.\d+\.\d+/,
  /^https?:\/\/0\.0\.0\.0/,
  /^https?:\/\/169\.254\.\d+\.\d+/,
  // IPv6 private
  /^https?:\/\/\[::1\]/,
  /^https?:\/\/\[fe80:/i,
  /^https?:\/\/\[fc00:/i,
  /^https?:\/\/\[fd/i,
  // Cloud metadata
  /^https?:\/\/169\.254\.169\.254/,
  /^https?:\/\/metadata\.google\.internal/i,
  // Dangerous schemes
  /^(javascript|file|data|vbscript|blob):/i,
  // Localhost variations
  /^https?:\/\/localhost/i,
];

function shouldBlock(url) {
  return BLOCKED_URL_PATTERNS.some((pattern) => pattern.test(url));
}

function installInterceptor(page) {
  page.on('request', (req) => {
    const url = req.url();
    if (shouldBlock(url)) {
      console.warn(`[INTERCEPTOR] Blocked: ${url.substring(0, 120)}`);
      req.abort('blockedbyclient');
    } else {
      req.continue();
    }
  });
}

module.exports = { installInterceptor, shouldBlock };
