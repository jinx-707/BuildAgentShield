/**
 * Browser lifecycle manager.
 * Each session gets an isolated Puppeteer browser context.
 * No shared state between sessions.
 */
'use strict';

const puppeteer = require('puppeteer');

// session_id -> { browser, page, createdAt }
const sessions = new Map();

const SESSION_TIMEOUT_MS = 120_000;

async function createSession() {
  const sessionId = `sess_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-web-security',          // Disabled — AgentShield enforces at Python level
      '--disable-features=VizDisplayCompositor',
      '--no-first-run',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-default-apps',
      '--disable-sync',
      '--disable-translate',
      '--safebrowsing-disable-auto-update',
      '--disable-client-side-phishing-detection',
    ],
  });

  // Use isolated incognito context — no cookies from previous sessions
  const context = await browser.createIncognitoBrowserContext();
  const page = await context.newPage();

  // Restrict browser permissions — no camera, microphone, geolocation
  await context.overridePermissions('https://example.com', []);

  // Block access to localhost and private IPs at the browser level
  // (Defence in depth — Python gateway already validates URLs)
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const url = req.url();
    const blockedPatterns = [
      /^(javascript|file|data|vbscript|blob):/i,
      /127\.0\.0\.1/,
      /localhost/,
      /0\.0\.0\.0/,
      /169\.254\./,
      /\[::1\]/,
      /\[fe80:/i,
    ];
    const isBlocked = blockedPatterns.some((p) => p.test(url));
    if (isBlocked) {
      console.warn(`[BROWSER WORKER] Blocked request to: ${url.substring(0, 100)}`);
      req.abort('blockedbyclient');
    } else {
      req.continue();
    }
  });

  sessions.set(sessionId, {
    browser,
    context,
    page,
    createdAt: Date.now(),
  });

  return sessionId;
}

async function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;

  // Check timeout
  if (Date.now() - session.createdAt > SESSION_TIMEOUT_MS) {
    await closeSession(sessionId);
    return null;
  }

  return session;
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (session) {
    try {
      await session.browser.close();
    } catch (e) {
      console.error(`[BROWSER WORKER] Error closing session ${sessionId}:`, e.message);
    }
    sessions.delete(sessionId);
    console.log(`[BROWSER WORKER] Session closed: ${sessionId}`);
  }
}

async function navigate(sessionId, url, timeoutMs = 30000) {
  const session = await getSession(sessionId);
  if (!session) throw new Error(`Session ${sessionId} not found or expired`);

  await session.page.goto(url, {
    waitUntil: 'domcontentloaded',
    timeout: timeoutMs,
  });

  const title = await session.page.title();
  return { url, title, status: 'navigated' };
}

async function extractText(sessionId, selector = null) {
  const session = await getSession(sessionId);
  if (!session) throw new Error(`Session ${sessionId} not found or expired`);

  let text;
  const title = await session.page.title();

  if (selector) {
    try {
      await session.page.waitForSelector(selector, { timeout: 5000 });
      text = await session.page.$eval(selector, (el) => el.innerText);
    } catch {
      text = '';
    }
  } else {
    // Extract visible text only — not scripts or hidden content
    text = await session.page.evaluate(() => {
      const body = document.body;
      if (!body) return '';
      // Remove script and style elements
      const scripts = body.querySelectorAll('script, style, noscript');
      scripts.forEach((s) => s.remove());
      return body.innerText || body.textContent || '';
    });
  }

  // Limit text size to prevent memory issues
  const MAX_TEXT = 100_000;
  if (text.length > MAX_TEXT) {
    text = text.substring(0, MAX_TEXT) + '\n[CONTENT TRUNCATED]';
  }

  return {
    title,
    text,
    url: session.page.url(),
    metadata: { textLength: text.length },
  };
}

async function click(sessionId, selector) {
  const session = await getSession(sessionId);
  if (!session) throw new Error(`Session ${sessionId} not found or expired`);

  await session.page.waitForSelector(selector, { timeout: 5000 });
  await session.page.click(selector);
  return { clicked: selector, status: 'clicked' };
}

async function getMetadata(sessionId) {
  const session = await getSession(sessionId);
  if (!session) throw new Error(`Session ${sessionId} not found or expired`);

  const title = await session.page.title();
  const url = session.page.url();
  const metadata = await session.page.evaluate(() => {
    const metas = {};
    document.querySelectorAll('meta').forEach((m) => {
      const name = m.getAttribute('name') || m.getAttribute('property') || '';
      const content = m.getAttribute('content') || '';
      if (name && content) metas[name] = content;
    });
    return metas;
  });

  return { title, url, metadata };
}

function getActiveSessionCount() {
  return sessions.size;
}

module.exports = {
  createSession,
  getSession,
  closeSession,
  navigate,
  extractText,
  click,
  getMetadata,
  getActiveSessionCount,
};
