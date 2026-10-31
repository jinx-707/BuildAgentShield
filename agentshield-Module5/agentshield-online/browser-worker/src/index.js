/**
 * AgentShield Browser Worker — Express HTTP server wrapping Puppeteer.
 *
 * The LLM never calls this server directly.
 * All requests come from the authenticated Python backend.
 *
 * Endpoints:
 *   GET  /health
 *   POST /session/create
 *   POST /session/close
 *   POST /navigate
 *   POST /extract
 *   POST /click
 *   POST /metadata
 */
'use strict';

const express = require('express');
const browser = require('./browser');
const { enforceAuth, enforceSessionId, enforceUrl } = require('./policy_enforcer');

const PORT = process.env.BROWSER_WORKER_PORT || 3001;
const app = express();

app.use(express.json({ limit: '1mb' }));

// All routes require authentication
app.use(enforceAuth);

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    activeSessions: browser.getActiveSessionCount(),
  });
});

// ── Session management ────────────────────────────────────────────────────────

app.post('/session/create', async (req, res) => {
  try {
    const sessionId = await browser.createSession();
    console.log(`[WORKER] Session created: ${sessionId}`);
    res.json({ sessionId });
  } catch (err) {
    console.error('[WORKER] createSession error:', err.message);
    res.status(500).json({ error: 'Failed to create browser session' });
  }
});

app.post('/session/close', enforceSessionId, async (req, res) => {
  try {
    await browser.closeSession(req.body.sessionId);
    res.json({ closed: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to close session' });
  }
});

// ── Navigation ────────────────────────────────────────────────────────────────

app.post('/navigate', enforceSessionId, enforceUrl, async (req, res) => {
  const { sessionId, url, timeout = 30000 } = req.body;
  try {
    const result = await browser.navigate(sessionId, url, timeout);
    res.json(result);
  } catch (err) {
    console.error('[WORKER] navigate error:', err.message);
    res.status(500).json({ error: `Navigation failed: ${err.message}` });
  }
});

// ── Extract ───────────────────────────────────────────────────────────────────

app.post('/extract', enforceSessionId, async (req, res) => {
  const { sessionId, selector } = req.body;
  try {
    const result = await browser.extractText(sessionId, selector || null);
    res.json(result);
  } catch (err) {
    console.error('[WORKER] extract error:', err.message);
    res.status(500).json({ error: `Extract failed: ${err.message}` });
  }
});

// ── Click ─────────────────────────────────────────────────────────────────────

app.post('/click', enforceSessionId, async (req, res) => {
  const { sessionId, selector } = req.body;
  if (!selector) return res.status(400).json({ error: 'selector required' });
  try {
    const result = await browser.click(sessionId, selector);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: `Click failed: ${err.message}` });
  }
});

// ── Metadata ──────────────────────────────────────────────────────────────────

app.post('/metadata', enforceSessionId, async (req, res) => {
  const { sessionId } = req.body;
  try {
    const result = await browser.getMetadata(sessionId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: `Metadata failed: ${err.message}` });
  }
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[WORKER] Unhandled error:', err);
  res.status(500).json({ error: 'Internal worker error' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[WORKER] AgentShield Browser Worker listening on 127.0.0.1:${PORT}`);
  console.log(`[WORKER] Auth required: X-AgentShield-Key header`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[WORKER] SIGTERM received, shutting down');
  process.exit(0);
});

module.exports = app;
