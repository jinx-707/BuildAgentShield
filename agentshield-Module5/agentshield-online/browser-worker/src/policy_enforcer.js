/**
 * Policy enforcer — validates incoming requests to the browser worker API.
 * The LLM never reaches this service directly.
 * All requests must carry the AgentShield internal API key.
 */
'use strict';

const WORKER_API_KEY = process.env.BROWSER_WORKER_API_KEY || 'dev-browser-worker-key-change-me';

function enforceAuth(req, res, next) {
  const key = req.headers['x-agentshield-key'];
  if (!key || key !== WORKER_API_KEY) {
    console.warn(`[POLICY] Unauthorized request from ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function enforceSessionId(req, res, next) {
  const sessionId = req.body?.sessionId;
  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 100) {
    return res.status(400).json({ error: 'Valid sessionId required' });
  }
  next();
}

function enforceUrl(req, res, next) {
  const url = req.body?.url;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url required' });
  }
  if (url.length > 2048) {
    return res.status(400).json({ error: 'url too long' });
  }
  // Block obvious dangerous schemes (Python gateway does the full check)
  if (/^(javascript|file|data|vbscript)/i.test(url)) {
    return res.status(400).json({ error: 'Blocked URL scheme' });
  }
  next();
}

module.exports = { enforceAuth, enforceSessionId, enforceUrl };
