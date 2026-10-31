import { useEffect, useState } from "react"
import { Globe, Plus, ShieldAlert, ShieldCheck, X } from "lucide-react"
import { Badge, Button, Empty, Panel, Select, toneFor } from "../components/ui"
import type { AuditEvent } from "../services/demo"
import {
  ApiError,
  closeBrowserSession,
  createBrowserSession,
  getBrowserSession,
  navigateBrowser,
  type AgentRecord,
  type BrowserNavigationResult,
  type BrowserSession,
} from "../services/api"

const SESSION_KEY = "agentshield.browser_session"

type StoredSession = {
  agentId: string
  sessionId: string
}

function readStoredSession(): StoredSession | null {
  try {
    const raw = window.localStorage.getItem(SESSION_KEY)
    return raw ? (JSON.parse(raw) as StoredSession) : null
  } catch {
    return null
  }
}

function storeSession(session: StoredSession | null) {
  try {
    if (session) {
      window.localStorage.setItem(SESSION_KEY, JSON.stringify(session))
    } else {
      window.localStorage.removeItem(SESSION_KEY)
    }
  } catch {
    // Browser storage is optional; the live session still works in memory.
  }
}

export default function BrowserSessions({
  agents,
  events,
  notify,
  onRefreshAudit,
}: {
  agents: AgentRecord[]
  events: AuditEvent[]
  notify: (message: string) => void
  onRefreshAudit: () => Promise<void> | void
}) {
  const activeAgents = agents.filter((agent) => agent.status === "Active")
  const [agentId, setAgentId] = useState(activeAgents[0]?.id || "")
  const [session, setSession] = useState<BrowserSession | null>(null)
  const [sessionAgent, setSessionAgent] = useState("")
  const [url, setUrl] = useState("https://example.com")
  const [result, setResult] = useState<BrowserNavigationResult | null>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState("")

  useEffect(() => {
    if (!activeAgents.some((agent) => agent.id === agentId)) {
      setAgentId(activeAgents[0]?.id || "")
    }
  }, [activeAgents, agentId])

  useEffect(() => {
    const stored = readStoredSession()
    if (!stored) return
    let cancelled = false
    getBrowserSession(stored.agentId, stored.sessionId)
      .then((live) => {
        if (cancelled) return
        setSession(live)
        setSessionAgent(stored.agentId)
        setAgentId(stored.agentId)
      })
      .catch(() => {
        if (!cancelled) storeSession(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function launch() {
    if (!agentId) {
      setError("Create and select an active agent first.")
      return
    }
    setBusy("launch")
    setError("")
    try {
      const created = await createBrowserSession(agentId)
      setSession(created)
      setSessionAgent(agentId)
      storeSession({ agentId, sessionId: created.session_id })
      notify(`Browser session ${created.session_id} launched.`)
      await onRefreshAudit()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Session launch failed")
    } finally {
      setBusy("")
    }
  }

  async function close() {
    if (!session) return
    setBusy("close")
    setError("")
    try {
      await closeBrowserSession(sessionAgent, session.session_id)
      setSession(null)
      setResult(null)
      storeSession(null)
      notify("Browser session closed.")
      await onRefreshAudit()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Session close failed")
    } finally {
      setBusy("")
    }
  }

  async function navigate(target = url) {
    if (!session) {
      setError("Launch a browser session first.")
      return
    }
    setBusy("navigate")
    setError("")
    setResult(null)
    try {
      const response = await navigateBrowser(
        sessionAgent,
        target,
        session.session_id,
      )
      setResult(response)
      setSession(await getBrowserSession(sessionAgent, session.session_id))
      notify(
        response.policy.allowed
          ? `Navigation allowed to ${response.final_url}.`
          : `Navigation denied: ${response.policy.reason}`,
      )
    } catch (failure) {
      const message =
        failure instanceof ApiError ? failure.message : "Navigation failed"
      setError(message)
      notify(`Navigation blocked: ${message}`)
    } finally {
      setBusy("")
      await onRefreshAudit()
    }
  }

  const browserEvents = events
    .filter((event) =>
      ["navigation.", "session.", "action.", "security."].some((prefix) =>
        event.tool.startsWith(prefix),
      ),
    )
    .slice(0, 8)

  return (
    <>
      <div className="summary-strip">
        <div>
          <Globe size={16} />
          Session{" "}
          <strong>{session ? session.session_id.slice(0, 18) : "not launched"}</strong>
        </div>
        <div>
          <ShieldCheck size={16} />
          Policy <strong>database-backed</strong>
        </div>
        <div>
          <i className={session ? "live-dot" : "live-dot idle"} />
          {session ? session.status : "idle"}
        </div>
      </div>

      <div className="two-column-grid">
        <Panel
          title="Launch a controlled browser"
          description="Every navigation is evaluated against the active database policy before the worker runs."
        >
          <label className="form-label">
            Agent identity
            <Select
              label="Agent"
              value={agentId}
              onChange={setAgentId}
              options={activeAgents.map((agent) => agent.id)}
            />
          </label>
          <div className="inline-actions">
            <Button
              variant="primary"
              disabled={Boolean(session) || busy === "launch"}
              onClick={launch}
            >
              <Plus size={15} />
              {busy === "launch" ? "Launching…" : "Launch session"}
            </Button>
            {session && (
              <Button onClick={close} disabled={busy === "close"}>
                <X size={15} />
                Close session
              </Button>
            )}
          </div>

          <label className="form-label" style={{ marginTop: 18 }}>
            Destination URL
            <input
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com"
            />
          </label>
          <div className="inline-actions">
            <Button
              variant="primary"
              disabled={!session || busy === "navigate"}
              onClick={() => navigate()}
            >
              <Globe size={15} />
              {busy === "navigate" ? "Navigating…" : "Navigate"}
            </Button>
            <Button
              variant="danger"
              disabled={!session || busy === "navigate"}
              onClick={() => {
                setUrl("https://blocked.example/")
                navigate("https://blocked.example/")
              }}
            >
              <ShieldAlert size={15} />
              Attempt blocked destination
            </Button>
          </div>

          {error && (
            <div className="notice" style={{ marginTop: 16 }}>
              <ShieldAlert size={16} />
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div className="policy-detail" style={{ marginTop: 18 }}>
              <div>
                <span>Final URL</span>
                <code>{result.final_url}</code>
              </div>
              <div>
                <span>Decision</span>
                <Badge tone={result.policy.allowed ? "green" : "red"}>
                  {result.policy.allowed ? "Allowed" : "Blocked"}
                </Badge>
              </div>
              <div>
                <span>Policy</span>
                <code>{result.policy.policy_name}</code>
              </div>
              <div>
                <span>Reason</span>
                <strong>{result.policy.reason}</strong>
              </div>
              <div>
                <span>HTTP status</span>
                <code>{result.status_code ?? "none"}</code>
              </div>
              <div>
                <span>Title</span>
                <strong>{result.title || "(no title)"}</strong>
              </div>
              {result.inspection.findings.length > 0 && (
                <div>
                  <span>Inspection</span>
                  <strong>
                    {result.inspection.findings
                      .map((finding) => finding.message)
                      .join(" · ")}
                  </strong>
                </div>
              )}
            </div>
          )}
        </Panel>

        <Panel
          title="Session telemetry"
          description="Browser security decisions emitted by the API and worker."
        >
          {session ? (
            <div className="policy-detail">
              <div>
                <span>Session</span>
                <code>{session.session_id}</code>
              </div>
              <div>
                <span>State</span>
                <strong>{session.state}</strong>
              </div>
              <div>
                <span>Current URL</span>
                <code>{session.current_url || "(not navigated)"}</code>
              </div>
              <div>
                <span>Expires</span>
                <strong>{new Date(session.expires_at).toLocaleString()}</strong>
              </div>
            </div>
          ) : (
            <Empty
              title="No live session"
              detail="Launch a session to begin recording browser events."
              icon={Globe}
            />
          )}

          <div className="audit-mini-list" style={{ marginTop: 18 }}>
            {browserEvents.map((event) => (
              <div key={event.id} className="audit-mini-row">
                <Badge tone={toneFor(event.decision)}>{event.decision}</Badge>
                <div>
                  <strong>{event.tool}</strong>
                  <small>{event.description}</small>
                </div>
                <span>{event.time}</span>
              </div>
            ))}
            {browserEvents.length === 0 && (
              <p className="muted">
                No browser events yet. Launch a session and navigate to create an
                audit trail.
              </p>
            )}
          </div>
        </Panel>
      </div>
    </>
  )
}
