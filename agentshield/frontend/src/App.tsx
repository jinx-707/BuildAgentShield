import { useEffect, useRef, useState } from "react"
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Bell,
  BookOpen,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  FileCheck2,
  FlaskConical,
  Globe,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Users,
  X,
  Zap,
} from "lucide-react"
import {
  Badge,
  Button,
  Empty,
  Modal,
  PageHeading,
  Panel,
  Select,
  Toggle,
  toneFor,
} from "./components/ui"
import Overview from "./pages/Overview"
import {
  capabilities,
  exportFile,
  initialAgents,
  initialApprovals,
  initialEvents,
  policies as policySeed,
  scenarios,
  simulate,
  type Agent,
  type Approval,
  type AuditEvent,
} from "./services/demo"

const navigation = [
  { title: "Overview", icon: LayoutDashboard },
  { title: "Agents", icon: Users },
  { title: "Capabilities & Permissions", icon: SlidersHorizontal },
  { title: "Policy Manager", icon: ShieldCheck },
  { title: "Approval Queue", icon: FileCheck2 },
  { title: "Audit Logs", icon: Activity },
  { title: "Attack Simulator", icon: FlaskConical },
]
const pageDescriptions: Record<string, string> = {
  Agents: "Manage identities, access, and the lifecycle of your AI agents.",
  "Capabilities & Permissions":
    "Define exactly what each agent can access and do.",
  "Policy Manager":
    "Your security rules. Consistently enforced at every boundary.",
  "Approval Queue": "A human checkpoint for actions that need a second look.",
  "Audit Logs": "A complete, traceable record of every gateway decision.",
  "Attack Simulator":
    "Put your guardrails to the test. Without putting your systems at risk.",
  Quarantine:
    "Isolated content that needs your attention before it goes any further.",
  Settings: "Configure your workspace and connect your security modules.",
}

export default function App() {
  const [page, setPage] = useState("Overview")
  const [workspaceName, setWorkspaceName] = useState("Acme workspace")
  const [workspaceDraft, setWorkspaceDraft] = useState("Acme workspace")
  const [agents, setAgents] = useState<Agent[]>(initialAgents)
  const [events, setEvents] = useState<AuditEvent[]>(initialEvents)
  const [approvals, setApprovals] = useState<Approval[]>(initialApprovals)
  const [policies, setPolicies] = useState(policySeed)
  const [range, setRange] = useState("Last 24 hours")
  const [toast, setToast] = useState("")
  const toastTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
    undefined,
  )
  const [modal, setModal] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)
  const [selectedApproval, setSelectedApproval] = useState<Approval | null>(
    null,
  )
  const [selectedAgent, setSelectedAgent] = useState("research-agent")
  const [permissions, setPermissions] = useState<Record<string, boolean>>({})
  const [scopes, setScopes] = useState<Record<string, string>>({})
  const [filter, setFilter] = useState("All decisions")
  const [query, setQuery] = useState("")
  const [auditPage, setAuditPage] = useState(1)
  const [searchOpen, setSearchOpen] = useState(false)
  const [globalSearch, setGlobalSearch] = useState("")
  const [mobileOpen, setMobileOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const [notifications, setNotifications] = useState(false)
  const [readNotifications, setReadNotifications] = useState(false)
  const [statusFilter, setStatusFilter] = useState("All agents")
  const [results, setResults] =
    useState<Record<string, ReturnType<typeof simulate>>>({})
  const [running, setRunning] = useState(false)
  const [agentName, setAgentName] = useState("")
  const [agentRole, setAgentRole] = useState("Readonly researcher")
  const [newKey, setNewKey] = useState("")
  const [comment, setComment] = useState("")
  const [quarantined, setQuarantined] = useState([
    "Untrusted webpage content",
    "Suspicious PDF attachment",
    "Unverified download",
  ])
  const [approvalTab, setApprovalTab] = useState("Pending")
  const [loggedIn, setLoggedIn] = useState(true)
  const [loginEmail, setLoginEmail] = useState("admin@agentshield.demo")
  const [loginPassword, setLoginPassword] = useState("")
  const [loginError, setLoginError] = useState("")
  const pending = approvals.filter((a) => a.status === "Pending").length
  function notify(message: string) {
    setToast(message)
    clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(""), 4000)
  }
  function navigate(next: string) {
    setPage(next)
    setMobileOpen(false)
    setQuery("")
    setFilter("All decisions")
    setAuditPage(1)
    window.scrollTo({ top: 0, behavior: "smooth" })
  }
  useEffect(() => {
    function keydown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setSearchOpen((v) => !v)
      }
      if (e.key === "Escape") {
        setModal(null)
        setSelectedEvent(null)
        setSelectedApproval(null)
        setSearchOpen(false)
        setNotifications(false)
        setProfileOpen(false)
      }
    }
    window.addEventListener("keydown", keydown)
    return () => {
      window.removeEventListener("keydown", keydown)
      clearTimeout(toastTimer.current)
    }
  }, [])
  function addAudit(
    agent: string,
    tool: string,
    description: string,
    decision: AuditEvent["decision"],
    risk: number,
  ) {
    setEvents((old) => [
      {
        id: `evt_${crypto.randomUUID().slice(0, 8)}`,
        agent,
        tool,
        description,
        decision,
        risk,
        time: "Just now",
      },
      ...old,
    ])
  }
  function reviewApproval(status: string) {
    if (!selectedApproval) return
    setApprovals((old) =>
      old.map((a) => (a.id === selectedApproval.id ? { ...a, status } : a)),
    )
    addAudit(
      selectedApproval.agent,
      selectedApproval.tool,
      `Demo human review: ${status.toLowerCase()}.${
        comment ? ` Comment: ${comment}` : ""
      } No tool was executed.`,
      status === "Approved" ? "Allowed" : "Blocked",
      selectedApproval.risk,
    )
    setSelectedApproval(null)
    setComment("")
    notify(
      `Request ${status.toLowerCase()} in demo. No real action was executed.`,
    )
  }
  async function runSimulation(ids: string[]) {
    setRunning(true)
    for (const id of ids) {
      await new Promise((resolve) => setTimeout(resolve, 230))
      const scenario = scenarios.find((s) => s.id === id)!
      const result = simulate(scenario)
      setResults((old) => ({ ...old, [id]: result }))
      addAudit(
        "simulator-agent",
        scenario.tool,
        `${scenario.name}: ${result.reason}`,
        result.decision,
        scenario.risk,
      )
    }
    setRunning(false)
    notify(
      `${ids.length} demo scenario${
        ids.length > 1 ? "s" : ""
      } completed. No adapters executed.`,
    )
  }
  function createAgent() {
    if (!agentName.trim()) return
    if (agents.some((a) => a.name === agentName.trim())) {
      notify("An agent with this name already exists.")
      return
    }
    setAgents((old) => [
      ...old,
      {
        id: `agt_${crypto.randomUUID().slice(0, 6)}`,
        name: agentName.trim(),
        role: agentRole,
        status: "Active",
        requests: 0,
        initials: agentName.slice(0, 2).toUpperCase(),
        color: "violet",
      },
    ])
    setAgentName("")
    setNewKey(`as_demo_${crypto.randomUUID()}`)
    setModal("Agent created")
  }
  const visibleEvents = events.filter(
    (e) =>
      (filter === "All decisions" || e.decision === filter) &&
      `${e.agent} ${e.tool} ${e.id} ${e.description}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  )
  const searchable = [
    ...navigation.map((n) => ({
      title: n.title,
      category: "Page",
      target: n.title,
    })),
    ...agents.map((a) => ({
      title: a.name,
      category: "Agent",
      target: "Agents",
    })),
    ...policySeed.map((p) => ({
      title: p.name,
      category: "Policy",
      target: "Policy Manager",
    })),
  ].filter((s) => s.title.toLowerCase().includes(globalSearch.toLowerCase()))

  if (!loggedIn)
    return (
      <div className="login-page">
        <div className="login-card">
          <div className="brand-mark">
            <Shield size={26} />
          </div>
          <Badge tone="violet">DEMO WORKSPACE</Badge>
          <h1>Welcome to AgentShield</h1>
          <p>A safer boundary for every agent.</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (
                loginEmail === "admin@agentshield.demo" &&
                loginPassword === "demo-password"
              ) {
                setLoggedIn(true)
                setLoginError("")
              } else setLoginError("Use the demo credentials shown below.")
            }}
          >
            <label>
              Email address
              <input
                type="email"
                required
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                required
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
              />
            </label>
            {loginError && <p className="text-red">{loginError}</p>}
            <Button type="submit" variant="primary">
              Enter demo workspace
              <ArrowRight size={16} />
            </Button>
          </form>
          <div className="demo-login-note">
            Demo only · No authentication server
            <br />
            <code>admin@agentshield.demo</code>
            <br />
            <code>demo-password</code>
          </div>
        </div>
      </div>
    )

  return (
    <div className="app-shell">
      {mobileOpen && (
        <div className="sidebar-overlay" onClick={() => setMobileOpen(false)} />
      )}
      <aside className={`sidebar ${mobileOpen ? "is-open" : ""}`}>
        <button className="brand" onClick={() => navigate("Overview")}>
          <span className="brand-mark">
            <Shield size={23} strokeWidth={2} />
            <span className="brand-slash" />
          </span>
          <span>
            Agent<span>Shield</span>
          </span>
          <Badge>PLATFORM</Badge>
        </button>
        <button
          className="workspace-switch"
          onClick={() => setModal("Workspace")}
        >
          <span className="workspace-avatar">A</span>
          <span>
            <strong>{workspaceName}</strong>
            <small>Enterprise plan</small>
          </span>
          <ChevronDown size={14} />
        </button>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {navigation.map((n) => (
            <button
              key={n.title}
              className={`nav-item ${page === n.title ? "active" : ""}`}
              onClick={() => navigate(n.title)}
            >
              <n.icon size={17} />
              <span>{n.title}</span>
              {n.title === "Approval Queue" && (
                <span className="nav-count">{pending}</span>
              )}
              {n.title === "Attack Simulator" && (
                <span className="new-tag">NEW</span>
              )}
            </button>
          ))}
        </nav>
        <div className="nav-divider" />
        <button
          className={`nav-item ${page === "Quarantine" ? "active" : ""}`}
          onClick={() => navigate("Quarantine")}
        >
          <Shield size={17} />
          <span>Quarantine</span>
          <span className="neutral-count">{quarantined.length}</span>
        </button>
        <div className="sidebar-bottom">
          <div className="gateway-card">
            <div>
              <i className="live-dot" />
              <strong>Demo gateway ready</strong>
              <ShieldCheck size={14} />
            </div>
            <p>Every action. Authorized.</p>
            <span>
              DEMO MODE <i />
              v1.0.0
            </span>
          </div>
          <button
            className={`nav-item ${page === "Settings" ? "active" : ""}`}
            onClick={() => navigate("Settings")}
          >
            <Settings2 size={17} />
            <span>Settings</span>
          </button>
          <button
            className="nav-item"
            onClick={() => setModal("Help & documentation")}
          >
            <CircleHelp size={17} />
            <span>Help & documentation</span>
            <ArrowUpRight size={13} />
          </button>
          <div
            className="sidebar-user"
            onClick={() => setProfileOpen(!profileOpen)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && setProfileOpen(!profileOpen)}
          >
            <span className="profile-avatar">JD</span>
            <span>
              <strong>Jamie Davis</strong>
              <small>Workspace admin</small>
            </span>
            <ChevronDown size={14} />
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              aria-label="Open navigation"
              className="icon-button mobile-menu"
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={21} />
            </button>
            <Shield size={15} />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{page === "Overview" ? "Overview" : page}</strong>
          </div>
          <div className="topbar-actions">
            <span className="demo-indicator">Demo data</span>
            <button
              className="global-search"
              onClick={() => setSearchOpen(true)}
            >
              <Search size={14} />
              <span>Search anything...</span>
              <kbd>⌘ K</kbd>
            </button>
            <span className="header-divider" />
            <button
              className="notification-button icon-button"
              aria-label="Notifications"
              onClick={() => {
                setNotifications(!notifications)
                setReadNotifications(true)
              }}
            >
              <Bell size={18} />
              {!readNotifications && <i />}
            </button>
            <button
              className="profile-avatar small"
              aria-label="Open account menu"
              onClick={() => setProfileOpen(!profileOpen)}
            >
              JD
            </button>
          </div>
        </header>
        <main className="content">
          {page === "Overview" ? (
            <Overview
              events={events}
              agents={agents}
              navigate={navigate}
              range={range}
              setRange={setRange}
              pending={pending}
              onEvent={setSelectedEvent}
            />
          ) : (
            <>
              <PageHeading
                eyebrow="AGENTSHIELD PLATFORM"
                title={page}
                description={pageDescriptions[page] || ""}
                actions={
                  page === "Agents" ? (
                    <Button
                      variant="primary"
                      onClick={() => setModal("Create agent")}
                    >
                      <Plus size={16} />
                      Create agent
                    </Button>
                  ) : page === "Attack Simulator" ? (
                    <Button
                      variant="primary"
                      disabled={running}
                      onClick={() => runSimulation(scenarios.map((s) => s.id))}
                    >
                      <Zap size={16} />
                      {running ? "Running scenarios…" : "Run all scenarios"}
                    </Button>
                  ) : page === "Audit Logs" ? (
                    <>
                      <Button onClick={() => setModal("Audit integrity")}>
                        <ShieldCheck size={15} />
                        Verify integrity
                      </Button>
                      <Button
                        onClick={() =>
                          exportFile(
                            "agentshield-audit.json",
                            JSON.stringify(visibleEvents, null, 2),
                          )
                        }
                      >
                        <ArrowDownToLine size={15} />
                        Export JSON
                      </Button>
                    </>
                  ) : page === "Policy Manager" ? (
                    <Button
                      variant="primary"
                      onClick={() => setModal("Create policy")}
                    >
                      <Plus size={16} />
                      New policy
                    </Button>
                  ) : undefined
                }
              />
              {page === "Agents" && (
                <>
                  <div className="summary-strip">
                    <div>
                      <span className="live-dot" />
                      <strong>
                        {agents.filter((a) => a.status === "Active").length}
                      </strong>
                      Active agents
                    </div>
                    <div>
                      <ShieldCheck size={16} />
                      <strong>100%</strong>Gateway coverage
                    </div>
                    <div>
                      <Globe size={16} />
                      Tenant: <strong>{workspaceName}</strong>
                    </div>
                  </div>
                  <Panel
                    title="Your agent fleet"
                    description="Every identity is scoped to this workspace."
                    action={
                      <Select
                        label="Agent status"
                        value={statusFilter}
                        onChange={setStatusFilter}
                        options={["All agents", "Active", "Disabled"]}
                      />
                    }
                  >
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>AGENT</th>
                            <th>ROLE</th>
                            <th>STATUS</th>
                            <th>REQUESTS</th>
                            <th>ACTIONS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {agents
                            .filter(
                              (a) =>
                                statusFilter === "All agents" ||
                                a.status === statusFilter,
                            )
                            .map((a) => (
                              <tr key={a.id}>
                                <td>
                                  <div className="agent-tool">
                                    <span className={`avatar ${a.color}`}>
                                      {a.initials}
                                    </span>
                                    <div>
                                      <strong>{a.name}</strong>
                                      <code>{a.id}</code>
                                    </div>
                                  </div>
                                </td>
                                <td>{a.role}</td>
                                <td>
                                  <Badge tone={toneFor(a.status)} dot>
                                    {a.status}
                                  </Badge>
                                </td>
                                <td>{a.requests.toLocaleString()}</td>
                                <td>
                                  <div className="row-actions">
                                    <button
                                      aria-label={`Permissions for ${a.name}`}
                                      className="icon-button"
                                      onClick={() => {
                                        setSelectedAgent(a.name)
                                        navigate("Capabilities & Permissions")
                                      }}
                                    >
                                      <SlidersHorizontal size={16} />
                                    </button>
                                    <button
                                      aria-label={`Rotate key for ${a.name}`}
                                      className="icon-button"
                                      onClick={() => {
                                        setSelectedAgent(a.name)
                                        setModal("Rotate API key")
                                      }}
                                    >
                                      <KeyRound size={16} />
                                    </button>
                                    <button
                                      className={`button compact ${
                                        a.status === "Active" ? "danger" : ""
                                      }`}
                                      onClick={() => {
                                        setSelectedAgent(a.name)
                                        setModal(
                                          a.status === "Active"
                                            ? "Disable agent"
                                            : "Enable agent",
                                        )
                                      }}
                                    >
                                      {a.status === "Active"
                                        ? "Disable"
                                        : "Enable"}
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </Panel>
                </>
              )}
              {page === "Capabilities & Permissions" && (
                <>
                  <div className="toolbar">
                    <div>
                      <label className="inline-label">CONFIGURE AGENT</label>
                      <Select
                        label="Agent to configure"
                        value={selectedAgent}
                        onChange={setSelectedAgent}
                        options={agents.map((a) => a.name)}
                      />
                    </div>
                    <Badge tone="violet">
                      <ShieldCheck size={12} />
                      Default deny
                    </Badge>
                  </div>
                  <div className="notice">
                    <ShieldCheck size={17} />
                    <span>
                      Permissions are scoped to <strong>{selectedAgent}</strong>
                      . Missing permissions deny access. Changes are local to
                      this demo.
                    </span>
                  </div>
                  <div className="capability-grid">
                    {capabilities.map((c, i) => {
                      const key = `${selectedAgent}:${c.key}`
                      const enabled =
                        permissions[key] ?? [0, 1, 5, 7].includes(i)
                      return (
                        <div
                          className={`capability-card ${
                            enabled ? "enabled" : ""
                          }`}
                          key={key}
                        >
                          <div className="capability-top">
                            <span
                              className={`integration-icon ${
                                enabled ? "violet" : "neutral"
                              }`}
                            >
                              <SlidersHorizontal size={19} />
                            </span>
                            <Toggle
                              checked={enabled}
                              onChange={() => {
                                setPermissions((p) => ({
                                  ...p,
                                  [key]: !enabled,
                                }))
                                notify(
                                  `${c.name} ${
                                    enabled ? "disabled" : "enabled"
                                  } for ${selectedAgent}.`,
                                )
                              }}
                              label={`Enable ${c.name}`}
                            />
                          </div>
                          <h3>{c.name}</h3>
                          <p>{c.description}</p>
                          <div className="capability-meta">
                            <span>{c.tools} registered tools</span>
                            <Badge tone={enabled ? "green" : "neutral"}>
                              {enabled ? "Enabled" : "Denied"}
                            </Badge>
                          </div>
                          <button
                            className="capability-config"
                            onClick={() => setModal(`Configure ${c.name}`)}
                          >
                            Configure scope & restrictions
                            <ChevronRight size={14} />
                          </button>
                        </div>
                      )
                    })}
                  </div>
                </>
              )}
              {page === "Policy Manager" && (
                <>
                  <div className="summary-strip">
                    <div>
                      <ShieldCheck size={17} />
                      <strong>{policies.filter((p) => p.active).length}</strong>
                      Active policies
                    </div>
                    <div>
                      <Terminal size={16} />
                      Engine <strong>Local demo evaluator</strong>
                    </div>
                    <div>
                      <i className="live-dot" />
                      Default-deny enforcement
                    </div>
                  </div>
                  <div className="policy-list">
                    {policies.map((p) => (
                      <div className="panel policy-card" key={p.id}>
                        <span className="integration-icon violet">
                          <ShieldCheck size={21} />
                        </span>
                        <div className="policy-info">
                          <div>
                            <h3>{p.name}</h3>
                            <Badge tone={p.active ? "green" : "neutral"}>
                              {p.active ? "Active" : "Inactive"}
                            </Badge>
                            <code>v{p.version}</code>
                          </div>
                          <p>{p.description}</p>
                          <span>
                            {p.category}
                            <i />
                            Updated 2 hours ago
                          </span>
                        </div>
                        <Button
                          variant="compact"
                          onClick={() => setModal(`Policy: ${p.id}`)}
                        >
                          View policy
                          <ChevronRight size={13} />
                        </Button>
                      </div>
                    ))}
                  </div>
                  <div className="notice">
                    <CircleHelp size={16} />
                    <span>
                      Policy changes here demonstrate UI behavior only. OPA and
                      server-side policy enforcement are not connected.
                    </span>
                  </div>
                </>
              )}
              {page === "Approval Queue" && (
                <>
                  <div className="tabs">
                    {["Pending", "Approved", "Rejected"].map((t) => (
                      <button
                        className={approvalTab === t ? "active" : ""}
                        key={t}
                        onClick={() => setApprovalTab(t)}
                      >
                        {t}
                        <span>
                          {approvals.filter((a) => a.status === t).length}
                        </span>
                      </button>
                    ))}
                  </div>
                  <div className="notice">
                    <Clock3 size={16} />
                    <span>
                      Review the exact requested action before approving. Demo
                      reviews do not execute a real tool.
                    </span>
                  </div>
                  {approvals.filter((a) => a.status === approvalTab).length ===
                  0 ? (
                    <Panel title="All caught up">
                      <Empty
                        title={`No ${approvalTab.toLowerCase()} requests`}
                        detail="New requests will appear here when an agent needs review."
                        icon={CheckCheck}
                      />
                    </Panel>
                  ) : (
                    <div className="approval-grid">
                      {approvals
                        .filter((a) => a.status === approvalTab)
                        .map((a) => (
                          <div className="panel approval-card" key={a.id}>
                            <div className="approval-card-top">
                              <Badge tone="amber">
                                <Clock3 size={11} />
                                {a.status}
                              </Badge>
                              <span className="muted">{a.id}</span>
                            </div>
                            <h3>{a.summary}</h3>
                            <div className="approval-agent">
                              <Users size={14} />
                              {a.agent}
                              <code>{a.tool}</code>
                            </div>
                            <pre>{JSON.stringify(a.args, null, 2)}</pre>
                            <div className="approval-bottom">
                              <span>
                                <span className="text-amber">{a.risk}</span>{" "}
                                risk score
                              </span>
                              <span>
                                <Clock3 size={12} />
                                {a.expires} remaining
                              </span>
                            </div>
                            <Button
                              onClick={() => {
                                setSelectedApproval(a)
                                setComment("")
                              }}
                              variant={a.status === "Pending" ? "primary" : ""}
                            >
                              {a.status === "Pending"
                                ? "Review request"
                                : "View decision"}
                              <ArrowRight size={14} />
                            </Button>
                          </div>
                        ))}
                    </div>
                  )}
                </>
              )}
              {page === "Audit Logs" && (
                <Panel
                  title="Gateway event stream"
                  description={`${visibleEvents.length} events · demo session`}
                  action={
                    <Badge tone="green" dot>
                      Append-only view
                    </Badge>
                  }
                >
                  <div className="audit-toolbar">
                    <div className="search-input">
                      <Search size={15} />
                      <input
                        aria-label="Search audit events"
                        placeholder="Search agents, tools, or event IDs..."
                        value={query}
                        onChange={(e) => {
                          setQuery(e.target.value)
                          setAuditPage(1)
                        }}
                      />
                    </div>
                    <Select
                      label="Decision filter"
                      value={filter}
                      onChange={(v) => {
                        setFilter(v)
                        setAuditPage(1)
                      }}
                      options={[
                        "All decisions",
                        "Blocked",
                        "Allowed",
                        "Approval",
                        "Quarantined",
                        "Redacted",
                      ]}
                    />
                    <Button
                      onClick={() =>
                        exportFile(
                          "agentshield-audit.csv",
                          "id,agent,tool,decision,risk,time\n" +
                            visibleEvents
                              .map((e) =>
                                [
                                  e.id,
                                  e.agent,
                                  e.tool,
                                  e.decision,
                                  e.risk,
                                  e.time,
                                ].join(","),
                              )
                              .join("\n"),
                          "text/csv",
                        )
                      }
                    >
                      <ArrowDownToLine size={14} />
                      CSV
                    </Button>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>EVENT / AGENT</th>
                          <th>TOOL</th>
                          <th>DECISION</th>
                          <th>RISK</th>
                          <th>TIME</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {visibleEvents
                          .slice((auditPage - 1) * 6, auditPage * 6)
                          .map((e) => (
                            <tr
                              className="clickable"
                              key={e.id}
                              onClick={() => setSelectedEvent(e)}
                            >
                              <td>
                                <div className="agent-tool">
                                  <span
                                    className={`event-icon ${toneFor(e.decision)}`}
                                  >
                                    <Activity size={15} />
                                  </span>
                                  <div>
                                    <strong>{e.agent}</strong>
                                    <code>{e.id}</code>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <code>{e.tool}</code>
                              </td>
                              <td>
                                <Badge tone={toneFor(e.decision)}>
                                  {e.decision}
                                </Badge>
                              </td>
                              <td>
                                <strong
                                  className={
                                    e.risk > 80 ? "text-red" : "text-amber"
                                  }
                                >
                                  {e.risk}
                                </strong>
                              </td>
                              <td className="muted">{e.time}</td>
                              <td>
                                <ChevronRight size={14} />
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                    {visibleEvents.length === 0 && (
                      <Empty
                        title="No matching events"
                        detail="Try another search or decision filter."
                        icon={Search}
                      />
                    )}
                  </div>
                  <div className="pagination">
                    <span>
                      Showing{" "}
                      {visibleEvents.length ? (auditPage - 1) * 6 + 1 : 0}–
                      {Math.min(auditPage * 6, visibleEvents.length)} of{" "}
                      {visibleEvents.length} events
                    </span>
                    <div>
                      <Button
                        variant="compact"
                        disabled={auditPage === 1}
                        onClick={() => setAuditPage((p) => p - 1)}
                      >
                        Previous
                      </Button>
                      <span>{auditPage}</span>
                      <Button
                        variant="compact"
                        disabled={auditPage * 6 >= visibleEvents.length}
                        onClick={() => setAuditPage((p) => p + 1)}
                      >
                        Next
                      </Button>
                    </div>
                  </div>
                </Panel>
              )}
              {page === "Attack Simulator" && (
                <>
                  <div className="simulator-notice">
                    <span className="integration-icon violet">
                      <FlaskConical size={23} />
                    </span>
                    <div>
                      <h3>A safe place to break things.</h3>
                      <p>
                        These scenarios run through a local demo evaluator. No
                        files are read, emails sent, or payments made.
                      </p>
                    </div>
                    <Badge tone="violet">SANDBOX</Badge>
                  </div>
                  <div className="summary-strip">
                    <div>
                      <FlaskConical size={17} />
                      <strong>10</strong>Attack scenarios
                    </div>
                    <div>
                      <Check size={17} />
                      <strong>
                        {
                          Object.entries(results).filter(
                            ([id, r]) =>
                              r.decision ===
                                scenarios.find((s) => s.id === id)?.expected &&
                              !r.executed,
                          ).length
                        }
                      </strong>
                      Passed
                    </div>
                    <div>
                      <ShieldCheck size={17} />
                      <strong>0</strong>Real tool executions
                    </div>
                    {Object.keys(results).length > 0 && (
                      <Button
                        variant="compact"
                        onClick={() =>
                          exportFile(
                            "attack-results.json",
                            JSON.stringify(
                              { mode: "local-demo", results },
                              null,
                              2,
                            ),
                          )
                        }
                      >
                        <ArrowDownToLine size={13} />
                        Export results
                      </Button>
                    )}
                  </div>
                  <div className="scenario-grid">
                    {scenarios.map((s, i) => (
                      <div className="panel scenario-card" key={s.id}>
                        <div className="scenario-top">
                          <span className="scenario-number">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <Badge
                            tone={
                              results[s.id]
                                ? results[s.id].decision === s.expected
                                  ? "green"
                                  : "red"
                                : "neutral"
                            }
                          >
                            {results[s.id]
                              ? results[s.id].decision === s.expected
                                ? "Passed"
                                : "Failed"
                              : s.category}
                          </Badge>
                        </div>
                        <h3>{s.name}</h3>
                        <p>{s.description}</p>
                        <div className="scenario-expected">
                          <span>Expected outcome</span>
                          <Badge tone={toneFor(s.expected)}>{s.expected}</Badge>
                        </div>
                        {results[s.id] && (
                          <div className="scenario-result">
                            <ShieldCheck size={14} />
                            <span>
                              {results[s.id].reason}
                              <br />
                              <strong>Executed: no</strong>
                            </span>
                          </div>
                        )}
                        <Button
                          disabled={running}
                          onClick={() => runSimulation([s.id])}
                        >
                          <FlaskConical size={14} />
                          {results[s.id] ? "Run again" : "Run scenario"}
                          <ArrowUpRight size={13} />
                        </Button>
                      </div>
                    ))}
                  </div>
                </>
              )}
              {page === "Quarantine" && (
                <Panel
                  title="Isolated items"
                  description="Potentially unsafe content is never passed directly to an agent."
                >
                  {quarantined.length ? (
                    quarantined.map((q, i) => (
                      <div className="quarantine-row" key={q}>
                        <span className="integration-icon violet">
                          <Shield size={20} />
                        </span>
                        <div>
                          <h3>{q}</h3>
                          <p>
                            Detected by mock security engine · untrusted
                            provenance · {i + 2} minutes ago
                          </p>
                        </div>
                        <Badge tone="violet">Isolated</Badge>
                        <Button
                          variant="danger compact"
                          onClick={() => {
                            setQuarantined((old) =>
                              old.filter((item) => item !== q),
                            )
                            notify(
                              "Demo item permanently removed from quarantine.",
                            )
                          }}
                        >
                          Delete
                        </Button>
                        <Button
                          variant="compact"
                          onClick={() => setModal(`Release: ${q}`)}
                        >
                          Review
                        </Button>
                      </div>
                    ))
                  ) : (
                    <Empty
                      icon={ShieldCheck}
                      title="Quarantine is clear"
                      detail="No isolated items remain in this demo session."
                    />
                  )}
                </Panel>
              )}
              {page === "Settings" && (
                <>
                  <Panel
                    title="Workspace settings"
                    description="Your current environment"
                  >
                    <div className="settings-form">
                      <label>
                        Workspace name
                        <input
                          value={workspaceDraft}
                          maxLength={30}
                          onChange={(e) => setWorkspaceDraft(e.target.value)}
                        />
                      </label>
                      <label>
                        Environment
                        <input value="Local demonstration" readOnly />
                      </label>
                      <label>
                        Tenant identifier
                        <input value="tenant_acme_demo" readOnly />
                      </label>
                      <label>
                        Backend API URL
                        <input
                          placeholder="Not connected — demo data only"
                          disabled
                        />
                      </label>
                      <Button
                        variant="primary"
                        onClick={() => {
                          if (!workspaceDraft.trim()) {
                            notify("Workspace name cannot be empty.")
                            return
                          }
                          setWorkspaceName(workspaceDraft.trim())
                          notify(
                            "Demo workspace preferences saved for this session. No backend is connected.",
                          )
                        }}
                      >
                        Save preferences
                      </Button>
                    </div>
                  </Panel>
                  <Panel
                    title="Integration connections"
                    description="Shared contracts for your team’s security modules."
                  >
                    {[
                      {
                        name: "P1 — Security engine",
                        env: "P1_ENGINE",
                        contract:
                          "inspect_input · inspect_output · inspect_tool_call · calculate_risk",
                      },
                      {
                        name: "P2 — Offline adapters",
                        env: "P2_ADAPTERS",
                        contract: "precheck · execute · healthcheck · register",
                      },
                      {
                        name: "P3 — Online adapters",
                        env: "P3_ADAPTERS",
                        contract: "precheck · execute · healthcheck · register",
                      },
                    ].map((i) => (
                      <div className="settings-integration" key={i.env}>
                        <span className="integration-icon violet">
                          <Terminal size={18} />
                        </span>
                        <div>
                          <h3>{i.name}</h3>
                          <code>{i.env}</code>
                          <p>{i.contract}</p>
                        </div>
                        <Badge tone="amber">Mock</Badge>
                      </div>
                    ))}
                  </Panel>
                  <div className="notice">
                    <CircleHelp size={17} />
                    <span>
                      Backend integration is deferred. API URLs, authentication,
                      approvals, and authorization will need server-side
                      implementations before production use.
                    </span>
                  </div>
                </>
              )}
            </>
          )}
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <CircleHelp size={17} />
          <span>{toast}</span>
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
      {notifications && (
        <div className="popover notification-popover">
          <h3>
            Notifications <Badge tone="violet">{pending}</Badge>
          </h3>
          <button
            onClick={() => {
              navigate("Approval Queue")
              setNotifications(false)
            }}
          >
            <Clock3 size={18} />
            <span>
              <strong>{pending} actions need your approval</strong>
              <small>Review sensitive requests from your agents.</small>
            </span>
            <ChevronRight size={14} />
          </button>
          <button
            onClick={() => {
              navigate("Audit Logs")
              setNotifications(false)
            }}
          >
            <Shield size={18} />
            <span>
              <strong>Threat intercepted</strong>
              <small>Protected environment variable access blocked.</small>
            </span>
            <ChevronRight size={14} />
          </button>
          <div className="popover-note">
            Seeded demo notifications · all caught up
          </div>
        </div>
      )}
      {profileOpen && (
        <div className="popover profile-popover">
          <h3>Jamie Davis</h3>
          <p>admin@agentshield.demo</p>
          <Badge tone="violet">Workspace admin</Badge>
          <button
            onClick={() => {
              navigate("Settings")
              setProfileOpen(false)
            }}
          >
            <Settings2 size={15} />
            Workspace settings
          </button>
          <button
            onClick={() => {
              setLoggedIn(false)
              setProfileOpen(false)
            }}
          >
            <LogOut size={15} />
            Sign out of demo
          </button>
        </div>
      )}
      {searchOpen && (
        <Modal title="Search workspace" onClose={() => setSearchOpen(false)}>
          <div className="search-input modal-search">
            <Search size={18} />
            <input
              autoFocus
              placeholder="Search pages, agents, policies..."
              value={globalSearch}
              onChange={(e) => setGlobalSearch(e.target.value)}
            />
            <kbd>ESC</kbd>
          </div>
          <div className="search-results">
            {searchable.slice(0, 8).map((s, i) => (
              <button
                key={i}
                onClick={() => {
                  navigate(s.target)
                  setSearchOpen(false)
                  setGlobalSearch("")
                }}
              >
                <Search size={14} />
                <span>{s.title}</span>
                <small>{s.category}</small>
                <ArrowRight size={14} />
              </button>
            ))}
            {searchable.length === 0 && (
              <Empty
                icon={Search}
                title="No matches"
                detail="Try searching for an agent, policy, or page."
              />
            )}
          </div>
        </Modal>
      )}
      {selectedEvent && (
        <Modal
          title="Security event details"
          onClose={() => setSelectedEvent(null)}
        >
          <div className="detail-header">
            <Badge tone={toneFor(selectedEvent.decision)}>
              {selectedEvent.decision}
            </Badge>
            <code>{selectedEvent.id}</code>
          </div>
          <h3 className="detail-title">{selectedEvent.description}</h3>
          <div className="detail-grid">
            {Object.entries({
              Agent: selectedEvent.agent,
              Tool: selectedEvent.tool,
              "Risk score": `${selectedEvent.risk} / 100`,
              Tenant: "tenant_acme_demo",
              "Policy engine": "Local demo",
              Time: selectedEvent.time,
            }).map(([key, val]) => (
              <div key={key}>
                <span>{key}</span>
                <strong>{val}</strong>
              </div>
            ))}
          </div>
          <div className="notice">
            <ShieldCheck size={16} />
            <span>
              This is a demo event. No host tools or external services were
              executed.
            </span>
          </div>
          <div className="modal-actions">
            <Button
              onClick={() =>
                exportFile(
                  `${selectedEvent.id}.json`,
                  JSON.stringify(selectedEvent, null, 2),
                )
              }
            >
              <ArrowDownToLine size={14} />
              Export event
            </Button>
            <Button
              variant="primary"
              onClick={() => {
                navigate("Attack Simulator")
                setSelectedEvent(null)
              }}
            >
              Explore attack scenarios
              <ArrowUpRight size={14} />
            </Button>
          </div>
        </Modal>
      )}
      {selectedApproval && (
        <Modal
          title="Review requested action"
          onClose={() => setSelectedApproval(null)}
        >
          <div className="detail-header">
            <Badge tone={toneFor(selectedApproval.status)}>
              {selectedApproval.status}
            </Badge>
            <span className="text-amber">
              Risk {selectedApproval.risk} / 100
            </span>
          </div>
          <h3 className="detail-title">{selectedApproval.summary}</h3>
          <p className="muted">
            {selectedApproval.agent} · <code>{selectedApproval.tool}</code>
          </p>
          <pre className="approval-json">
            {JSON.stringify(selectedApproval.args, null, 2)}
          </pre>
          <div className="notice">
            <Shield size={15} />
            <span>
              Sensitive values are masked. Approval applies only to the exact
              demo action shown above.
            </span>
          </div>
          {selectedApproval.status === "Pending" && (
            <>
              <label className="form-label">
                Review comment (optional)
                <textarea
                  rows={3}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Add context for your decision..."
                />
              </label>
              <div className="modal-actions">
                <Button
                  variant="danger"
                  onClick={() => reviewApproval("Rejected")}
                >
                  Reject request
                </Button>
                <Button
                  variant="primary"
                  onClick={() => reviewApproval("Approved")}
                >
                  <Check size={15} />
                  Approve demo request
                </Button>
              </div>
            </>
          )}
        </Modal>
      )}
      {modal && (
        <Modal
          title={
            modal.startsWith("Policy:")
              ? "Policy details"
              : modal.startsWith("Release:")
                ? "Review quarantined item"
                : modal
          }
          onClose={() => setModal(null)}
          wide={modal === "Help & documentation"}
        >
          {modal === "Create agent" && (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                createAgent()
              }}
            >
              <p className="muted">
                Create a demo identity scoped to {workspaceName}.
              </p>
              <label className="form-label">
                Agent name
                <input
                  required
                  pattern="[a-zA-Z0-9_-]+"
                  maxLength={40}
                  placeholder="e.g. support-agent"
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                />
              </label>
              <label className="form-label">
                Role
                <Select
                  label="Agent role"
                  value={agentRole}
                  onChange={setAgentRole}
                  options={[
                    "Readonly researcher",
                    "Developer agent",
                    "Email assistant",
                    "Shopping agent",
                    "Custom",
                  ]}
                />
              </label>
              <div className="notice">
                <KeyRound size={16} />
                <span>
                  A non-functional demo key will be generated. Real API keys
                  require a backend.
                </span>
              </div>
              <div className="modal-actions">
                <Button onClick={() => setModal(null)}>Cancel</Button>
                <Button type="submit" variant="primary">
                  Create demo agent
                </Button>
              </div>
            </form>
          )}
          {(modal === "Agent created" || modal === "New demo key") && (
            <>
              <div className="success-icon">
                <Check size={25} />
              </div>
              <h3>Demo identity ready</h3>
              <p className="muted">
                This key is for interface demonstration only and cannot
                authenticate API requests.
              </p>
              <pre className="key-display">{newKey}</pre>
              <div className="modal-actions">
                <Button
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(newKey)
                      notify("Demo key copied.")
                    } catch {
                      notify(
                        "Clipboard unavailable. Select and copy the key above.",
                      )
                    }
                  }}
                >
                  Copy demo key
                </Button>
                <Button variant="primary" onClick={() => setModal(null)}>
                  Done
                </Button>
              </div>
            </>
          )}
          {["Disable agent", "Enable agent", "Rotate API key"].includes(
            modal,
          ) && (
            <>
              <p>
                Are you sure you want to{" "}
                {modal === "Rotate API key"
                  ? "rotate the demo key for"
                  : modal === "Disable agent"
                    ? "disable"
                    : "enable"}{" "}
                <strong>{selectedAgent}</strong>?
              </p>
              <div className="notice">
                <Shield size={17} />
                <span>
                  {modal === "Disable agent"
                    ? "The agent will be marked disabled in this demo. A real gateway must enforce revocation server-side."
                    : "This change affects demo state only, not real credentials or services."}
                </span>
              </div>
              <div className="modal-actions">
                <Button onClick={() => setModal(null)}>Cancel</Button>
                <Button
                  variant={modal === "Disable agent" ? "danger" : "primary"}
                  onClick={() => {
                    if (modal === "Rotate API key") {
                      setNewKey(`as_demo_${crypto.randomUUID()}`)
                      setModal("New demo key")
                    } else {
                      setAgents((old) =>
                        old.map((a) =>
                          a.name === selectedAgent
                            ? {
                                ...a,
                                status:
                                  modal === "Disable agent"
                                    ? "Disabled"
                                    : "Active",
                              }
                            : a,
                        ),
                      )
                      setModal(null)
                      notify("Agent status updated in demo.")
                    }
                  }}
                >
                  Confirm{" "}
                  {modal === "Rotate API key"
                    ? "rotation"
                    : modal === "Disable agent"
                      ? "disable"
                      : "enable"}
                </Button>
              </div>
            </>
          )}
          {modal.startsWith("Configure ") && (
            <>
              <p className="muted">
                Configure {modal.replace("Configure ", "").toLowerCase()} for{" "}
                <strong>{selectedAgent}</strong>.
              </p>
              <label className="form-label">
                Resource scope
                <input
                  value={
                    scopes[`${selectedAgent}:${modal}:scope`] ?? "/workspace/**"
                  }
                  onChange={(e) =>
                    setScopes((old) => ({
                      ...old,
                      [`${selectedAgent}:${modal}:scope`]: e.target.value,
                    }))
                  }
                />
              </label>
              <label className="form-label">
                Allowed domains / merchants
                <input
                  value={
                    scopes[`${selectedAgent}:${modal}:domains`] ??
                    "acme.example, docs.example"
                  }
                  onChange={(e) =>
                    setScopes((old) => ({
                      ...old,
                      [`${selectedAgent}:${modal}:domains`]: e.target.value,
                    }))
                  }
                />
              </label>
              {modal.includes("Payments") && (
                <label className="form-label">
                  Maximum transaction amount (USD)
                  <input
                    type="number"
                    min="0"
                    value={scopes[`${selectedAgent}:${modal}:budget`] ?? "500"}
                    onChange={(e) =>
                      setScopes((old) => ({
                        ...old,
                        [`${selectedAgent}:${modal}:budget`]: e.target.value,
                      }))
                    }
                  />
                </label>
              )}
              <div className="setting-toggle">
                <span>Require human approval</span>
                <Toggle
                  label="Require human approval"
                  checked={
                    permissions[`${selectedAgent}:${modal}:approval`] ?? true
                  }
                  onChange={() =>
                    setPermissions((old) => ({
                      ...old,
                      [`${selectedAgent}:${modal}:approval`]: !(
                        old[`${selectedAgent}:${modal}:approval`] ?? true
                      ),
                    }))
                  }
                />
              </div>
              <div className="modal-actions">
                <Button onClick={() => setModal(null)}>Close</Button>
                <Button
                  variant="primary"
                  onClick={() => {
                    setModal(null)
                    notify("Demo restrictions saved for this session.")
                  }}
                >
                  Save restrictions
                </Button>
              </div>
            </>
          )}
          {modal.startsWith("Policy:") &&
            (() => {
              const p = policies.find((p) => p.id === modal.split(": ")[1])!
              return (
                <>
                  <div className="detail-header">
                    <Badge tone={p.active ? "green" : "neutral"}>
                      {p.active ? "Active" : "Inactive"}
                    </Badge>
                    <code>
                      {p.id} · v{p.version}
                    </code>
                  </div>
                  <h3 className="detail-title">{p.name}</h3>
                  <p className="muted">{p.description}</p>
                  <pre className="approval-json">{p.rule}</pre>
                  <div className="policy-history">
                    <h3>Version history</h3>
                    {Array.from(
                      { length: p.version },
                      (_, i) => p.version - i,
                    ).map((v) => (
                      <div key={v}>
                        <span>
                          <Check size={13} />
                          Version {v}
                        </span>
                        <small>
                          {v === p.version
                            ? "Current version"
                            : "Previous revision"}
                        </small>
                        {v < p.version && (
                          <Button
                            variant="compact"
                            onClick={() => {
                              setPolicies((old) =>
                                old.map((item) =>
                                  item.id === p.id
                                    ? { ...item, version: v }
                                    : item,
                                ),
                              )
                              notify(`Demo policy rolled back to version ${v}.`)
                            }}
                          >
                            Roll back
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                  <div className="modal-actions">
                    <Button
                      variant={p.active ? "danger" : "primary"}
                      onClick={() => {
                        setPolicies((old) =>
                          old.map((item) =>
                            item.id === p.id
                              ? { ...item, active: !item.active }
                              : item,
                          ),
                        )
                        setModal(null)
                        notify(
                          `Demo policy ${
                            p.active ? "deactivated" : "activated"
                          }.`,
                        )
                      }}
                    >
                      {p.active ? "Deactivate policy" : "Activate policy"}
                    </Button>
                  </div>
                </>
              )
            })()}
          {modal === "Create policy" && (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                const form = new FormData(e.currentTarget)
                setPolicies((old) => [
                  ...old,
                  {
                    id: `pol_${crypto.randomUUID().slice(0, 6)}`,
                    name: String(form.get("name")),
                    description: String(form.get("description")),
                    category: "Custom policy",
                    version: 1,
                    active: false,
                    rule: String(form.get("rule")),
                  },
                ])
                setModal(null)
                notify(
                  "Draft demo policy created. It does not affect the evaluator.",
                )
              }}
            >
              <label className="form-label">
                Policy name
                <input
                  name="name"
                  required
                  placeholder="Give your policy a clear name"
                />
              </label>
              <label className="form-label">
                Description
                <input
                  name="description"
                  required
                  placeholder="What should this policy protect?"
                />
              </label>
              <label className="form-label">
                Rule definition
                <textarea
                  name="rule"
                  required
                  rows={4}
                  placeholder="DENY when ..."
                />
              </label>
              <div className="notice">
                <CircleHelp size={16} />
                <span>
                  Custom rules are saved as demo drafts. They are not executable
                  Rego policies.
                </span>
              </div>
              <div className="modal-actions">
                <Button type="submit" variant="primary">
                  Create draft
                </Button>
              </div>
            </form>
          )}
          {modal === "Audit integrity" && (
            <>
              <div className="integration-icon amber">
                <Shield size={24} />
              </div>
              <h3 className="detail-title">Backend verification required</h3>
              <p className="muted">
                This demo displays seeded and session-generated events. A
                cryptographic hash chain and durable append-only storage have
                not been implemented. Connect the backend to enable real
                integrity verification.
              </p>
              <div className="detail-grid">
                <div>
                  <span>Events in session</span>
                  <strong>{events.length}</strong>
                </div>
                <div>
                  <span>Verification status</span>
                  <Badge tone="amber">Not verified</Badge>
                </div>
              </div>
            </>
          )}
          {modal === "Workspace" && (
            <>
              <div className="workspace-option">
                <span className="workspace-avatar">A</span>
                <div>
                  <strong>{workspaceName}</strong>
                  <p>Enterprise · Demo environment</p>
                </div>
                <Check size={18} />
              </div>
              <div className="notice">
                <Globe size={17} />
                <span>
                  One seeded tenant is available. Multi-tenant isolation
                  requires a connected backend.
                </span>
              </div>
            </>
          )}
          {modal === "Help & documentation" && (
            <>
              <p className="muted">
                AgentShield is a runtime security gateway for AI agents. This
                frontend is a standalone demonstration of the Platform &
                Enforcement module.
              </p>
              <div className="help-grid">
                <div>
                  <ShieldCheck size={22} />
                  <h3>Every action, authorized</h3>
                  <p>
                    The intended gateway checks identity, schema, permissions,
                    risk, and policy before allowing a tool to execute.
                  </p>
                </div>
                <div>
                  <Users size={22} />
                  <h3>Built for your team</h3>
                  <p>
                    P1 supplies security inspection, P2 supplies isolated
                    offline tools, and P3 supplies online adapters.
                  </p>
                </div>
                <div>
                  <FlaskConical size={22} />
                  <h3>Safely simulated</h3>
                  <p>
                    The ten attack scenarios use local deterministic rules. No
                    host files, secrets, or external services are accessed.
                  </p>
                </div>
                <div>
                  <KeyRound size={22} />
                  <h3>Demo sign-in</h3>
                  <p>
                    admin@agentshield.demo
                    <br />
                    demo-password
                    <br />
                    For UI demonstration only.
                  </p>
                </div>
              </div>
              <div className="notice">
                <BookOpen size={17} />
                <span>
                  Project notes are in agentshield/README.md and
                  BUILD_STATUS.md. All demo state resets when the page reloads.
                </span>
              </div>
            </>
          )}
          {modal.startsWith("Release:") && (
            <>
              <h3>{modal.replace("Release: ", "")}</h3>
              <pre className="approval-json">
                [CONTENT WITHHELD BY MOCK SECURITY ENGINE]
              </pre>
              <div className="notice">
                <Shield size={17} />
                <span>
                  Untrusted content remains isolated. In production, release
                  must require authorization and a fresh security inspection.
                </span>
              </div>
              <div className="modal-actions">
                <Button onClick={() => setModal(null)}>Keep isolated</Button>
                <Button
                  variant="danger"
                  onClick={() => {
                    const item = modal.replace("Release: ", "")
                    setQuarantined((old) => old.filter((q) => q !== item))
                    setModal(null)
                    notify(
                      "Demo item removed from isolation. No content was sent to an agent.",
                    )
                  }}
                >
                  Release demo item
                </Button>
              </div>
            </>
          )}
        </Modal>
      )}
    </div>
  )
}
