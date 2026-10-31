import { useEffect, useRef, useState } from "react"
import {
  Activity,
  AlertCircle,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Bell,
  BookOpen,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Circle,
  CircleHelp,
  Clock,
  Clock3,
  FileCheck2,
  FileText,
  FlaskConical,
  Globe,
  HelpCircle,
  KeyRound,
  LayoutDashboard,
  Loader2,
  LogOut,
  Menu,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Square,
  Terminal,
  Trash2,
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
import { LiveExecution, EvidenceExplorer, ReportViewer } from "./components/CyberRange"
import Overview from "./pages/Overview"
import BrowserSessions from "./pages/BrowserSessions"
import {
  capabilities,
  exportFile,
  initialAgents,
  initialApprovals,
  initialEvents,
  policies as policySeed,
  scenarios as demoScenarios,
  simulate,
  type Agent,
  type Approval,
  type AuditEvent,
} from "./services/demo"
import {
  ApiError,
  apiBaseUrl,
  approveRequest as approveRequestApi,
  autoConnectBackend,
  clearSession,
  createAgent as createAgentApi,
  createPolicy as createPolicyApi,
  downloadAudit,
  getAgents as getAgentsApi,
  getApprovals as getApprovalsApi,
  getCyberRangeScenarios as getCyberRangeScenariosApi,
  createCampaign as createCampaignApi,
  listCampaigns as listCampaignsApi,
  getCampaign as getCampaignApi,
  cancelCampaign as cancelCampaignApi,
  getCampaignReport as getCampaignReportApi,
  getSimulation as getSimulationApi,
  getSimulationEvidence as getSimulationEvidenceApi,
  streamSimulationEvents as streamSimulationEventsApi,
  streamCampaignEvents as streamCampaignEventsApi,
  runSingleScenario as runSingleScenarioApi,
  getAttackScenarios as getAttackScenariosApi,
  getAudit as getAuditApi,
  getOverviewStats,
  getPolicies as getPoliciesApi,
  getQuarantine as getQuarantineApi,
  getWorkspace as getWorkspaceApi,
  hasStoredSession,
  login as loginApi,
  loginDemoBackend,
  logout as logoutApi,
  rejectRequest as rejectRequestApi,
  releaseQuarantine as releaseQuarantineApi,
  restoreSession,
  rotateAgentKey as rotateAgentKeyApi,
  runSimulator as runSimulatorApi,
  triggerDownload,
  updateAgent as updateAgentApi,
  updatePolicy as updatePolicyApi,
  updateWorkspace as updateWorkspaceApi,
  verifyAudit as verifyAuditApi,
  type AgentRecord,
  type AuditVerification,
  type OverviewStats,
  type PolicyRecord,
  type SessionUser,
} from "./services/api"

const navigation = [
  { title: "Overview", icon: LayoutDashboard },
  { title: "Agents", icon: Users },
  { title: "Browser Sessions", icon: Globe },
  { title: "Capabilities & Permissions", icon: SlidersHorizontal },
  { title: "Policy Manager", icon: ShieldCheck },
  { title: "Approval Queue", icon: FileCheck2 },
  { title: "Audit Logs", icon: Activity },
  { title: "Attack Simulator", icon: FlaskConical },
]
const pageDescriptions: Record<string, string> = {
  Agents: "Manage identities, access, and the lifecycle of your browser agents.",
  "Browser Sessions":
    "Launch a governed browser, navigate destinations, and watch policy enforcement in real time.",
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
const capabilityPermissions: Record<string, string[]> = {
  documents: ["documents.read"],
  local_files: ["local_files.read", "files.delete"],
  system_files: ["system_files.read"],
  environment: ["environment.read"],
  terminal: ["terminal.run"],
  browser: ["browser.read"],
  email: ["email.send"],
  dlp: ["dlp.export"],
  downloads: ["downloads.write"],
  payments: ["payments.execute"],
  external_api: ["external_api.call", "mcp.call"],
}
const rangePeriods: Record<string, "24h" | "7d" | "30d"> = {
  "Last 24 hours": "24h",
  "Last 7 days": "7d",
  "Last 30 days": "30d",
}
function errorMessage(error: unknown) {
  return error instanceof ApiError || error instanceof Error
    ? error.message
    : "AgentShield API request failed"
}

export default function App() {
  const [page, setPage] = useState("Overview")
  const [workspaceName, setWorkspaceName] = useState("Acme workspace")
  const [workspaceDraft, setWorkspaceDraft] = useState("Acme workspace")
  const [agents, setAgents] = useState<AgentRecord[]>(initialAgents)
  const [events, setEvents] = useState<AuditEvent[]>(initialEvents)
  const [approvals, setApprovals] = useState<Approval[]>(initialApprovals)
  const [policies, setPolicies] = useState<PolicyRecord[]>(policySeed)
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
    { id: "demo-0", label: "Untrusted webpage content" },
    { id: "demo-1", label: "Suspicious PDF attachment" },
    { id: "demo-2", label: "Unverified download" },
  ])
  const [approvalTab, setApprovalTab] = useState("Pending")
  const [loggedIn, setLoggedIn] = useState(false)
  const [loginEmail, setLoginEmail] = useState("admin@agentshield.dev")
  const [loginPassword, setLoginPassword] = useState("admin-change-me")
  const [loginError, setLoginError] = useState("")
  const [backendMode, setBackendMode] = useState(false)
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null)
  const [stats, setStats] = useState<OverviewStats | null>(null)
  const [auditVerification, setAuditVerification] =
    useState<AuditVerification | null>(null)
  const [attackScenarios, setAttackScenarios] = useState<Array<{ id: string; name: string; description: string; category: string }>>([])
  const [cyberRangeScenarios, setCyberRangeScenarios] = useState<Array<any>>([])
  const [campaigns, setCampaigns] = useState<any[]>([])
  const [selectedCampaign, setSelectedCampaign] = useState<any | null>(null)
  const [campaignSimulations, setCampaignSimulations] = useState<any[]>([])
  const [liveExecutionOpen, setLiveExecutionOpen] = useState(false)
  const [evidenceExplorerOpen, setEvidenceExplorerOpen] = useState(false)
  const [evidenceSimulationId, setEvidenceSimulationId] = useState<string | null>(null)
  const [reportViewerOpen, setReportViewerOpen] = useState(false)
  const [campaignReport, setCampaignReport] = useState<any>(null)
  const [creatingCampaign, setCreatingCampaign] = useState(false)
  const [newCampaignName, setNewCampaignName] = useState("")
  const [selectedScenarios, setSelectedScenarios] = useState<string[]>([])
  const pending = approvals.filter((a) => a.status === "Pending").length
  const selectedAgentRecord = agents.find(
    (agent) => agent.name === selectedAgent,
  )
  const activeScenarios = backendMode ? attackScenarios : demoScenarios
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
  function resetDemoState() {
    setAgents(initialAgents)
    setEvents(initialEvents)
    setApprovals(initialApprovals)
    setPolicies(policySeed)
    setQuarantined([
      { id: "demo-0", label: "Untrusted webpage content" },
      { id: "demo-1", label: "Suspicious PDF attachment" },
      { id: "demo-2", label: "Unverified download" },
    ])
    setWorkspaceName("Acme workspace")
    setWorkspaceDraft("Acme workspace")
    setStats(null)
    setAuditVerification(null)
    setPermissions({})
    setScopes({})
    setResults({})
  }
  async function loadBackendData(user?: SessionUser | null) {
    const [agentList, approvalList, auditResult, policyList, quarantineList, workspace, scenarios] =
      await Promise.all([
        getAgentsApi(),
        getApprovalsApi(),
        getAuditApi(),
        getPoliciesApi(),
        getQuarantineApi(),
        getWorkspaceApi(),
        getAttackScenariosApi(),
      ])
    setAgents(agentList)
    if (!agentList.some((agent) => agent.name === selectedAgent)) {
      setSelectedAgent(agentList[0]?.name || "research-agent")
    }
    setApprovals(approvalList)
    setEvents(auditResult.items)
    setPolicies(policyList)
    setQuarantined(
      quarantineList.map((item) => ({
        id: item.id,
        label: item.preview || item.reason || item.tool,
      })),
    )
    setAttackScenarios(scenarios)
    setWorkspaceName(workspace.name)
    // Load cyber-range scenarios
    try {
      const crScenarios = await getCyberRangeScenariosApi()
      setCyberRangeScenarios(crScenarios)
    } catch {
      setCyberRangeScenarios([])
    }
    // Load campaigns
    try {
      const campaignList = await listCampaignsApi()
      setCampaigns(campaignList)
    } catch {
      setCampaigns([])
    }
    setWorkspaceDraft(workspace.name)
    if (user) setSessionUser(user)
    setBackendMode(true)
  }
  async function refreshAudit() {
    if (!backendMode) return
    try {
      const result = await getAuditApi()
      setEvents(result.items)
    } catch {
      // Keep the last known audit view when a refresh fails.
    }
  }
  useEffect(() => {
    let cancelled = false
    async function bootstrap() {
      let user: SessionUser | null = await restoreSession()
      if (!user && autoConnectBackend) {
        try {
          user = (await loginDemoBackend()).user
        } catch {
          user = null
        }
      }
      if (!user || cancelled) return
      try {
        await loadBackendData(user)
      } catch {
        if (!cancelled) {
          clearSession()
          setBackendMode(false)
          setSessionUser(null)
        }
      }
    }
    bootstrap()
    return () => {
      cancelled = true
    }
  }, [])
  useEffect(() => {
    if (!backendMode) {
      setStats(null)
      return
    }
    let cancelled = false
    getOverviewStats(rangePeriods[range] || "24h")
      .then((result) => {
        if (!cancelled) setStats(result)
      })
      .catch(() => {
        if (!cancelled) setStats(null)
      })
    return () => {
      cancelled = true
    }
  }, [backendMode, range])
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
  async function reviewApproval(status: string) {
    if (!selectedApproval) return
    if (backendMode) {
      try {
        if (status === "Approved") {
          await approveRequestApi(selectedApproval.id, comment)
        } else {
          await rejectRequestApi(selectedApproval.id, comment)
        }
        const [approvalList, auditResult] = await Promise.all([
          getApprovalsApi(),
          getAuditApi(),
        ])
        setApprovals(approvalList)
        setEvents(auditResult.items)
        setSelectedApproval(null)
        setComment("")
        notify(
          status === "Approved"
            ? "Request approved. A single-use token was issued; no tool was executed."
            : "Request rejected. The agent cannot use this action.",
        )
      } catch (error) {
        notify(errorMessage(error))
      }
      return
    }
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
    if (backendMode) {
      try {
        const response = await runSimulatorApi(ids)
        const next: Record<string, ReturnType<typeof simulate>> = {}
        for (const item of response.items) {
          next[item.id] = {
            decision: item.actual as AuditEvent["decision"],
            reason: item.reason,
            executed: item.executed,
          }
        }
        setResults((old) => ({ ...old, ...next }))
        await refreshAudit()
        notify(
          `${response.passed} of ${response.total} scenarios passed. No real tools were executed.`,
        )
      } catch (error) {
        notify(errorMessage(error))
      } finally {
        setRunning(false)
      }
      return
    }
    for (const id of ids) {
      await new Promise((resolve) => setTimeout(resolve, 230))
      const scenario = activeScenarios.find((s) => s.id === id)!
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
  async function createAgent() {
    if (!agentName.trim()) return
    if (agents.some((a) => a.name === agentName.trim())) {
      notify("An agent with this name already exists.")
      return
    }
    if (backendMode) {
      try {
        const result = await createAgentApi(agentName.trim(), agentRole)
        const created = {
          ...result.agent,
          color: "violet",
          initials: agentName.slice(0, 2).toUpperCase(),
        }
        setAgents((old) => [...old, created])
        setAgentName("")
        setNewKey(result.api_key)
        setModal("Agent created")
        notify("Agent created. API key issued once.")
      } catch (error) {
        notify(errorMessage(error))
      }
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
  function capabilityEnabled(key: string, index: number) {
    const stateKey = `${selectedAgent}:${key}`
    if (permissions[stateKey] !== undefined) return permissions[stateKey]
    if (backendMode && selectedAgentRecord?.permissions) {
      return capabilityPermissions[key].every((permission) =>
        selectedAgentRecord.permissions!.includes(permission),
      )
    }
    return [0, 1, 5, 7].includes(index)
  }
  async function saveCapability(
    capabilityKey: string,
    capabilityName: string,
    enabled: boolean,
  ) {
    const stateKey = `${selectedAgent}:${capabilityKey}`
    setPermissions((old) => ({ ...old, [stateKey]: enabled }))
    notify(
      `${capabilityName} ${enabled ? "enabled" : "disabled"} for ${selectedAgent}.`,
    )
    if (!backendMode || !selectedAgentRecord) return
    const required = capabilityPermissions[capabilityKey]
    const current = selectedAgentRecord.permissions || []
    const next = enabled
      ? Array.from(new Set([...current, ...required]))
      : current.filter((permission) => !required.includes(permission))
    try {
      const updated = await updateAgentApi(selectedAgentRecord.id, {
        permissions: next,
      })
      setAgents((old) =>
        old.map((agent) =>
          agent.id === updated.id
            ? {
                ...agent,
                ...updated,
                color: agent.color,
                initials: agent.initials,
              }
            : agent,
        ),
      )
    } catch (error) {
      setPermissions((old) => ({ ...old, [stateKey]: !enabled }))
      notify(errorMessage(error))
    }
  }
  async function changeAgentStatus(agent: Agent, status: "Active" | "Disabled") {
    if (!backendMode) {
      setAgents((old) =>
        old.map((item) =>
          item.id === agent.id ? { ...item, status } : item,
        ),
      )
      notify("Agent status updated in demo.")
      return
    }
    try {
      const updated = await updateAgentApi(agent.id, { status })
      setAgents((old) =>
        old.map((item) =>
          item.id === updated.id
            ? {
                ...item,
                ...updated,
                color: item.color,
                initials: item.initials,
              }
            : item,
        ),
      )
      notify(`Agent ${status === "Active" ? "enabled" : "disabled"}.`)
    } catch (error) {
      notify(errorMessage(error))
    }
  }
  async function rotateKey(agent: Agent) {
    if (!backendMode) {
      setNewKey(`as_demo_${crypto.randomUUID()}`)
      setModal("New demo key")
      return
    }
    try {
      const result = await rotateAgentKeyApi(agent.id)
      setNewKey(result.api_key)
      setModal("New API key")
      notify("Agent API key rotated. The previous key is revoked.")
    } catch (error) {
      notify(errorMessage(error))
    }
  }
  async function releaseQuarantinedItem(id: string, comment: string) {
    if (backendMode && !id.startsWith("demo-")) {
      try {
        await releaseQuarantineApi(id, comment)
      } catch (error) {
        notify(errorMessage(error))
        return false
      }
    }
    setQuarantined((old) => old.filter((item) => item.id !== id))
    return true
  }
  async function verifyAuditChain() {
    if (backendMode) {
      try {
        setAuditVerification(await verifyAuditApi())
      } catch (error) {
        notify(errorMessage(error))
      }
    } else {
      setAuditVerification(null)
    }
    setModal("Audit integrity")
  }
  async function exportAudit(format: "json" | "csv") {
    if (backendMode) {
      try {
        const blob = await downloadAudit(format)
        triggerDownload(blob, `agentshield-audit.${format}`)
        notify("Sanitized audit export downloaded.")
      } catch (error) {
        notify(errorMessage(error))
      }
      return
    }
    if (format === "json") {
      exportFile(
        "agentshield-audit.json",
        JSON.stringify(visibleEvents, null, 2),
      )
      return
    }
    exportFile(
      "agentshield-audit.csv",
      "id,agent,tool,decision,risk,time\n" +
        visibleEvents
          .map((event) =>
            [
              event.id,
              event.agent,
              event.tool,
              event.decision,
              event.risk,
              event.time,
            ].join(","),
          )
          .join("\n"),
      "text/csv",
    )
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
    ...policies.map((p) => ({
      title: p.name,
      category: "Policy",
      target: "Policy Manager",
    })),
  ].filter((s) => s.title.toLowerCase().includes(globalSearch.toLowerCase()))
  async function handleLogin() {
    setLoginError("")
    try {
      const result = await loginApi(loginEmail, loginPassword)
      await loadBackendData(result.user)
      setLoggedIn(true)
      notify("Connected to the AgentShield backend.")
      return
    } catch (error) {
      clearSession()
      setLoginError(errorMessage(error))
    }
  }
  async function signOut() {
    if (backendMode) {
      try {
        await logoutApi()
      } catch {
        clearSession()
      }
    }
    setBackendMode(false)
    setSessionUser(null)
    resetDemoState()
    setLoggedIn(false)
    setProfileOpen(false)
    setLoginPassword("")
  }

  if (!loggedIn)
    return (
      <div className="login-page">
        <div className="login-card">
          <div className="brand-mark">
            <Shield size={26} />
          </div>
          <Badge tone="violet">SECURE WORKSPACE</Badge>
          <h1>Welcome to AgentShield</h1>
          <p>A safer boundary for every agent.</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              handleLogin()
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
              Sign in
              <ArrowRight size={16} />
            </Button>
          </form>
          <div className="demo-login-note">
            Development workspace seeded by scripts/seed_dev.py
            <br />
            <code>admin@agentshield.dev</code>
            <br />
            <code>admin-change-me</code>
          </div>
        </div>
      </div>
    )

  const quarantinedItem = modal?.startsWith("Release: ")
    ? quarantined.find((item) => item.id === modal.replace("Release: ", ""))
    : undefined

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
              <strong>
                {backendMode ? "Gateway connected" : "Demo gateway ready"}
              </strong>
              <ShieldCheck size={14} />
            </div>
            <p>Every action. Authorized.</p>
            <span>
              {backendMode ? "LIVE MODE" : "DEMO MODE"} <i />
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
              <strong>{sessionUser?.email || "Jamie Davis"}</strong>
              <small>{sessionUser?.role || "Workspace admin"}</small>
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
            <span className="demo-indicator">
              {backendMode ? "Live backend" : "Demo data"}
            </span>
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
              stats={stats}
              connected={backendMode}
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
                      onClick={() => runSimulation(activeScenarios.map((s) => s.id))}
                    >
                      <Zap size={16} />
                      {running ? "Running scenarios…" : "Run all scenarios"}
                    </Button>
                  ) : page === "Audit Logs" ? (
                    <>
                      <Button onClick={() => verifyAuditChain()}>
                        <ShieldCheck size={15} />
                        Verify integrity
                      </Button>
                      <Button onClick={() => exportAudit("json")}>
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
              {page === "Browser Sessions" && (
                <BrowserSessions
                  agents={agents}
                  events={events}
                  notify={notify}
                  onRefreshAudit={refreshAudit}
                />
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
                      . Missing permissions deny access.{" "}
                      {backendMode
                        ? "Changes are persisted to the connected backend."
                        : "Changes are local to this demo."}
                    </span>
                  </div>
                  <div className="capability-grid">
                    {capabilities.map((c, i) => {
                      const key = `${selectedAgent}:${c.key}`
                      const enabled = capabilityEnabled(c.key, i)
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
                              onChange={() =>
                                saveCapability(c.key, c.name, !enabled)
                              }
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
                      Engine{" "}
                      <strong>
                        {backendMode
                          ? "Server-side policy engine"
                          : "Local demo evaluator"}
                      </strong>
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
                      {backendMode
                        ? "Policy state is stored by the backend. Baseline security policies remain immutable; custom drafts are not executable Rego."
                        : "Policy changes here demonstrate UI behavior only. OPA and server-side policy enforcement are not connected."}
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
                      Review the exact requested action before approving.{" "}
                      {backendMode
                        ? "Approval issues a single-use token; the tool is not executed automatically."
                        : "Demo reviews do not execute a real tool."}
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
                  description={`${visibleEvents.length} events · ${backendMode ? "live backend" : "demo session"}`}
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
                    <Button onClick={() => exportAudit("csv")}>
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
                        {backendMode
                          ? "These scenarios run through the real gateway with mock adapters. No host files are read, emails sent, or payments made."
                          : "These scenarios run through a local demo evaluator. No files are read, emails sent, or payments made."}
                      </p>
                    </div>
                    <Badge tone="violet">SANDBOX</Badge>
                  </div>
                  <div className="summary-strip">
                    <div>
                      <FlaskConical size={17} />
                      <strong>{activeScenarios.length}</strong>Attack scenarios
                    </div>
                    <div>
                      <Check size={17} />
                      <strong>
                        {
                          Object.entries(results).filter(
                            ([id, r]) => {
                              const scenario = activeScenarios.find((s) => s.id === id)
                              const expected = backendMode ? undefined : (scenario as typeof demoScenarios[number] | undefined)?.expected
                              return expected !== undefined && r.decision === expected && !r.executed
                            },
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
                    {activeScenarios.map((s, i) => {
                      const isDemo = !backendMode
                      const expected = isDemo ? (s as typeof demoScenarios[number]).expected : undefined
                      const category = isDemo ? (s as typeof demoScenarios[number]).category : s.category
                      return (
                        <div className="panel scenario-card" key={s.id}>
                          <div className="scenario-top">
                            <span className="scenario-number">
                              {String(i + 1).padStart(2, "0")}
                            </span>
                            <Badge
                              tone={
                                results[s.id]
                                  ? results[s.id].decision === expected
                                    ? "green"
                                    : "red"
                                  : "neutral"
                              }
                            >
                              {results[s.id]
                                ? results[s.id].decision === expected
                                  ? "Passed"
                                  : "Failed"
                                : category}
                            </Badge>
                          </div>
                          <h3>{s.name}</h3>
                          <p>{s.description}</p>
                          {isDemo && expected && (
                            <div className="scenario-expected">
                              <span>Expected outcome</span>
                              <Badge tone={toneFor(expected)}>{expected}</Badge>
                            </div>
                          )}
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
                      )
                    })}
                  </div>
                </>
              )}
              {page === "Quarantine" && (
                <Panel
                  title="Isolated items"
                  description="Potentially unsafe content is never passed directly to an agent."
                >
                  {quarantined.length ? (
                    quarantined.map((item, i) => (
                      <div className="quarantine-row" key={item.id}>
                        <span className="integration-icon violet">
                          <Shield size={20} />
                        </span>
                        <div>
                          <h3>{item.label}</h3>
                          <p>
                            Detected by mock security engine · untrusted
                            provenance · {i + 2} minutes ago
                          </p>
                        </div>
                        <Badge tone="violet">Isolated</Badge>
                        <Button
                          variant="danger compact"
                          onClick={async () => {
                            const released = await releaseQuarantinedItem(
                              item.id,
                              "Removed from quarantine view by an administrator.",
                            )
                            if (released) {
                              notify(
                                backendMode
                                  ? "Quarantined item released. No content was sent to an agent."
                                  : "Demo item permanently removed from quarantine.",
                              )
                            }
                          }}
                        >
                          Delete
                        </Button>
                        <Button
                          variant="compact"
                          onClick={() => setModal(`Release: ${item.id}`)}
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
                        <input
                          value={
                            backendMode
                              ? "Connected backend"
                              : "Local demonstration"
                          }
                          readOnly
                        />
                      </label>
                      <label>
                        Tenant identifier
                        <input
                          value={sessionUser?.tenant_id || "tenant_acme_demo"}
                          readOnly
                        />
                      </label>
                      <label>
                        Backend API URL
                        <input
                          value={backendMode ? apiBaseUrl : ""}
                          placeholder="Not connected — demo data only"
                          readOnly
                        />
                      </label>
                      <Button
                        variant="primary"
                        onClick={async () => {
                          if (!workspaceDraft.trim()) {
                            notify("Workspace name cannot be empty.")
                            return
                          }
                          if (backendMode) {
                            try {
                              const workspace = await updateWorkspaceApi(
                                workspaceDraft.trim(),
                              )
                              setWorkspaceName(workspace.name)
                              setWorkspaceDraft(workspace.name)
                              notify("Workspace preferences saved.")
                            } catch (error) {
                              notify(errorMessage(error))
                            }
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
            {backendMode
              ? "Live approval notifications · all caught up"
              : "Seeded demo notifications · all caught up"}
          </div>
        </div>
      )}
      {profileOpen && (
        <div className="popover profile-popover">
          <h3>{sessionUser?.email?.split("@")[0] || "Jamie Davis"}</h3>
          <p>{sessionUser?.email || "admin@agentshield.demo"}</p>
          <Badge tone="violet">
            {sessionUser?.role || "Workspace admin"}
          </Badge>
          <button
            onClick={() => {
              navigate("Settings")
              setProfileOpen(false)
            }}
          >
            <Settings2 size={15} />
            Workspace settings
          </button>
          <button onClick={signOut}>
            <LogOut size={15} />
            {backendMode ? "Sign out" : "Sign out of demo"}
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
              Tenant: sessionUser?.tenant_id || "tenant_acme_demo",
              "Policy engine": backendMode ? "Server-side policy" : "Local demo",
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
              {backendMode
                ? "This event is from the live gateway audit log. Blocked requests never reached an adapter."
                : "This is a demo event. No host tools or external services were executed."}
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
              action shown above and cannot be reused.
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
                  {backendMode ? "Approve request" : "Approve demo request"}
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
                {backendMode
                  ? `Create an identity scoped to ${workspaceName} and the current tenant.`
                  : `Create a demo identity scoped to ${workspaceName}.`}
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
                  {backendMode
                    ? "A scoped API key will be issued once. Store it securely."
                    : "A non-functional demo key will be generated. Real API keys require a backend."}
                </span>
              </div>
              <div className="modal-actions">
                <Button onClick={() => setModal(null)}>Cancel</Button>
                <Button type="submit" variant="primary">
                  {backendMode ? "Create agent" : "Create demo agent"}
                </Button>
              </div>
            </form>
          )}
          {(modal === "Agent created" ||
            modal === "New demo key" ||
            modal === "New API key") && (
            <>
              <div className="success-icon">
                <Check size={25} />
              </div>
              <h3>{backendMode ? "Identity ready" : "Demo identity ready"}</h3>
              <p className="muted">
                {backendMode
                  ? "Store this key once. It cannot be retrieved again."
                  : "This key is for interface demonstration only and cannot authenticate API requests."}
              </p>
              <pre className="key-display">{newKey}</pre>
              <div className="modal-actions">
                <Button
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(newKey)
                      notify(
                        backendMode ? "API key copied." : "Demo key copied.",
                      )
                    } catch {
                      notify(
                        "Clipboard unavailable. Select and copy the key above.",
                      )
                    }
                  }}
                >
                  {backendMode ? "Copy API key" : "Copy demo key"}
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
                  ? backendMode
                    ? "rotate the API key for"
                    : "rotate the demo key for"
                  : modal === "Disable agent"
                    ? "disable"
                    : "enable"}{" "}
                <strong>{selectedAgent}</strong>?
              </p>
              <div className="notice">
                <Shield size={17} />
                <span>
                  {backendMode
                    ? modal === "Disable agent"
                      ? "The gateway will reject every request from this agent immediately."
                      : "The previous credential is revoked before the new key is issued."
                    : modal === "Disable agent"
                      ? "The agent will be marked disabled in this demo. A real gateway must enforce revocation server-side."
                      : "This change affects demo state only, not real credentials or services."}
                </span>
              </div>
              <div className="modal-actions">
                <Button onClick={() => setModal(null)}>Cancel</Button>
                <Button
                  variant={modal === "Disable agent" ? "danger" : "primary"}
                  onClick={() => {
                    const agent = agents.find(
                      (item) => item.name === selectedAgent,
                    )
                    if (!agent) return
                    if (modal === "Rotate API key") {
                      rotateKey(agent)
                    } else {
                      setModal(null)
                      changeAgentStatus(
                        agent,
                        modal === "Disable agent" ? "Disabled" : "Active",
                      )
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
                  onClick={async () => {
                    if (!backendMode || !selectedAgentRecord) {
                      setModal(null)
                      notify("Demo restrictions saved for this session.")
                      return
                    }
                    const pathValue =
                      scopes[`${selectedAgent}:${modal}:scope`] ??
                      "/workspace/**"
                    const domainValue =
                      scopes[`${selectedAgent}:${modal}:domains`] ??
                      "acme.example, docs.example"
                    const nextScopes: Record<string, unknown> = {
                      ...(selectedAgentRecord.scopes || {}),
                      allowed_paths: pathValue
                        .split(",")
                        .map((item) => item.trim())
                        .filter(Boolean),
                      allowed_domains: domainValue
                        .split(",")
                        .map((item) => item.trim())
                        .filter(Boolean),
                    }
                    if (modal.includes("Payments")) {
                      nextScopes.payment_budget = Number(
                        scopes[`${selectedAgent}:${modal}:budget`] ?? "500",
                      )
                    }
                    try {
                      const updated = await updateAgentApi(
                        selectedAgentRecord.id,
                        { scopes: nextScopes },
                      )
                      setAgents((old) =>
                        old.map((agent) =>
                          agent.id === updated.id
                            ? {
                                ...agent,
                                ...updated,
                                color: agent.color,
                                initials: agent.initials,
                              }
                            : agent,
                        ),
                      )
                      setModal(null)
                      notify("Agent restrictions saved to the gateway.")
                    } catch (error) {
                      notify(errorMessage(error))
                    }
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
                              if (backendMode) {
                                notify(
                                  "Version rollback is not exposed by the connected policy API.",
                                )
                                return
                              }
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
                      disabled={p.immutable}
                      onClick={async () => {
                        if (p.immutable) {
                          notify("Baseline security policies cannot be disabled.")
                          return
                        }
                        if (backendMode) {
                          try {
                            const updated = await updatePolicyApi(
                              p.id,
                              !p.active,
                            )
                            setPolicies((old) =>
                              old.map((item) =>
                                item.id === p.id
                                  ? { ...item, ...updated }
                                  : item,
                              ),
                            )
                            setModal(null)
                            notify(
                              `Policy ${updated.active ? "activated" : "deactivated"}.`,
                            )
                          } catch (error) {
                            notify(errorMessage(error))
                          }
                          return
                        }
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
                      {p.immutable
                        ? "Baseline policy enforced"
                        : p.active
                          ? "Deactivate policy"
                          : "Activate policy"}
                    </Button>
                  </div>
                </>
              )
            })()}
          {modal === "Create policy" && (
            <form
              onSubmit={async (e) => {
                e.preventDefault()
                const form = new FormData(e.currentTarget)
                const splitDomains = (value: FormDataEntryValue | null) =>
                  String(value || "")
                    .split(/[,\s]+/)
                    .map((item) => item.trim())
                    .filter(Boolean)
                const draft = {
                  name: String(form.get("name")),
                  description: String(form.get("description")),
                  category: "Browser egress",
                  allowed_domains: splitDomains(form.get("allowed_domains")),
                  blocked_domains: splitDomains(form.get("blocked_domains")),
                  default_domain_policy: String(
                    form.get("default_domain_policy") || "deny",
                  ) as "allow" | "deny",
                  allowed_ports: splitDomains(form.get("allowed_ports")),
                  allow_private_networks:
                    form.get("allow_private_networks") === "on",
                  is_default: false,
                }
                if (backendMode) {
                  try {
                    const created = await createPolicyApi(draft)
                    setPolicies((old) => [...old, created])
                    setModal(null)
                    notify(
                      "Policy created and enforced by the database policy engine.",
                    )
                  } catch (error) {
                    notify(errorMessage(error))
                  }
                  return
                }
                setPolicies((old) => [
                  ...old,
                  {
                    id: `pol_${crypto.randomUUID().slice(0, 6)}`,
                    ...draft,
                    rule: `default: ${draft.default_domain_policy}\nallowed: ${draft.allowed_domains.join(", ") || "(none)"}\nblocked: ${draft.blocked_domains.join(", ") || "(none)"}`,
                    version: 1,
                    active: true,
                  },
                ])
                setModal(null)
                notify(
                  "Demo policy created. Connect the backend to enforce it.",
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
                Allowed domains
                <input
                  name="allowed_domains"
                  placeholder="example.com, docs.example.org"
                  defaultValue="example.com"
                />
              </label>
              <label className="form-label">
                Blocked domains
                <input
                  name="blocked_domains"
                  placeholder="blocked.example, metadata.example"
                  required
                />
              </label>
              <div className="form-row">
                <label className="form-label">
                  Default domain policy
                  <select name="default_domain_policy" defaultValue="deny">
                    <option value="deny">deny</option>
                    <option value="allow">allow</option>
                  </select>
                </label>
                <label className="form-label">
                  Allowed ports
                  <input
                    name="allowed_ports"
                    defaultValue="80,443"
                    placeholder="80,443"
                  />
                </label>
              </div>
              <label className="form-check">
                <input type="checkbox" name="allow_private_networks" />
                Allow private network destinations
              </label>
              <div className="notice">
                <CircleHelp size={16} />
                <span>
                  {backendMode
                    ? "This policy is stored in PostgreSQL and evaluated by the database policy engine before any browser navigation."
                    : "This demo policy is local only. Connect the backend to enforce it in the browser worker."}
                </span>
              </div>
              <div className="modal-actions">
                <Button type="submit" variant="primary">
                  Create policy
                </Button>
              </div>
            </form>
          )}
          {modal === "Audit integrity" && (
            <>
              <div
                className={`integration-icon ${
                  backendMode && auditVerification?.valid
                    ? "green"
                    : backendMode
                      ? "red"
                      : "amber"
                }`}
              >
                <Shield size={24} />
              </div>
              <h3 className="detail-title">
                {backendMode
                  ? auditVerification?.valid
                    ? "Audit chain verified"
                    : auditVerification
                      ? "Audit integrity check failed"
                      : "Verification not run"
                  : "Backend verification required"}
              </h3>
              <p className="muted">
                {backendMode
                  ? auditVerification
                    ? auditVerification.valid
                      ? "Every event hash links to the previous event and the append-only sequence is intact."
                      : `The hash chain is broken at event sequence ${auditVerification.broken_sequence ?? "unknown"}.`
                    : "Run verification to check the tenant's hash-chained audit log."
                  : "This demo displays seeded and session-generated events. A cryptographic hash chain and durable append-only storage have not been implemented. Connect the backend to enable real integrity verification."}
              </p>
              <div className="detail-grid">
                <div>
                  <span>Events verified</span>
                  <strong>
                    {backendMode && auditVerification
                      ? auditVerification.events
                      : events.length}
                  </strong>
                </div>
                <div>
                  <span>Verification status</span>
                  <Badge
                    tone={
                      backendMode
                        ? auditVerification?.valid
                          ? "green"
                          : "red"
                        : "amber"
                    }
                  >
                    {backendMode
                      ? auditVerification?.valid
                        ? "Verified"
                        : auditVerification
                          ? "Failed"
                          : "Not verified"
                      : "Not verified"}
                  </Badge>
                </div>
              </div>
              {backendMode && auditVerification?.head && (
                <div className="notice">
                  <ShieldCheck size={16} />
                  <span>
                    Chain head <code>{auditVerification.head.slice(0, 24)}…</code>
                  </span>
                </div>
              )}
            </>
          )}
          {modal === "Workspace" && (
            <>
              <div className="workspace-option">
                <span className="workspace-avatar">A</span>
                <div>
                  <strong>{workspaceName}</strong>
                  <p>
                    Enterprise ·{" "}
                    {backendMode ? "Connected tenant" : "Demo environment"}
                  </p>
                </div>
                <Check size={18} />
              </div>
              <div className="notice">
                <Globe size={17} />
                <span>
                  {backendMode
                    ? `Requests and audit records are isolated to ${sessionUser?.tenant_id || "the current tenant"}.`
                    : "One seeded tenant is available. Multi-tenant isolation requires a connected backend."}
                </span>
              </div>
            </>
          )}
          {modal === "Help & documentation" && (
            <>
              <p className="muted">
                AgentShield is a runtime security gateway for AI agents.{" "}
                {backendMode
                  ? "This workspace is connected to the live gateway, policy engine, and audit log."
                  : "This frontend is a standalone demonstration of the Platform & Enforcement module."}
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
                    {backendMode
                      ? "P1 inspection, P2 offline tools, and P3 online adapters are reported by the backend; unavailable integrations fail closed."
                      : "P1 supplies security inspection, P2 supplies isolated offline tools, and P3 supplies online adapters."}
                  </p>
                </div>
                <div>
                  <FlaskConical size={22} />
                  <h3>Safely simulated</h3>
                  <p>
                    {backendMode
                      ? `${activeScenarios.length} scenarios execute through the gateway with mock adapters. No host files, secrets, or external services are accessed.`
                      : `${activeScenarios.length} attack scenarios use local deterministic rules. No host files, secrets, or external services are accessed.`}
                  </p>
                </div>
                <div>
                  <KeyRound size={22} />
                  <h3>{backendMode ? "Signed in" : "Demo sign-in"}</h3>
                  <p>
                    {backendMode
                      ? `${sessionUser?.email || "Administrator"} · ${sessionUser?.role || "admin"}`
                      : "admin@agentshield.demo"}
                    {!backendMode && (
                      <>
                        <br />
                        demo-password
                        <br />
                        For UI demonstration only.
                      </>
                    )}
                  </p>
                </div>
              </div>
              <div className="notice">
                <BookOpen size={17} />
                <span>
                  {backendMode
                    ? "Project notes are in agentshield/README.md and INTEGRATION.md. Live state is persisted by the backend."
                    : "Project notes are in agentshield/README.md and BUILD_STATUS.md. All demo state resets when the page reloads."}
                </span>
              </div>
            </>
          )}
          {modal.startsWith("Release:") && (
            <>
              <h3>{quarantinedItem?.label}</h3>
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
                  onClick={async () => {
                    if (!quarantinedItem) return
                    const released = await releaseQuarantinedItem(
                      quarantinedItem.id,
                      "Released from quarantine after administrator review.",
                    )
                    if (!released) return
                    setModal(null)
                    notify(
                      backendMode
                        ? "Quarantined item released. No content was sent to an agent."
                        : "Demo item removed from isolation. No content was sent to an agent.",
                    )
                  }}
                >
                  {backendMode ? "Release item" : "Release demo item"}
                </Button>
              </div>
            </>
          )}
        </Modal>
      )}
    </div>
  )
}
