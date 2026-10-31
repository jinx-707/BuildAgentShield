import type { Agent, Approval, AuditEvent } from "./demo"

export type CapabilityRecord = {
  id: string
  organization_id: string
  key: string
  name: string
  description: string | null
  tools: string[]
  is_system: boolean
  is_active: boolean
  created_at: string
}

export type AgentCapabilityRecord = {
  id: string
  organization_id: string
  agent_id: string
  capability_id: string
  capability_key: string | null
  capability_name: string | null
  enabled: boolean
  allowed_tools: string[]
  resource_scope: string[]
  allowed_domains: string[]
  require_approval: boolean
  payment_budget: number | null
  created_at: string
  updated_at: string
}

export type ApprovalRequestRecord = {
  id: string
  organization_id: string
  agent_id: string
  capability_id: string
  tool_name: string
  tool_args: Record<string, unknown>
  target: string | null
  status: string
  requested_by: string | null
  approved_by: string | null
  requested_at: string
  approved_at: string | null
  reason: string | null
}

type ApiEnvironment = Record<string, string | undefined>

const environment: ApiEnvironment =
  ((import.meta as ImportMeta & { env?: ApiEnvironment }).env as
    | ApiEnvironment
    | undefined) ?? {}

function defaultBaseUrl() {
  if (typeof window !== "undefined" && window.location) {
    const { hostname, origin } = window.location
    if (hostname === "127.0.0.1" || hostname === "localhost") {
      return "http://127.0.0.1:8000/v1"
    }
    return `${origin}/v1`
  }
  return "http://127.0.0.1:8000/v1"
}

export const apiBaseUrl = (
  environment.VITE_AGENTSHIELD_API_URL || defaultBaseUrl()
).replace(/\/+$/, "")

export const backendDemoCredentials = {
  email: environment.VITE_AGENTSHIELD_DEMO_EMAIL || "admin@agentshield.dev",
  password: environment.VITE_AGENTSHIELD_DEMO_PASSWORD || "admin-change-me",
}

export const autoConnectBackend =
  environment.VITE_AGENTSHIELD_AUTO_CONNECT === "true"

const TOKEN_KEY = "agentshield.access_token"
const USER_KEY = "agentshield.session_user"
const ORG_NAME_KEY = "agentshield.organization_name"

export class ApiError extends Error {
  status: number
  details: unknown

  constructor(message: string, status = 0, details: unknown = null) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.details = details
  }
}

export type SessionUser = {
  id: string
  email: string
  role: string
  tenant_id: string
  permissions: string[]
  organization_name?: string
  full_name?: string | null
}

export type LoginResult = {
  access_token: string
  token_type: string
  expires_in: number
  user: SessionUser
}

export type AgentRecord = Agent & {
  permissions?: string[]
  scopes?: Record<string, unknown>
  created_at?: string
  agent_id?: string
}

export type PolicyRecord = {
  id: string
  name: string
  description: string
  category: string
  version: number
  active: boolean
  rule: string
  immutable?: boolean
  updated_at?: string
  allowed_domains?: string[]
  blocked_domains?: string[]
  default_domain_policy?: string
  allowed_ports?: string[]
  allow_private_networks?: boolean
  is_default?: boolean
}

export type QuarantineRecord = {
  id: string
  agent_id: string
  tool: string
  reason: string
  preview: string
  status: string
  created_at: string
  released_at: string | null
}

export type OverviewStats = {
  period: string
  total_requests: number
  allowed_requests: number
  blocked_threats: number
  pending_approvals: number
  approval_requests: number
  active_agents: number
  total_agents: number
  series: Array<{
    time: string
    label: string
    allowed: number
    blocked: number
  }>
  risk_distribution: Record<string, number>
  integrations: Array<{ name: string; status: string; detail: string }>
  mode: string
}

export type SimulatorResult = {
  id: string
  name: string
  expected: string
  actual: string
  passed: boolean
  risk: number
  executed: boolean
  reason: string
  audit_id?: string | null
}

export type AuditVerification = {
  valid: boolean
  events: number
  head?: string
  broken_sequence?: number | null
  checked_at: string
}

export type ToolExecutionResult = {
  request_id: string
  decision: string
  risk_level: string
  risk_score: number
  executed: boolean
  reason: string
  audit_id?: string | null
  status: string
  tool: string
  approval?: { id: string; status: string; token?: string | null } | null
}

export type BrowserSession = {
  session_id: string
  state: string
  status: string
  created_at: string
  last_used_at: string
  expires_at: string
  current_url: string | null
}

export type BrowserNavigationResult = {
  request_id: string
  requested_url: string
  final_url: string
  status_code: number | null
  title: string | null
  content: string
  content_truncated: boolean
  elapsed_ms: number
  redirect_count: number
  blocked_request_count: number
  blocked_target_count: number
  policy: { allowed: boolean; policy_name: string; reason: string }
  inspection: {
    inspector_name: string
    findings: Array<{
      rule_id: string
      severity: string
      message: string
      location: Record<string, unknown> | string | null
    }>
    trust_label: string
    highest_severity: string
    summary: string
  }
}

type BackendLoginResponse = {
  access_token: string
  token_type: string
  organization_id: string
  organization_name: string
  role: string
}

type BackendUser = {
  user_id: string
  agent_id: string | null
  organization_id: string
  role: string
  email: string
  full_name: string | null
}

type BackendAgent = {
  id: string
  agent_id: string
  name: string
  status: string
  created_at: string
  last_activity_at: string | null
  permissions?: string[]
  scopes?: Record<string, unknown>
}

type BackendPolicy = {
  id: string
  organization_id: string
  name: string
  description: string | null
  version: number
  is_active: boolean
  is_default: boolean
  allowed_domains: string[]
  blocked_domains: string[]
  default_domain_policy: string
  allowed_ports: string[]
  allow_private_networks: boolean
  agent_id: string | null
  created_at: string
}

type BackendAuditEvent = {
  id: string
  event_type: string
  event_category: string | null
  actor: string | null
  session_id: string | null
  agent_id: string | null
  target: string | null
  decision: string | null
  reason: string | null
  severity: string
  request_id: string | null
  created_at: string
}

type BackendDashboard = {
  registered_agents: number
  active_sessions: number
  total_requests: number
  allowed_requests: number
  blocked_requests: number
  policy_violations: number
  security_incidents: number
  service_health: Record<string, string>
}

function readStorage(key: string) {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // Storage can be unavailable in privacy mode. The session stays in memory.
  }
}

function removeStorage(key: string) {
  try {
    window.localStorage.removeItem(key)
  } catch {
    // Ignore unavailable storage.
  }
}

export function getAccessToken() {
  return readStorage(TOKEN_KEY)
}

export function getStoredUser(): SessionUser | null {
  const raw = readStorage(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as SessionUser
  } catch {
    return null
  }
}

export function hasStoredSession() {
  return Boolean(getAccessToken())
}

export function clearSession() {
  removeStorage(TOKEN_KEY)
  removeStorage(USER_KEY)
  removeStorage(ORG_NAME_KEY)
}

function storeSession(result: LoginResult) {
  writeStorage(TOKEN_KEY, result.access_token)
  writeStorage(USER_KEY, JSON.stringify(result.user))
  if (result.user.organization_name) {
    writeStorage(ORG_NAME_KEY, result.user.organization_name)
  }
}

function organizationId() {
  const user = getStoredUser()
  if (!user?.tenant_id) {
    throw new ApiError("Sign in to load organization data.", 401)
  }
  return user.tenant_id
}

function organizationPath(path: string) {
  return `/organizations/${encodeURIComponent(organizationId())}${path}`
}

function mapUser(
  user: BackendUser,
  login?: BackendLoginResponse,
): SessionUser {
  return {
    id: user.user_id,
    email: user.email,
    role: user.role || login?.role || "viewer",
    tenant_id: user.organization_id || login?.organization_id || "",
    organization_name:
      login?.organization_name || readStorage(ORG_NAME_KEY) || undefined,
    full_name: user.full_name,
    permissions: user.role === "owner" || user.role === "admin" ? ["*"] : [],
  }
}

function initials(name: string) {
  return name
    .split(/[-_\s]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("")
}

function mapAgent(row: BackendAgent): AgentRecord {
  const status =
    row.status === "active"
      ? "Active"
      : row.status === "revoked"
        ? "Disabled"
        : row.status
  return {
    id: row.agent_id,
    agent_id: row.agent_id,
    name: row.name,
    role: "Browser agent",
    status,
    requests: 0,
    initials: initials(row.name) || "AG",
    color: "violet",
    created_at: row.created_at,
    permissions: row.permissions,
    scopes: row.scopes,
  }
}

function mapPolicy(row: BackendPolicy): PolicyRecord {
  const allowed = row.allowed_domains || []
  const blocked = row.blocked_domains || []
  return {
    id: row.id,
    name: row.name,
    description: row.description || "Browser egress policy.",
    category: "Browser egress",
    version: row.version,
    active: row.is_active,
    rule: [
      `default: ${row.default_domain_policy}`,
      `allowed: ${allowed.join(", ") || "(none)"}`,
      `blocked: ${blocked.join(", ") || "(none)"}`,
      `ports: ${(row.allowed_ports || []).join(", ") || "(none)"}`,
    ].join("\n"),
    updated_at: row.created_at,
    allowed_domains: allowed,
    blocked_domains: blocked,
    default_domain_policy: row.default_domain_policy,
    allowed_ports: row.allowed_ports,
    allow_private_networks: row.allow_private_networks,
    is_default: row.is_default,
  }
}

function riskForSeverity(severity: string) {
  const normalized = severity.toLowerCase()
  if (normalized === "critical") return 95
  if (normalized === "high") return 82
  if (normalized === "medium") return 55
  if (normalized === "low") return 28
  return 10
}

function decisionFor(event: BackendAuditEvent): AuditEvent["decision"] {
  const decision = (event.decision || "").toLowerCase()
  if (decision === "deny" || decision === "blocked") return "Blocked"
  if (event.event_type === "navigation.blocked_redirect") return "Blocked"
  if (event.event_type === "security.violation") return "Blocked"
  if (event.event_type === "action.refuse") return "Blocked"
  if (decision === "quarantined") return "Quarantined"
  if (decision === "approval") return "Approval"
  return "Allowed"
}

function mapAuditEvent(event: BackendAuditEvent): AuditEvent {
  return {
    id: event.id,
    agent: event.actor || event.agent_id || "system",
    tool: event.event_type,
    description:
      event.reason || event.target || event.request_id || event.event_type,
    decision: decisionFor(event),
    risk: riskForSeverity(event.severity || "info"),
    time: relativeTime(event.created_at),
  }
}

type RequestOptions = {
  method?: string
  body?: unknown
  auth?: boolean
  headers?: Record<string, string>
  agentKey?: string
  agentId?: string
  timeoutMs?: number
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const controller = new AbortController()
  const timeout = window.setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? 15000,
  )
  const headers: Record<string, string> = { ...options.headers }
  if (options.body !== undefined) headers["Content-Type"] = "application/json"
  const token = getAccessToken()
  if (options.agentKey) headers["X-Agent-Key"] = options.agentKey
  if (options.agentId) headers["X-Agent-ID"] = options.agentId
  if (options.auth !== false && token)
    headers.Authorization = `Bearer ${token}`
  try {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      method: options.method || "GET",
      headers,
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
      credentials: "omit",
    })
    const contentType = response.headers.get("content-type") || ""
    const payload = contentType.includes("application/json")
      ? await response.json().catch(() => null)
      : await response.text().catch(() => "")
    if (!response.ok) {
      const envelope =
        payload && typeof payload === "object" && "detail" in payload
          ? (payload as { detail: unknown }).detail
          : payload
      const detail =
        envelope && typeof envelope === "object" && "message" in envelope
          ? String((envelope as { message: unknown }).message)
          : typeof envelope === "string" && envelope
            ? envelope
            : envelope
              ? JSON.stringify(envelope)
              : `Request failed with status ${response.status}`
      throw new ApiError(detail, response.status, payload)
    }
    return payload as T
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("AgentShield API timed out", 0)
    }
    throw new ApiError(
      error instanceof Error ? error.message : "AgentShield API is unreachable",
      0,
    )
  } finally {
    window.clearTimeout(timeout)
  }
}

export async function login(
  email: string,
  password: string,
): Promise<LoginResult> {
  const auth = await request<BackendLoginResponse>("/auth/login", {
    method: "POST",
    body: { email, password },
    auth: false,
  })
  writeStorage(TOKEN_KEY, auth.access_token)
  try {
    const me = await request<BackendUser>("/auth/me")
    const user = mapUser(me, auth)
    const result: LoginResult = {
      access_token: auth.access_token,
      token_type: auth.token_type,
      expires_in: 3600,
      user,
    }
    storeSession(result)
    return result
  } catch (error) {
    clearSession()
    throw error
  }
}

export async function loginDemoBackend() {
  return login(backendDemoCredentials.email, backendDemoCredentials.password)
}

export async function me() {
  return mapUser(await request<BackendUser>("/auth/me"))
}

export async function logout() {
  try {
    await request("/auth/logout", { method: "POST" })
  } finally {
    clearSession()
  }
}

export async function restoreSession() {
  if (!hasStoredSession()) return null
  try {
    const user = await me()
    writeStorage(USER_KEY, JSON.stringify(user))
    return user
  } catch {
    clearSession()
    return null
  }
}

export async function getAgents() {
  const result = await request<BackendAgent[]>(organizationPath("/agents"))
  return result.map(mapAgent)
}

export async function createAgent(
  name: string,
  _role: string,
  _permissions?: string[],
  _scopes?: Record<string, unknown>,
) {
  const result = await request<{ agent_id: string; name: string; secret: string }>(
    organizationPath("/agents"),
    { method: "POST", body: { name } },
  )
  const agent: AgentRecord = {
    id: result.agent_id,
    agent_id: result.agent_id,
    name: result.name,
    role: "Browser agent",
    status: "Active",
    requests: 0,
    initials: initials(result.name) || "AG",
    color: "violet",
    created_at: new Date().toISOString(),
  }
  return {
    agent,
    api_key: result.secret,
    key_prefix: result.secret.slice(0, 12),
  }
}

export async function updateAgent(
  agentId: string,
  patch: {
    name?: string
    role?: string
    status?: "Active" | "Disabled"
    permissions?: string[]
    scopes?: Record<string, unknown>
  },
) {
  if (patch.status === "Disabled") {
    await request(`/agents/${encodeURIComponent(agentId)}/revoke`, {
      method: "POST",
    })
    return {
      id: agentId,
      agent_id: agentId,
      name: agentId,
      role: "Browser agent",
      status: "Disabled",
      requests: 0,
      initials: "AG",
      color: "violet",
    } as AgentRecord
  }
  if (patch.status === "Active") {
    throw new ApiError(
      "The browser-security API cannot re-enable a revoked agent. Create a new agent instead.",
      501,
    )
  }
  const orgId = organizationId()
  const result = await request<AgentRecord>(
    `/agents/${encodeURIComponent(agentId)}`,
    {
      method: "PATCH",
      body: {
        permissions: patch.permissions,
        scopes: patch.scopes,
      },
    },
  )
  return result
}

export async function getCapabilities(): Promise<CapabilityRecord[]> {
  const orgId = organizationId()
  return request<CapabilityRecord[]>(
    organizationPath("/capabilities"),
    { method: "GET" },
  )
}

export async function getAgentCapabilities(agentId: string): Promise<AgentCapabilityRecord[]> {
  return request<AgentCapabilityRecord[]>(
    `/agents/${encodeURIComponent(agentId)}/capabilities`,
    { method: "GET" },
  )
}

export async function updateAgentCapability(
  agentId: string,
  capabilityKey: string,
  patch: {
    enabled?: boolean
    allowed_tools?: string[]
    resource_scope?: string[]
    allowed_domains?: string[]
    require_approval?: boolean
    payment_budget?: number
  },
): Promise<AgentCapabilityRecord> {
  return request<AgentCapabilityRecord>(
    `/agents/${encodeURIComponent(agentId)}/capabilities/${encodeURIComponent(capabilityKey)}`,
    { method: "PATCH", body: patch },
  )
}

export async function getApprovals(status?: string) {
  const orgId = organizationId()
  const params = status ? `?status=${encodeURIComponent(status)}` : ""
  return request<ApprovalRequestRecord[]>(
    organizationPath(`/approvals${params}`),
    { method: "GET" },
  )
}

export async function approveRequest(approvalId: string, comment?: string) {
  return request<ApprovalRequestRecord>(
    `/approvals/${encodeURIComponent(approvalId)}/approve`,
    { method: "POST", body: { reason: comment } },
  )
}

export async function rejectRequest(approvalId: string, comment?: string) {
  return request<ApprovalRequestRecord>(
    `/approvals/${encodeURIComponent(approvalId)}/reject`,
    { method: "POST", body: { reason: comment } },
  )
}

export async function rotateAgentKey(
  _agentId: string,
): Promise<{ api_key: string; key_prefix: string }> {
  throw new ApiError(
    "Agent key rotation is not supported by the browser-security API. Create a new agent to issue a new key.",
    501,
  )
}

export function relativeTime(value: string) {
  const timestamp = new Date(value).getTime()
  if (Number.isNaN(timestamp)) return value
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000))
  if (seconds < 45) return "Just now"
  if (seconds < 90) return "1 min ago"
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} hr ago`
  const days = Math.round(hours / 24)
  return `${days} day${days === 1 ? "" : "s"} ago`
}

export async function getAudit(
  decision?: string,
  query?: string,
  pageSize = 200,
) {
  const params = new URLSearchParams()
  params.set("limit", String(pageSize))
  params.set("offset", "0")
  const result = await request<BackendAuditEvent[]>(
    `${organizationPath("/audit")}?${params.toString()}`,
  )
  let items = result.map(mapAuditEvent)
  if (decision && decision !== "All decisions") {
    items = items.filter((event) => event.decision === decision)
  }
  if (query) {
    const needle = query.toLowerCase()
    items = items.filter((event) =>
      `${event.agent} ${event.tool} ${event.id} ${event.description}`
        .toLowerCase()
        .includes(needle),
    )
  }
  return { items, total: items.length, page: 1, page_size: pageSize }
}

export async function getBrowserAuditEvents(limit = 50) {
  const result = await request<BackendAuditEvent[]>(
    `${organizationPath("/audit")}?limit=${limit}`,
  )
  return result.map(mapAuditEvent)
}

export async function verifyAudit(): Promise<AuditVerification> {
  throw new ApiError(
    "Audit hash-chain verification is not available in the browser-security API.",
    501,
  )
}

export async function downloadAudit(format: "json" | "csv") {
  const { items } = await getAudit(undefined, undefined, 1000)
  if (format === "json") {
    return new Blob([JSON.stringify(items, null, 2)], {
      type: "application/json",
    })
  }
  const rows = [
    "id,agent,tool,decision,risk,time",
    ...items.map((event) =>
      [event.id, event.agent, event.tool, event.decision, event.risk, event.time]
        .map((value) => `"${String(value).replace(/"/g, '""')}"`)
        .join(","),
    ),
  ]
  return new Blob([rows.join("\n")], { type: "text/csv" })
}

export async function getPolicies() {
  const result = await request<BackendPolicy[]>(organizationPath("/policies"))
  return result.map(mapPolicy)
}

export type PolicyDraft = {
  name: string
  description: string
  category?: string
  rule?: string
  allowed_domains?: string[]
  blocked_domains?: string[]
  default_domain_policy?: "allow" | "deny"
  allowed_ports?: string[]
  allow_private_networks?: boolean
  is_default?: boolean
}

export async function createPolicy(policy: PolicyDraft) {
  const body = {
    name: policy.name,
    description: policy.description,
    allowed_domains: policy.allowed_domains || [],
    blocked_domains: policy.blocked_domains || [],
    default_domain_policy: policy.default_domain_policy || "deny",
    allowed_ports: policy.allowed_ports || ["80", "443"],
    allow_private_networks: policy.allow_private_networks ?? false,
    is_default: policy.is_default ?? false,
  }
  const result = await request<BackendPolicy>(organizationPath("/policies"), {
    method: "POST",
    body,
  })
  return mapPolicy(result)
}

export async function updatePolicy(policyId: string, active: boolean) {
  const result = await request<BackendPolicy>(
    `/policies/${encodeURIComponent(policyId)}`,
    { method: "PATCH", body: { is_active: active } },
  )
  return mapPolicy(result)
}

export async function getQuarantine() {
  return [] as QuarantineRecord[]
}

export async function releaseQuarantine(_itemId: string, _comment: string) {
  throw new ApiError(
    "The browser-security API does not expose a quarantine queue.",
    501,
  )
}

export async function getWorkspace() {
  const user = getStoredUser()
  const id = organizationId()
  const name =
    user?.organization_name || readStorage(ORG_NAME_KEY) || "AgentShield"
  return {
    id,
    slug: name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
    name,
  }
}

export async function updateWorkspace(
  _name: string,
): Promise<{ id: string; slug: string; name: string }> {
  throw new ApiError(
    "Workspace renaming is not exposed by the browser-security API.",
    501,
  )
}

export async function getOverviewStats(period: "24h" | "7d" | "30d") {
  const [dashboard, audit] = await Promise.all([
    request<BackendDashboard>(organizationPath("/dashboard")),
    request<BackendAuditEvent[]>(
      `${organizationPath("/audit")}?limit=500`,
    ),
  ])
  const bucketCount = period === "24h" ? 8 : period === "7d" ? 7 : 6
  const windowMs =
    period === "24h"
      ? 24 * 60 * 60 * 1000
      : period === "7d"
        ? 7 * 24 * 60 * 60 * 1000
        : 30 * 24 * 60 * 60 * 1000
  const now = Date.now()
  const series = Array.from({ length: bucketCount }, (_, index) => {
    const start = now - windowMs + (windowMs / bucketCount) * index
    const end = start + windowMs / bucketCount
    const bucket = audit.filter((event) => {
      const time = new Date(event.created_at).getTime()
      return time >= start && time < end
    })
    return {
      time: new Date(start).toISOString(),
      label:
        period === "24h"
          ? `${String(new Date(start).getHours()).padStart(2, "0")}:00`
          : new Date(start).toLocaleDateString(undefined, {
              month: "short",
              day: "numeric",
            }),
      allowed: bucket.filter((event) => decisionFor(event) === "Allowed").length,
      blocked: bucket.filter((event) => decisionFor(event) === "Blocked").length,
    }
  })
  const severityCounts = audit.reduce<Record<string, number>>((acc, event) => {
    const key = (event.severity || "low").toLowerCase()
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  return {
    period,
    total_requests: dashboard.total_requests,
    allowed_requests: dashboard.allowed_requests,
    blocked_threats: dashboard.blocked_requests,
    pending_approvals: 0,
    approval_requests: 0,
    active_agents: dashboard.registered_agents,
    total_agents: dashboard.registered_agents,
    series,
    risk_distribution: {
      critical: severityCounts.critical || 0,
      high: severityCounts.high || 0,
      medium: severityCounts.medium || 0,
      low: severityCounts.low || 0,
    },
    integrations: Object.entries(dashboard.service_health || {}).map(
      ([name, status]) => ({
        name,
        status,
        detail: `${name.replace(/_/g, " ")}: ${status}`,
      }),
    ),
    mode: "database-backed browser security",
  } satisfies OverviewStats
}

export async function getIntegrationHealth() {
  const dashboard = await request<BackendDashboard>(
    organizationPath("/dashboard"),
  )
  return {
    items: Object.entries(dashboard.service_health || {}).map(
      ([name, status]) => ({
        name,
        status,
        detail: `${name.replace(/_/g, " ")}: ${status}`,
      }),
    ),
    gateway: dashboard.service_health?.api || "unknown",
    opa: dashboard.service_health?.policy_engine || "unknown",
  }
}

export async function getAttackScenarios() {
  const results = await request<Array<{
    scenario_id: string
    scenario_name: string
    threat_category: string | null
  }>>("/attack-simulation/scenarios")
  return results.map((s) => ({
    id: s.scenario_id,
    name: s.scenario_name,
    description: s.threat_category || "",
    category: s.threat_category || "",
  }))
}

export type CyberRangeScenario = {
  scenario_id: string
  name: string
  description: string
  target_service: string
  risk_category: string
  required_services: string[]
  available: boolean
}

export type Campaign = {
  id: string
  organization_id: string
  user_id: string
  name: string
  description: string | null
  policy_version: string
  status: string
  scenario_ids: string[]
  execution_mode: string
  max_concurrency: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  created_at: string
}

export type Simulation = {
  id: string
  campaign_id: string
  organization_id: string
  scenario_id: string
  target_id: string
  status: string
  assessment: string | null
  policy_version: string
  browser_session_id: string | null
  agent_id: string | null
  started_at: string | null
  completed_at: string | null
  error: string | null
  agent_shield_decision: string | null
  proxy_decision: string | null
  created_at: string
}

export type SimulationEvidence = {
  id: string
  simulation_id: string
  evidence_type: string
  description: string | null
  content: Record<string, unknown>
  source: string
  created_at: string | null
}

export async function getSimulationEvidence(simulationId: string): Promise<SimulationEvidence[]> {
  return request<SimulationEvidence[]>(`/simulations/${simulationId}/evidence`)
}

export type CampaignReport = {
  campaign_id: string
  campaign_name: string
  organization_id: string
  policy_version: string
  execution_mode: string
  started_at: string | null
  completed_at: string | null
  summary: {
    total_scenarios: number
    passed: number
    failed: number
    errors: number
    inconclusive: number
    detection_coverage_pct: number
    enforcement_coverage_pct: number
  }
  scenario_results: Array<{
    scenario_id: string
    scenario_name: string
    status: string
    assessment: string | null
    agent_shield_decision: string | null
    proxy_decision: string | null
    evidence_count: number
  }>
  failed_controls: Array<{
    scenario_id: string
    scenario_name: string
    assessment: string
    error: string | null
  }>
  inconclusive_tests: Array<{
    scenario_id: string
    scenario_name: string
    reason: string
  }>
  recommendations: string[]
  known_limitations: string[]
}

export async function getCyberRangeScenarios(): Promise<CyberRangeScenario[]> {
  return request<CyberRangeScenario[]>("/simulations/scenarios")
}

export async function createCampaign(campaign: {
  organization_id: string
  user_id: string
  name: string
  description?: string
  policy_version?: string
  scenario_ids: string[]
  execution_mode?: string
  max_concurrency?: number
  agent_id?: string
}): Promise<Campaign> {
  return request<Campaign>("/simulations/campaigns", {
    method: "POST",
    body: campaign,
  })
}

export async function listCampaigns(limit = 100, offset = 0): Promise<Campaign[]> {
  const params = new URLSearchParams()
  params.set("limit", String(limit))
  params.set("offset", String(offset))
  return request<Campaign[]>(`/simulations/campaigns?${params.toString()}`)
}

export async function getCampaign(campaignId: string): Promise<Campaign> {
  return request<Campaign>(`/simulations/campaigns/${campaignId}`)
}

export async function cancelCampaign(campaignId: string): Promise<{ status: string }> {
  return request<{ status: string }>(`/simulations/campaigns/${campaignId}/cancel`, {
    method: "POST",
  })
}

export async function getCampaignReport(campaignId: string): Promise<CampaignReport> {
  return request<CampaignReport>(`/simulations/campaigns/${campaignId}/report`)
}

export async function getSimulation(simulationId: string): Promise<Simulation> {
  return request<Simulation>(`/simulations/${simulationId}`)
}

// Duplicate removed
export function streamSimulationEvents(
  simulationId: string,
  onEvent: (event: { id: string; stage: string; message: string; data: Record<string, unknown>; timestamp: string }) => void,
  onError?: (error: Error) => void
): () => void {
  const token = getAccessToken()
  const orgId = getStoredUser()?.tenant_id
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`
  if (orgId) headers["x-organization-id"] = orgId

  const eventSource = new EventSource(`${apiBaseUrl}/simulations/${simulationId}/events`, { withCredentials: false })
  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onEvent(data)
    } catch {
      // Ignore parse errors
    }
  }
  eventSource.onerror = (error) => {
    if (onError) onError(new Error("EventSource error"))
    eventSource.close()
  }

  return () => eventSource.close()
}

export function streamCampaignEvents(
  campaignId: string,
  onEvent: (event: { id: string; type: string; message: string; data: Record<string, unknown>; timestamp: string }) => void,
  onError?: (error: Error) => void
): () => void {
  const token = getAccessToken()
  const orgId = getStoredUser()?.tenant_id
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`
  if (orgId) headers["x-organization-id"] = orgId

  const eventSource = new EventSource(`${apiBaseUrl}/simulations/campaigns/${campaignId}/events`, { withCredentials: false })
  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onEvent(data)
    } catch {
      // Ignore parse errors
    }
  }
  eventSource.onerror = (error) => {
    if (onError) onError(new Error("EventSource error"))
    eventSource.close()
  }

  return () => eventSource.close()
}

export async function runSingleScenario(
  scenarioId: string,
  organizationId: string,
  agentId?: string,
  sessionId?: string
): Promise<Simulation> {
  const params = new URLSearchParams()
  params.set("organization_id", organizationId)
  if (agentId) params.set("agent_id", agentId)
  if (sessionId) params.set("session_id", sessionId)
  return request<Simulation>(`/simulations/scenarios/${scenarioId}/run?${params.toString()}`, {
    method: "POST",
  })
}

export async function runSimulator(_scenarioIds: string[]) {
  const results = await request<{
    results: Array<{
      scenario_id: string
      scenario_name: string
      enforcement_result: string
      policy_decision: string
      evidence?: unknown
    }>
  }>("/attack-simulation/run", {
    method: "POST",
    body: { organization_id: organizationId() },
    timeoutMs: 120000,
  })
  const items: SimulatorResult[] = results.results.map((result) => ({
    id: result.scenario_id,
    name: result.scenario_name,
    expected: "PASS",
    actual: result.enforcement_result,
    passed: result.enforcement_result === "PASS",
    risk: result.policy_decision === "deny" ? 10 : 85,
    executed: true,
    reason: `${result.policy_decision} · ${result.enforcement_result}`,
  }))
  return {
    items,
    passed: items.filter((item) => item.passed).length,
    total: items.length,
    mode: "database-backed browser security",
  }
}

export async function executeTool(
  _agentKey: string,
  _requestBody: {
    request_id: string
    tool_name: string
    arguments: Record<string, unknown>
    reason?: string
    provenance?: Record<string, unknown>
    approval_token?: string
  },
  _options: { idempotencyKey?: string; approvalToken?: string } = {},
) {
  throw new ApiError(
    "Tool gateway execution is not part of the browser-security API.",
    501,
  )
}

export async function createBrowserSession(
  agentId: string,
  options: { idleTimeoutMs?: number; maxAgeMs?: number } = {},
) {
  return request<BrowserSession>("/browser/session", {
    method: "POST",
    agentId,
    body: {
      idle_timeout_ms: options.idleTimeoutMs,
      max_age_ms: options.maxAgeMs,
    },
  })
}

export async function getBrowserSession(agentId: string, sessionId: string) {
  return request<BrowserSession>(
    `/browser/session/${encodeURIComponent(sessionId)}`,
    { agentId },
  )
}

export async function closeBrowserSession(agentId: string, sessionId: string) {
  return request<{ session_id: string; closed: boolean; closing: boolean }>(
    `/browser/session/${encodeURIComponent(sessionId)}`,
    { method: "DELETE", agentId },
  )
}

export async function navigateBrowser(
  agentId: string,
  url: string,
  sessionId?: string,
) {
  try {
    return await request<BrowserNavigationResult>("/browser/navigate", {
      method: "POST",
      agentId,
      body: { url, session_id: sessionId, wait_until: "domcontentloaded" },
      timeoutMs: 60000,
    })
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      const envelope = error.details as {
        detail?: { code?: string; message?: string }
      } | null
      const code = envelope?.detail?.code
      const blockedMessage = envelope?.detail?.message || error.message
      if (code === "DOMAIN_BLOCKED" || code === "PRIVATE_NETWORK_BLOCKED") {
        return {
          request_id: crypto.randomUUID(),
          requested_url: url,
          final_url: url,
          status_code: null,
          title: null,
          content: "",
          content_truncated: false,
          elapsed_ms: 0,
          redirect_count: 0,
          blocked_request_count: 0,
          blocked_target_count: 1,
          policy: {
            allowed: false,
            policy_name: "Active browser egress policy",
            reason: blockedMessage,
          },
          inspection: {
            inspector_name: "egress-policy",
            findings: [],
            trust_label: "blocked",
            highest_severity: "high",
            summary: "Destination rejected before the worker loaded it.",
          },
        } satisfies BrowserNavigationResult
      }
    }
    throw error
  }
}

export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
