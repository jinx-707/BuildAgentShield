import type { Agent, Approval, AuditEvent } from "./demo"

type ApiEnvironment = Record<string, string | undefined>

const environment: ApiEnvironment =
  ((import.meta as ImportMeta & { env?: ApiEnvironment }).env as
    | ApiEnvironment
    | undefined) ?? {}

function defaultBaseUrl() {
  if (typeof window !== "undefined" && window.location) {
    const { origin, port, protocol } = window.location
    if (port === "8443" || protocol === "file:") {
      return "http://127.0.0.1:8000/api/v1"
    }
    return `${origin}/api/v1`
  }
  return "http://127.0.0.1:8000/api/v1"
}

export const apiBaseUrl = (
  environment.VITE_AGENTSHIELD_API_URL || defaultBaseUrl()
).replace(/\/+$/, "")

export const backendDemoCredentials = {
  email: environment.VITE_AGENTSHIELD_DEMO_EMAIL || "admin@agentshield.local",
  password: environment.VITE_AGENTSHIELD_DEMO_PASSWORD || "admin-change-me",
}

export const autoConnectBackend =
  environment.VITE_AGENTSHIELD_AUTO_CONNECT !== "false"

const TOKEN_KEY = "agentshield.access_token"
const USER_KEY = "agentshield.session_user"

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
}

function storeSession(result: LoginResult) {
  writeStorage(TOKEN_KEY, result.access_token)
  writeStorage(USER_KEY, JSON.stringify(result.user))
}

type RequestOptions = {
  method?: string
  body?: unknown
  auth?: boolean
  headers?: Record<string, string>
  agentKey?: string
  timeoutMs?: number
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const controller = new AbortController()
  const timeout = window.setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? 8000,
  )
  const headers: Record<string, string> = { ...options.headers }
  if (options.body !== undefined) headers["Content-Type"] = "application/json"
  const token = getAccessToken()
  if (options.agentKey) headers["X-Agent-Key"] = options.agentKey
  else if (options.auth !== false && token)
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
      const detail =
        payload && typeof payload === "object" && "detail" in payload
          ? String((payload as { detail: unknown }).detail)
          : typeof payload === "string" && payload
            ? payload
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
  const result = await request<LoginResult>("/auth/login", {
    method: "POST",
    body: { email, password },
    auth: false,
  })
  storeSession(result)
  return result
}

export async function loginDemoBackend() {
  return login(backendDemoCredentials.email, backendDemoCredentials.password)
}

export async function me() {
  return request<SessionUser & { agents?: AgentRecord[] }>("/auth/me")
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
  const result = await request<{ items: AgentRecord[] }>("/agents")
  return result.items
}

export async function createAgent(
  name: string,
  role: string,
  permissions?: string[],
  scopes?: Record<string, unknown>,
) {
  return request<{ agent: AgentRecord; api_key: string; key_prefix: string }>(
    "/agents",
    {
      method: "POST",
      body: { name, role, permissions, scopes },
    },
  )
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
  return request<AgentRecord>(`/agents/${encodeURIComponent(agentId)}`, {
    method: "PATCH",
    body: patch,
  })
}

export async function rotateAgentKey(agentId: string) {
  return request<{ agent_id: string; api_key: string; key_prefix: string }>(
    `/agents/${encodeURIComponent(agentId)}/rotate-key`,
    { method: "POST" },
  )
}

export async function getApprovals(status?: string) {
  const query = status ? `?status=${encodeURIComponent(status)}` : ""
  const result = await request<{ items: Approval[]; pending: number }>(
    `/approvals${query}`,
  )
  return result.items
}

export async function approveRequest(approvalId: string, comment: string) {
  return request<Approval & { token: string }>(
    `/approvals/${encodeURIComponent(approvalId)}/approve`,
    { method: "POST", body: { comment } },
  )
}

export async function rejectRequest(approvalId: string, comment: string) {
  return request<Approval>(
    `/approvals/${encodeURIComponent(approvalId)}/reject`,
    { method: "POST", body: { comment } },
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

function normalizeEvent(event: AuditEvent) {
  return { ...event, time: relativeTime(event.time) }
}

export async function getAudit(decision?: string, query?: string, pageSize = 200) {
  const params = new URLSearchParams()
  if (decision && decision !== "All decisions") params.set("decision", decision)
  if (query) params.set("query", query)
  params.set("page", "1")
  params.set("page_size", String(pageSize))
  const result = await request<{
    items: AuditEvent[]
    total: number
    page: number
    page_size: number
  }>(`/audit?${params.toString()}`)
  return { ...result, items: result.items.map(normalizeEvent) }
}

export async function verifyAudit() {
  return request<AuditVerification>("/audit/verify")
}

export async function downloadAudit(format: "json" | "csv") {
  const token = getAccessToken()
  const response = await fetch(`${apiBaseUrl}/audit/export?format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: "omit",
  })
  if (!response.ok) {
    throw new ApiError(`Audit export failed with status ${response.status}`, response.status)
  }
  return response.blob()
}

export async function getPolicies() {
  const result = await request<{ items: PolicyRecord[] }>("/policies")
  return result.items
}

export async function createPolicy(policy: {
  name: string
  description: string
  category?: string
  rule: string
}) {
  return request<PolicyRecord>("/policies", {
    method: "POST",
    body: { category: "Custom policy", ...policy },
  })
}

export async function updatePolicy(policyId: string, active: boolean) {
  return request<PolicyRecord>(`/policies/${encodeURIComponent(policyId)}`, {
    method: "PATCH",
    body: { active },
  })
}

export async function getQuarantine() {
  const result = await request<{ items: QuarantineRecord[] }>("/quarantine")
  return result.items
}

export async function releaseQuarantine(itemId: string, comment: string) {
  return request<QuarantineRecord>(
    `/quarantine/${encodeURIComponent(itemId)}/release`,
    { method: "POST", body: { comment } },
  )
}

export async function getWorkspace() {
  return request<{ id: string; slug: string; name: string }>("/workspace")
}

export async function updateWorkspace(name: string) {
  return request<{ id: string; slug: string; name: string }>("/workspace", {
    method: "PATCH",
    body: { name },
  })
}

export async function getOverviewStats(period: "24h" | "7d" | "30d") {
  return request<OverviewStats>(`/stats/overview?period=${period}`)
}

export async function getIntegrationHealth() {
  return request<{
    items: Array<{ name: string; status: string; detail: string }>
    gateway: string
    opa: string
  }>("/integrations/health")
}

export async function getTools() {
  return request<{ items: Array<Record<string, unknown>> }>("/tools")
}

export async function runSimulator(scenarioIds: string[]) {
  return request<{
    items: SimulatorResult[]
    passed: number
    total: number
    mode: string
  }>("/simulator/run", {
    method: "POST",
    body: { scenario_ids: scenarioIds },
  })
}

export async function executeTool(
  agentKey: string,
  requestBody: {
    request_id: string
    tool_name: string
    arguments: Record<string, unknown>
    reason?: string
    provenance?: Record<string, unknown>
    approval_token?: string
  },
  options: { idempotencyKey?: string; approvalToken?: string } = {},
) {
  const headers: Record<string, string> = {}
  if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey
  if (options.approvalToken) headers["X-Approval-Token"] = options.approvalToken
  return request<ToolExecutionResult>("/gateway/execute", {
    method: "POST",
    body: requestBody,
    agentKey,
    headers,
  })
}

export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
