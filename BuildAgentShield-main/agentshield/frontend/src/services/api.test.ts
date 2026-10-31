import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import {
  getAttackScenarios,
  getAgents,
  getAudit,
  getPolicies,
} from "./api"

const originalFetch = globalThis.fetch
const originalWindow = globalThis.window
const localStorageStore = new Map<string, string>()

const mockWindow = {
  setTimeout: globalThis.setTimeout.bind(globalThis),
  clearTimeout: globalThis.clearTimeout.bind(globalThis),
  localStorage: {
    getItem: (key: string) => localStorageStore.get(key) ?? null,
    setItem: (key: string, value: string) => {
      localStorageStore.set(key, value)
    },
    removeItem: (key: string) => {
      localStorageStore.delete(key)
    },
  },
}

function mockFetch(json: unknown, status = 200) {
  globalThis.fetch = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(json), {
        status,
        headers: { "content-type": "application/json" },
      }),
  ) as unknown as typeof fetch
}

const USER_KEY = "agentshield.session_user"

function setStoredUser(tenant_id = "org-1") {
  localStorageStore.set(
    USER_KEY,
    JSON.stringify({
      id: "user-1",
      email: "admin@agentshield.dev",
      role: "owner",
      tenant_id,
      permissions: ["*"],
    }),
  )
}

beforeEach(() => {
  localStorageStore.clear()
  setStoredUser()
  vi.stubGlobal("window", mockWindow)
  vi.stubGlobal("fetch", originalFetch)
})

afterEach(() => {
  vi.restoreAllMocks()
  globalThis.fetch = originalFetch
  globalThis.window = originalWindow
})

describe("getAttackScenarios — flat array response (login initialization)", () => {
  it("maps the flat array returned by the API, not an envelope", async () => {
    mockFetch([
      {
        scenario_id: "unauthorized-destination",
        scenario_name: "Unauthorized destination access",
        threat_category: "suspicious_navigation",
      },
      {
        scenario_id: "ssrf-metadata",
        scenario_name: "SSRF against mock metadata endpoint",
        threat_category: null,
      },
    ])
    const result = await getAttackScenarios()
    expect(result).toEqual([
      {
        id: "unauthorized-destination",
        name: "Unauthorized destination access",
        description: "suspicious_navigation",
        category: "suspicious_navigation",
      },
      {
        id: "ssrf-metadata",
        name: "SSRF against mock metadata endpoint",
        description: "",
        category: "",
      },
    ])
  })

  it("returns an empty array when the API returns an empty collection", async () => {
    mockFetch([])
    const result = await getAttackScenarios()
    expect(result).toEqual([])
    expect(Array.isArray(result)).toBe(true)
  })
})

describe("getAgents — valid empty collections", () => {
  it("maps agent objects from a flat array response", async () => {
    mockFetch([
      {
        id: "agent-8873ba05d2be",
        agent_id: "agent-8873ba05d2be",
        name: "dashboard-agent",
        status: "active",
        created_at: "2026-10-31T08:30:02.609430Z",
        last_activity_at: null,
      },
    ])
    const result = await getAgents()
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe("agent-8873ba05d2be")
    expect(result[0].name).toBe("dashboard-agent")
    expect(result[0].status).toBe("Active")
  })

  it("returns an empty array when no agents exist", async () => {
    mockFetch([])
    const result = await getAgents()
    expect(result).toEqual([])
  })
})

describe("getPolicies — valid empty collections", () => {
  it("maps policy objects from a flat array response", async () => {
    mockFetch([
      {
        id: "pol-1",
        organization_id: "org-1",
        name: "Default browser egress",
        description: "desc",
        version: 1,
        is_active: true,
        is_default: true,
        allowed_domains: ["example.com"],
        blocked_domains: ["blocked.example"],
        default_domain_policy: "deny",
        allowed_ports: ["80", "443"],
        allow_private_networks: false,
        agent_id: null,
        created_at: "2026-10-31T08:30:02.630734Z",
      },
    ])
    const result = await getPolicies()
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe("pol-1")
    expect(result[0].name).toBe("Default browser egress")
    expect(result[0].active).toBe(true)
    expect(result[0].allowed_domains).toEqual(["example.com"])
  })

  it("returns an empty array when no policies exist", async () => {
    mockFetch([])
    const result = await getPolicies()
    expect(result).toEqual([])
  })
})

describe("getAudit — valid empty collections", () => {
  it("maps audit events from a flat array response", async () => {
    mockFetch([
      {
        id: "evt-1",
        event_type: "navigation.deny",
        event_category: null,
        actor: "research-agent",
        session_id: null,
        agent_id: null,
        target: null,
        decision: "deny",
        reason: "blocked",
        severity: "high",
        request_id: null,
        created_at: "2026-10-31T08:30:02Z",
      },
    ])
    const result = await getAudit()
    expect(result.items).toHaveLength(1)
    expect(result.items[0].id).toBe("evt-1")
    expect(result.items[0].agent).toBe("research-agent")
    expect(result.items[0].decision).toBe("Blocked")
  })

  it("returns an empty items array when no audit events exist", async () => {
    mockFetch([])
    const result = await getAudit()
    expect(result.items).toEqual([])
    expect(result.total).toBe(0)
  })
})
