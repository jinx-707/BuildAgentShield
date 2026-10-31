import { describe, expect, it } from "vitest"
import {
  capabilities,
  initialAgents,
  initialApprovals,
  initialEvents,
  scenarios,
  simulate,
} from "./demo"

describe("safe local attack simulator", () => {
  for (const scenario of scenarios) {
    it(`intercepts ${scenario.name}`, () => {
      const result = simulate(scenario)
      expect(result.decision).toBe(scenario.expected)
      expect(result.executed).toBe(false)
      expect(result.reason.length).toBeGreaterThan(0)
    })
  }
})
describe("demo data consistency", () => {
  it("provides eleven capabilities and thirty registered tools", () => {
    expect(capabilities).toHaveLength(11)
    expect(capabilities.reduce((total, c) => total + c.tools, 0)).toBe(30)
  })
  it("uses unique event, agent, scenario, and approval identifiers", () => {
    for (const list of [
      initialAgents,
      initialEvents,
      initialApprovals,
      scenarios,
    ]) {
      expect(new Set(list.map((item) => item.id)).size).toBe(list.length)
    }
  })
  it("associates seeded approvals with existing agents", () => {
    for (const approval of initialApprovals) {
      expect(initialAgents.some((agent) => agent.name === approval.agent)).toBe(
        true,
      )
    }
  })
  it("keeps all risk scores within the supported range", () => {
    for (const event of [...initialEvents, ...initialApprovals]) {
      expect(event.risk).toBeGreaterThanOrEqual(0)
      expect(event.risk).toBeLessThanOrEqual(100)
    }
  })
})
