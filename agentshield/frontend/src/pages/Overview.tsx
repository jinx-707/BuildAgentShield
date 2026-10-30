import {
  Activity,
  ArrowUpRight,
  Box,
  ChevronRight,
  Clock3,
  Code2,
  Ellipsis,
  Fingerprint,
  Layers,
  LockKeyhole,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Zap,
} from "lucide-react"
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { Badge, Panel, Select, ViewLink, toneFor } from "../components/ui"
import type { Agent, AuditEvent } from "../services/demo"
import type { OverviewStats } from "../services/api"

const data = Array.from({ length: 49 }, (_, i) => {
  const wave = Math.sin(i * 1.6) * 45 + Math.sin(i * 0.61) * 40
  const peak = i > 27 && i < 35 ? 150 : i > 37 ? 60 : 0
  return {
    hour: i / 2,
    allowed: Math.round(180 + wave + peak),
    blocked: Math.round(22 + Math.abs(Math.sin(i * 1.25) * 22) + peak * 0.13),
  }
})
const metrics = [
  {
    label: "Total requests",
    value: "24,856",
    change: "12.8%",
    desc: "vs. previous period",
    icon: Activity,
    tone: "violet",
    spark: "0,25 7,22 14,27 21,17 28,20 35,12 42,16 49,9 56,13 63,3 70,7",
  },
  {
    label: "Allowed requests",
    value: "22,419",
    change: "10.2%",
    desc: "90.2% of all requests",
    icon: ShieldCheck,
    tone: "green",
    spark: "0,25 7,26 14,17 21,23 28,19 35,21 42,10 49,13 56,6 63,10 70,4",
  },
  {
    label: "Blocked threats",
    value: "1,842",
    change: "18.6%",
    desc: "Threats stopped at the gateway",
    icon: ShieldAlert,
    tone: "red",
    spark: "0,27 7,22 14,24 21,13 28,20 35,8 42,15 49,11 56,15 63,4 70,7",
  },
  {
    label: "Pending approvals",
    value: "4",
    change: null,
    desc: "4 high-priority requests",
    icon: Clock3,
    tone: "amber",
    spark: "0,21 7,21 14,26 21,18 28,18 35,10 42,15 49,8 56,14 63,10 70,12",
  },
]
export default function Overview({
  events,
  agents,
  navigate,
  range,
  setRange,
  pending,
  onEvent,
  stats,
  connected = false,
}: {
  events: AuditEvent[]
  agents: Agent[]
  navigate: (page: string) => void
  range: string
  setRange: (range: string) => void
  pending: number
  onEvent: (event: AuditEvent) => void
  stats?: OverviewStats | null
  connected?: boolean
}) {
  const factor =
    range === "Last 7 days" ? 6.8 : range === "Last 30 days" ? 27.3 : 1
  const liveSeries = Boolean(stats?.series?.length)
  const chartData: Array<{
    hour: number
    label: string
    allowed: number
    blocked: number
  }> = liveSeries
    ? stats!.series.map((point, index) => ({
        hour: index,
        label: point.label,
        allowed: point.allowed,
        blocked: point.blocked,
      }))
    : data.map((point) => ({
        ...point,
        label: `${String(point.hour === 24 ? 0 : point.hour).padStart(2, "0")}:00`,
      }))
  const totalRequests = stats
    ? stats.total_requests
    : Math.round(24856 * factor)
  const allowedRequests = stats
    ? stats.allowed_requests
    : Math.round(22419 * factor)
  const blockedThreats = stats
    ? stats.blocked_threats
    : Math.round(1842 * factor)
  const riskLegend = stats
    ? [
        {
          name: "Critical",
          value: stats.risk_distribution.critical ?? 0,
          tone: "red",
        },
        {
          name: "High",
          value: stats.risk_distribution.high ?? 0,
          tone: "orange",
        },
        {
          name: "Medium",
          value: stats.risk_distribution.medium ?? 0,
          tone: "violet",
        },
        {
          name: "Low",
          value: stats.risk_distribution.low ?? 0,
          tone: "blue",
        },
      ].map((item) => ({
        ...item,
        percent: blockedThreats
          ? `${((item.value / Math.max(1, blockedThreats)) * 100).toFixed(1)}%`
          : "0%",
      }))
    : [
        { name: "Critical", value: 124, percent: "6.7%", tone: "red" },
        { name: "High", value: 486, percent: "26.4%", tone: "orange" },
        { name: "Medium", value: 852, percent: "46.3%", tone: "violet" },
        { name: "Low", value: 380, percent: "20.6%", tone: "blue" },
      ].map((item) => ({
        ...item,
        value: Math.round(item.value * factor),
      }))
  const componentStatus = (name: string) =>
    stats?.integrations.find((item) => item.name === name)?.status
  const integrationRows = [
    {
      name: "Security engine",
      person: "P1",
      description: "Inspection & risk analysis",
      icon: ShieldCheck,
      color: "violet",
      status: componentStatus("security_engine"),
    },
    {
      name: "Offline adapters",
      person: "P2",
      description: "Files, documents & terminal",
      icon: Layers,
      color: "blue",
      status: componentStatus("offline_adapters"),
    },
    {
      name: "Online adapters",
      person: "P3",
      description: "Browser, email & payments",
      icon: Box,
      color: "green",
      status: componentStatus("online_adapters"),
    },
  ]
  const connectedCount = stats
    ? integrationRows.filter(
        (item) => item.status === "REAL" || item.status === "MOCK",
      ).length
    : 3
  return (
    <>
      <div className="security-banner">
        <span className="banner-icon">
          <ShieldCheck size={19} />
        </span>
        <div>
          <strong>Your agents. Under control.</strong>
          <span>
            Explore how the execution gateway inspects, authorizes, and protects
            every tool call.
          </span>
        </div>
        <Badge tone="green" dot>
          {connected ? "Backend connected" : "Demo environment ready"}
        </Badge>
      </div>
      <div className="overview-title">
        <div>
          <div className="eyebrow">YOUR SECURITY AT A GLANCE</div>
          <h1>
            Security overview<span className="heading-dot">.</span>
          </h1>
          <p>Real-time visibility. Enforced boundaries. Safer agents.</p>
        </div>
        <Select
          label="Dashboard period"
          value={range}
          onChange={setRange}
          options={["Last 24 hours", "Last 7 days", "Last 30 days"]}
        />
      </div>
      <div className="metric-grid">
        {metrics.map((m, index) => (
          <div className={`metric-card ${m.tone}`} key={m.label}>
            <div className="metric-label">
              <span>{m.label}</span>
              <m.icon size={17} />
            </div>
            <div className="metric-middle">
              <strong>
                {(index === 0
                  ? totalRequests
                  : index === 1
                    ? allowedRequests
                    : index === 2
                      ? blockedThreats
                      : pending
                ).toLocaleString()}
              </strong>
              <svg className="sparkline" viewBox="0 0 72 32">
                <polyline
                  points={m.spark}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.7"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            <div className="metric-foot">
              {m.change && (
                <span
                  className={`metric-change ${index === 2 ? "red" : "green"}`}
                >
                  <ArrowUpRight size={12} />
                  {m.change}
                </span>
              )}
              <span>
                {index === 3 ? `${pending} requests awaiting review` : m.desc}
              </span>
              {index === 3 && <ChevronRight size={13} />}
            </div>
          </div>
        ))}
      </div>
      <div className="chart-grid">
        <Panel
          title="Request activity"
          description="Every request. Every decision."
          className="activity-panel"
          action={
            <div className="chart-legend">
              <span>
                <i className="legend-dot green" />
                Allowed
              </span>
              <span>
                <i className="legend-dot red" />
                Blocked
              </span>
              <button
                className="icon-button"
                aria-label="Open detailed activity"
                onClick={() => navigate("Audit Logs")}
              >
                <Ellipsis size={19} />
              </button>
            </div>
          }
        >
          <div className="activity-chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={chartData}
                margin={{ top: 18, right: 5, bottom: 0, left: -25 }}
              >
                <defs>
                  <linearGradient id="allowed-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#39865A" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#39865A" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="blocked-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#C83D32" stopOpacity={0.17} />
                    <stop offset="100%" stopColor="#C83D32" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  stroke="#E7E7E1"
                  strokeDasharray="3 5"
                  vertical={false}
                />
                <XAxis
                  dataKey="hour"
                  type="number"
                  domain={liveSeries ? [0, Math.max(1, chartData.length - 1)] : [0, 24]}
                  ticks={
                    liveSeries
                      ? chartData
                          .map((point) => point.hour)
                          .filter(
                            (hour) =>
                              hour === 0 ||
                              hour === chartData.length - 1 ||
                              hour % Math.ceil(chartData.length / 6) === 0,
                          )
                      : [0, 4, 8, 12, 16, 20, 24]
                  }
                  tickFormatter={(v) =>
                    liveSeries
                      ? (chartData.find((point) => point.hour === Number(v))
                          ?.label ?? "")
                      : `${String(v === 24 ? 0 : v).padStart(2, "0")}:00`
                  }
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: "#73746E", fontSize: 10 }}
                  dy={10}
                />
                <YAxis
                  ticks={[0, 100, 200, 300, 400]}
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: "#73746E", fontSize: 10 }}
                />
                <Tooltip
                  contentStyle={{
                    background: "#FFFFFF",
                    border: "1px solid #D9DAD3",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "#171817",
                  }}
                  labelFormatter={(v) =>
                    liveSeries
                      ? (chartData.find((point) => point.hour === Number(v))
                          ?.label ?? `${v}`)
                      : `${v}:00 · ${range}`
                  }
                  formatter={(value, name) => [
                    Math.round(Number(value) * (liveSeries ? 1 : factor)),
                    name,
                  ]}
                />
                <Area
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="allowed"
                  name="Allowed"
                  stroke="#39865A"
                  fill="url(#allowed-fill)"
                  strokeWidth={2}
                  dot={false}
                />
                <Area
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="blocked"
                  name="Blocked"
                  stroke="#C83D32"
                  fill="url(#blocked-fill)"
                  strokeWidth={2}
                  dot={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-footer">
            <span>
              <span className="live-dot" />
              {connected ? "Live monitoring" : "Demo monitoring"}
            </span>
            <span>
              {connected ? "Backend activity" : "Seeded activity"}
              <Clock3 size={11} />
            </span>
          </div>
        </Panel>
        <Panel
          title="Threat distribution"
          description="Detected risks by severity"
          action={<Shield size={16} className="muted" />}
          className="distribution-panel"
        >
          <div className="donut-area">
            <div className="donut">
              <div className="donut-center">
                <span>Total threats</span>
                <strong>{blockedThreats.toLocaleString()}</strong>
                <small>
                  <ShieldCheck size={10} />
                  100% intercepted
                </small>
              </div>
            </div>
          </div>
          <div className="risk-legend">
            {riskLegend.map((r) => (
              <div key={r.name}>
                <span>
                  <i className={`legend-dot ${r.tone}`} />
                  {r.name}
                </span>
                <strong>{r.value.toLocaleString()}</strong>
                <span className="muted">{r.percent}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
      <div className="middle-grid">
        <Panel
          title="Recent security events"
          description="What your gateway is protecting against"
          action={
            <ViewLink onClick={() => navigate("Audit Logs")}>
              View audit logs
            </ViewLink>
          }
          className="events-panel"
        >
          <div className="table-scroll">
            <table className="events-table">
              <thead>
                <tr>
                  <th>AGENT / TOOL</th>
                  <th>DECISION</th>
                  <th>RISK SCORE</th>
                  <th>TIME</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 5).map((e, i) => (
                  <tr
                    key={e.id}
                    onClick={() => onEvent(e)}
                    tabIndex={0}
                    onKeyDown={(event) => event.key === "Enter" && onEvent(e)}
                  >
                    <td>
                      <div className="agent-tool">
                        <span
                          className={`event-icon ${["amber", "blue", "red", "violet", "pink"][i % 5]}`}
                        >
                          {i === 0 ? (
                            <LockKeyhole size={15} />
                          ) : i === 1 ? (
                            <ArrowUpRight size={15} />
                          ) : i === 2 ? (
                            <Terminal size={15} />
                          ) : i === 3 ? (
                            <Shield size={15} />
                          ) : (
                            <Fingerprint size={15} />
                          )}
                        </span>
                        <div>
                          <strong>{e.agent}</strong>
                          <code>{e.tool}</code>
                        </div>
                      </div>
                    </td>
                    <td>
                      <Badge tone={toneFor(e.decision)}>
                        {e.decision === "Approval"
                          ? "Needs approval"
                          : e.decision}
                      </Badge>
                    </td>
                    <td>
                      <div className="risk-score">
                        <span
                          className={e.risk >= 85 ? "text-red" : "text-amber"}
                        >
                          {e.risk}
                        </span>
                        <div className="risk-track">
                          <i
                            className={e.risk >= 85 ? "red" : "amber"}
                            style={{ width: `${e.risk}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="nowrap muted">{e.time}</td>
                    <td>
                      <ChevronRight size={13} className="muted" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer">
            <span>
              <i className="tiny-dot" />
              {connected
                ? "Live event stream · hash-chained audit log"
                : "Demo event stream · cryptographic verification not connected"}
            </span>
            <ShieldCheck size={13} />
          </div>
        </Panel>
        <Panel
          title="Integration health"
          description="Your security stack, connected"
          action={<Badge tone="neutral">{connectedCount} / 3</Badge>}
          className="integrations-panel"
        >
          {integrationRows.map((item) => {
            const status = item.status || "MOCK"
            const tone =
              status === "REAL"
                ? "green"
                : status === "MOCK"
                  ? "amber"
                  : "red"
            return (
              <div className="integration-row" key={item.person}>
                <span className={`integration-icon ${item.color}`}>
                  <item.icon size={18} />
                </span>
                <div>
                  <strong>
                    {item.name}
                    <span>{item.person}</span>
                  </strong>
                  <p>{item.description}</p>
                </div>
                <Badge tone={tone}>{status === "REAL" ? "Live" : status === "MOCK" ? "Mock" : status}</Badge>
              </div>
            )
          })}
          <div className="integration-note">
            <Code2 size={15} />
            <span>
              {connected
                ? "Connected to the live gateway and integration health API."
                : "Running with safe mock integrations."}
              <br />
              <button onClick={() => navigate("Settings")}>
                Connect your modules <ArrowUpRight size={11} />
              </button>
            </span>
          </div>
          <div className="gateway-status">
            <span>
              <i className="live-dot" />
              {connected ? "Execution gateway online" : "Mock execution gateway"}
            </span>
            <Badge tone={connected ? "green" : "green"}>
              {connected ? "Connected" : "Simulated"}
            </Badge>
          </div>
        </Panel>
      </div>
      <div className="bottom-grid">
        <div className="simulator-promo">
          <div className="promo-icon">
            <Zap size={24} />
            <div className="orbit" />
          </div>
          <div>
            <Badge tone="violet">
              <Sparkles size={10} />
              TEST YOUR DEFENSES
            </Badge>
            <h3>
              Think like an attacker. <br />
              Stay one step ahead.
            </h3>
            <p>Run real-world attack scenarios in a safe sandbox.</p>
            <button
              className="button primary"
              onClick={() => navigate("Attack Simulator")}
            >
              Open attack simulator
              <ArrowUpRight size={14} />
            </button>
          </div>
          <div className="promo-decoration">
            <ShieldCheck size={100} strokeWidth={0.7} />
          </div>
        </div>
        <Panel
          title="Agent fleet"
          description={`${agents.filter((a) => a.status === "Active").length} active agents under protection`}
          action={
            <ViewLink onClick={() => navigate("Agents")}>
              Manage agents
            </ViewLink>
          }
          className="fleet-panel"
        >
          <div className="fleet-agents">
            {agents.slice(0, 4).map((a) => (
              <button
                className="fleet-agent"
                onClick={() => navigate("Agents")}
                key={a.id}
              >
                <span className={`avatar ${a.color}`}>
                  {a.initials}
                  <i className={a.status === "Active" ? "active" : ""} />
                </span>
                <strong>{a.name}</strong>
                <span>{a.requests.toLocaleString()} requests</span>
              </button>
            ))}
          </div>
        </Panel>
      </div>
      <div className="overview-bottom">
        <span>
          <LockKeyhole size={11} />
          Enforcement by design. Not by trust.
        </span>
        <span>
          AgentShield Platform <span className="muted">v1.0.0</span>
          <i />
          {connected ? "Live environment" : "Demo environment"}
        </span>
      </div>
    </>
  )
}
