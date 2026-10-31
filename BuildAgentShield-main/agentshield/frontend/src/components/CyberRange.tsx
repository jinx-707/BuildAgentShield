import { useEffect, useRef, useState } from "react"
import {
  Activity,
  AlertCircle,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Circle,
  Clock,
  FileText,
  FlaskConical,
  Globe,
  HelpCircle,
  Loader2,
  Pause,
  Play,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Square,
  Terminal,
  Trash2,
  X,
  Zap,
} from "lucide-react"
import { Badge, Button, Empty, Modal, PageHeading, Panel, Select, Toggle } from "../components/ui"
import { streamCampaignEvents, streamSimulationEvents, type Campaign, type Simulation } from "../services/api"

export type CampaignStatus = "QUEUED" | "INITIALIZING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | "TIMED_OUT"
export type SimulationStatus = "QUEUED" | "INITIALIZING" | "RUNNING" | "DETECTED" | "BLOCKED" | "COMPLETED" | "FAILED" | "CANCELLED" | "TIMED_OUT"
export type AssessmentResult = "PASS" | "FAIL" | "ERROR" | "INCONCLUSIVE"

const STATUS_ICONS: Record<CampaignStatus, typeof Circle> = {
  QUEUED: Circle,
  INITIALIZING: Loader2,
  RUNNING: Zap,
  COMPLETED: CheckCheck,
  FAILED: AlertCircle,
  CANCELLED: X,
  TIMED_OUT: Clock,
}

const SIM_STATUS_ICONS: Record<SimulationStatus, typeof Circle> = {
  QUEUED: Circle,
  INITIALIZING: Loader2,
  RUNNING: Zap,
  DETECTED: ShieldAlert,
  BLOCKED: ShieldCheck,
  COMPLETED: CheckCheck,
  FAILED: AlertCircle,
  CANCELLED: X,
  TIMED_OUT: Clock,
}

const ASSESSMENT_COLORS: Record<AssessmentResult, string> = {
  PASS: "green",
  FAIL: "red",
  ERROR: "amber",
  INCONCLUSIVE: "neutral",
}

interface ScenarioCardProps {
  scenario: any
  available: boolean
  onRun: (id: string) => void
  disabled: boolean
}

function ScenarioCard({ scenario, available, onRun, disabled }: ScenarioCardProps) {
  return (
    <div className="panel scenario-card">
      <div className="scenario-top">
        <Badge tone={available ? "green" : "red"}>
          {available ? "Available" : "Unavailable"}
        </Badge>
        <Badge tone="violet">{scenario.risk_category}</Badge>
      </div>
      <h3>{scenario.name}</h3>
      <p>{scenario.description}</p>
      <div className="scenario-meta">
        <span>Target: <code>{scenario.target_service}</code></span>
        <span>Services: {scenario.required_services.length}</span>
      </div>
      <Button disabled={disabled || !available} onClick={() => onRun(scenario.scenario_id)}>
        <FlaskConical size={14} />
        Run Scenario
      </Button>
    </div>
  )
}

interface CampaignCardProps {
  campaign: Campaign
  onView: (id: string) => void
  onCancel: (id: string) => void
  onRun: (id: string) => void
  disabled: boolean
}

function CampaignCard({ campaign, onView, onCancel, onRun, disabled }: CampaignCardProps) {
  const StatusIcon = STATUS_ICONS[campaign.status as CampaignStatus] || Circle
  const canCancel = ["QUEUED", "INITIALIZING", "RUNNING"].includes(campaign.status)
  
  return (
    <div className="panel campaign-card">
      <div className="campaign-header">
        <div>
          <h3>{campaign.name}</h3>
          <p className="muted">{campaign.scenario_ids.length} scenarios · {campaign.execution_mode}</p>
        </div>
        <div className="campaign-status">
          <StatusIcon size={16} className={campaign.status === "RUNNING" ? "animate-spin" : ""} />
          <Badge tone={campaign.status === "COMPLETED" ? "green" : campaign.status === "FAILED" ? "red" : campaign.status === "RUNNING" ? "violet" : "neutral"}>
            {campaign.status}
          </Badge>
        </div>
      </div>
      <div className="campaign-meta">
        <span>Policy: <code>{campaign.policy_version}</code></span>
        {campaign.started_at && <span>Started: {new Date(campaign.started_at).toLocaleString()}</span>}
        {campaign.completed_at && <span>Completed: {new Date(campaign.completed_at).toLocaleString()}</span>}
        {campaign.error && <span className="error">Error: {campaign.error}</span>}
      </div>
      <div className="campaign-actions">
        <Button variant="compact" onClick={() => onView(campaign.id)} disabled={disabled}>
          <FileText size={14} />
          View Report
        </Button>
        {canCancel && (
          <Button variant="danger compact" onClick={() => onCancel(campaign.id)} disabled={disabled}>
            <X size={14} />
            Cancel
          </Button>
        )}
        {!canCancel && campaign.status !== "COMPLETED" && (
          <Button variant="compact" onClick={() => onRun(campaign.id)} disabled={disabled}>
            <RotateCcw size={14} />
            Re-run
          </Button>
        )}
      </div>
    </div>
  )
}

interface LiveExecutionProps {
  campaignId: string
  campaignName: string
  simulations: Simulation[]
  onCancel: () => void
  onClose: () => void
}

export function LiveExecution({ campaignId, campaignName, simulations, onCancel, onClose }: LiveExecutionProps) {
  const [events, setEvents] = useState<Array<{ simulationId: string; stage: string; message: string; data: any; timestamp: string }>>([])
  const [campaignEventsList, setCampaignEvents] = useState<Array<{ type: string; message: string; data: any; timestamp: string }>>([])
  const [unsubSim, setUnsubSim] = useState<(() => void) | null>(null)
  const [unsubCamp, setUnsubCamp] = useState<(() => void) | null>(null)
  const eventsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Stream campaign events
    const stopCamp = streamCampaignEvents(campaignId, (event) => {
      setCampaignEvents((prev) => [...prev, event])
    }, (error) => console.error("Campaign events error:", error))
    setUnsubCamp(stopCamp)

    // Stream simulation events for each simulation
    const stopFns: (() => void)[] = []
    simulations.forEach((sim) => {
      const stop = streamSimulationEvents(sim.id, (event) => {
        setEvents((prev) => [...prev, { ...event, simulationId: sim.id }])
      }, (error) => console.error("Simulation events error:", error))
      stopFns.push(stop)
    })
    setUnsubSim(() => () => stopFns.forEach((fn) => fn()))

    return () => {
      if (unsubCamp) unsubCamp()
      if (unsubSim) unsubSim()
    }
  }, [campaignId, simulations])

  const scrollToBottom = () => {
    eventsEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  useEffect(() => {
    scrollToBottom()
  }, [events, campaignEventsList])

  const runningSims = simulations.filter((s) => ["QUEUED", "INITIALIZING", "RUNNING", "DETECTED", "BLOCKED"].includes(s.status))
  const completedSims = simulations.filter((s) => ["COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"].includes(s.status))

  return (
    <div className="live-execution">
      <div className="live-header">
        <div>
          <h3>
            <Zap size={20} className="animate-pulse" />
            Live Execution: {campaignName}
          </h3>
          <p className="muted">Campaign ID: <code>{campaignId}</code></p>
        </div>
        <div className="live-actions">
          <Button variant="danger" onClick={onCancel}>
            <X size={16} />
            Cancel Campaign
          </Button>
          <Button variant="primary" onClick={onClose}>
            <Check size={16} />
            Close
          </Button>
        </div>
      </div>

      <div className="live-summary">
        <div className="summary-item running">
          <Loader2 size={16} className="animate-spin" />
          <span>{runningSims.length} Running</span>
        </div>
        <div className="summary-item completed">
          <CheckCheck size={16} />
          <span>{completedSims.length} Completed</span>
        </div>
        <div className="summary-item total">
          <FlaskConical size={16} />
          <span>{simulations.length} Total</span>
        </div>
      </div>

      <div className="live-tabs">
        <button className="tab-active">Simulation Events</button>
        <button className="tab-inactive">Campaign Events</button>
      </div>

      <div className="events-log">
        {events.map((event, i) => (
          <div key={i} className="event-entry">
            <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
            <span className="event-sim">[{event.simulationId.slice(0, 8)}]</span>
            <span className="event-stage">{event.stage}</span>
            <span className="event-message">{event.message}</span>
            {event.data && Object.keys(event.data).length > 0 && (
              <details>
                <summary>Data</summary>
                <pre>{JSON.stringify(event.data, null, 2)}</pre>
              </details>
            )}
          </div>
        ))}
        {campaignEventsList.map((event, i) => (
          <div key={i} className="event-entry campaign">
            <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
            <span className="event-type">{event.type}</span>
            <span className="event-message">{event.message}</span>
          </div>
        ))}
        {(events.length === 0 && campaignEventsList.length === 0) && (
          <div className="events-empty">
            <Loader2 size={24} className="animate-spin" />
            <p>Waiting for events...</p>
          </div>
        )}
        <div ref={eventsEndRef} />
      </div>

      <div className="simulations-grid">
        {simulations.map((sim) => {
          const SimStatusIcon = SIM_STATUS_ICONS[sim.status as SimulationStatus] || Circle
          const assessment = sim.assessment as AssessmentResult | null
          return (
            <div key={sim.id} className="simulation-card">
              <div className="sim-header">
                <SimStatusIcon size={16} className={sim.status === "RUNNING" ? "animate-spin" : ""} />
                <span className="sim-scenario">{sim.scenario_id}</span>
                <Badge tone={assessment ? ASSESSMENT_COLORS[assessment] : "neutral"}>
                  {assessment || sim.status}
                </Badge>
              </div>
              <div className="sim-details">
                <span>Target: <code>{sim.target_id}</code></span>
                {sim.agent_shield_decision && <span>AgentShield: {sim.agent_shield_decision}</span>}
                {sim.proxy_decision && <span>Proxy: {sim.proxy_decision}</span>}
                {sim.error && <span className="error">Error: {sim.error}</span>}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

interface EvidenceExplorerProps {
  simulationId: string
  onClose: () => void
}

export function EvidenceExplorer({ simulationId, onClose }: EvidenceExplorerProps) {
  const [evidence, setEvidence] = useState<SimulationEvidence[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedEvidence, setSelectedEvidence] = useState<SimulationEvidence | null>(null)

  useEffect(() => {
    async function load() {
      try {
        const data = await Promise.resolve([])
        // Note: This would need a proper API call to get evidence
        // For now, we'll use a placeholder
        setEvidence([])
      } catch (error) {
        console.error("Failed to load evidence:", error)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [simulationId])

  if (loading) {
    return (
      <Modal title="Evidence Explorer" onClose={onClose}>
        <Loader2 size={24} className="animate-spin mx-auto" />
      </Modal>
    )
  }

  return (
    <Modal title="Evidence Explorer" onClose={onClose} wide>
      <div className="evidence-explorer">
        <div className="evidence-list">
          {evidence.length === 0 ? (
            <Empty icon={FileText} title="No evidence collected" detail="Run a simulation to generate evidence" />
          ) : (
            evidence.map((ev) => (
              <div key={ev.id} className="evidence-item" onClick={() => setSelectedEvidence(ev)}>
                <Badge tone="violet">{ev.evidence_type}</Badge>
                <span>{ev.description || "No description"}</span>
                <span className="evidence-source">{ev.source}</span>
                <ChevronRight size={14} />
              </div>
            ))
          )}
        </div>
        {selectedEvidence && (
          <div className="evidence-detail">
            <h4>{selectedEvidence.evidence_type}</h4>
            <p>{selectedEvidence.description}</p>
            <pre>{JSON.stringify(selectedEvidence.content, null, 2)}</pre>
            <Button onClick={() => setSelectedEvidence(null)}>Close</Button>
          </div>
        )}
      </div>
    </Modal>
  )
}

interface ReportViewerProps {
  report: CampaignReport
  onClose: () => void
}

export function ReportViewer({ report, onClose }: ReportViewerProps) {
  return (
    <Modal title="Campaign Report" onClose={onClose} wide>
      <div className="report-viewer">
        <div className="report-header">
          <h3>{report.campaign_name}</h3>
          <p className="muted">Campaign ID: <code>{report.campaign_id}</code></p>
          <div className="report-meta">
            <span>Policy: <code>{report.policy_version}</code></span>
            <span>Mode: {report.execution_mode}</span>
            {report.started_at && <span>Started: {new Date(report.started_at).toLocaleString()}</span>}
            {report.completed_at && <span>Completed: {new Date(report.completed_at).toLocaleString()}</span>}
          </div>
        </div>

        <div className="report-summary">
          <div className="summary-card pass">
            <CheckCheck size={24} />
            <div>
              <strong>{report.summary.passed}</strong> Passed
            </div>
          </div>
          <div className="summary-card fail">
            <AlertCircle size={24} />
            <div>
              <strong>{report.summary.failed}</strong> Failed
            </div>
          </div>
          <div className="summary-card error">
            <X size={24} />
            <div>
              <strong>{report.summary.errors}</strong> Errors
            </div>
          </div>
          <div className="summary-card inconclusive">
            <HelpCircle size={24} />
            <div>
              <strong>{report.summary.inconclusive}</strong> Inconclusive
            </div>
          </div>
          <div className="summary-card coverage">
            <ShieldCheck size={24} />
            <div>
              <strong>{report.summary.detection_coverage_pct}%</strong> Detection
            </div>
          </div>
          <div className="summary-card coverage">
            <Shield size={24} />
            <div>
              <strong>{report.summary.enforcement_coverage_pct}%</strong> Enforcement
            </div>
          </div>
        </div>

        <Panel title="Scenario Results">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Status</th>
                  <th>Assessment</th>
                  <th>AgentShield</th>
                  <th>Proxy</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {report.scenario_results.map((r) => (
                  <tr key={r.scenario_id}>
                    <td><code>{r.scenario_id}</code></td>
                    <td><Badge tone={r.status === "COMPLETED" ? "green" : r.status === "FAILED" ? "red" : "neutral"}>{r.status}</Badge></td>
                    <td><Badge tone={r.assessment ? ASSESSMENT_COLORS[r.assessment as AssessmentResult] : "neutral"}>{r.assessment || "—"}</Badge></td>
                    <td>{r.agent_shield_decision || "—"}</td>
                    <td>{r.proxy_decision || "—"}</td>
                    <td>{r.evidence_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        {report.failed_controls.length > 0 && (
          <Panel title="Failed Controls">
            <div className="failed-controls">
              {report.failed_controls.map((f, i) => (
                <div key={i} className="failed-control">
                  <code>{f.scenario_id}</code> - {f.scenario_name}
                  <Badge tone="red">{f.assessment}</Badge>
                  {f.error && <span className="error">{f.error}</span>}
                </div>
              ))}
            </div>
          </Panel>
        )}

        {report.inconclusive_tests.length > 0 && (
          <Panel title="Inconclusive Tests">
            <div className="inconclusive-tests">
              {report.inconclusive_tests.map((t, i) => (
                <div key={i} className="inconclusive-test">
                  <code>{t.scenario_id}</code> - {t.scenario_name}
                  <span className="reason">{t.reason}</span>
                </div>
              ))}
            </div>
          </Panel>
        )}

        <Panel title="Recommendations">
          <ul>
            {report.recommendations.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </Panel>

        <Panel title="Known Limitations">
          <ul>
            {report.known_limitations.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </Panel>
      </div>
    </Modal>
  )
}