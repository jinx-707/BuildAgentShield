import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

const API_BASE = ((import.meta as any).env?.VITE_AGENTSHIELD_API_URL ?? "http://127.0.0.1:8000/v1") as string;

type IntegrationStatus = "Connected" | "Degraded" | "Disconnected" | "Mock" | "Not configured";

type IntegrationHealth = {
  p1_engine: { name: string; status: IntegrationStatus; backend?: string; detail?: string; checked_at?: string };
  p2_adapters: { name: string; status: IntegrationStatus; backend?: string; detail?: string; checked_at?: string };
  p3_adapters: {
    egress_proxy: { name: string; status: IntegrationStatus; detail?: string; checked_at?: string };
    browser_worker: { name: string; status: IntegrationStatus; detail?: string; checked_at?: string };
  };
  scenarios: Array<{
    scenario_id: string;
    name: string;
    threat_category?: string;
    category?: string;
    target_service?: string;
    target_port?: number;
    available: boolean;
    status: IntegrationStatus;
    detail?: string;
    checked_at?: string;
  }>;
  checked_at?: string;
};

type Scenario = {
  scenario_id: string;
  scenario_name: string;
  threat_category?: string;
  category?: string;
};

type SimulationResult = {
  scenario_id: string;
  scenario_name: string;
  category?: string;
  threat_category?: string;
  attempted_action?: string;
  policy_decision?: string;
  enforcement_result: string;
  requests_attempted?: number;
  requests_allowed?: number;
  requests_blocked?: number;
  detection_outcome?: string;
  execution_duration_ms?: number;
  failure_reason?: string;
  evidence?: any;
};

type RunRequest = {
  organization_id: string;
  agent_id: string;
  session_id?: string;
  scenario_ids?: string[];
  external_target?: string;
};

async function api(path: string, opts: RequestInit = {}) {
  const token = localStorage.getItem("agentshield_token");
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...opts.headers,
    },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

function statusColor(status: IntegrationStatus) {
  switch (status) {
    case "Connected": return "bg-green-100 text-green-800 border-green-200";
    case "Degraded": return "bg-yellow-100 text-yellow-800 border-yellow-200";
    case "Disconnected": return "bg-red-100 text-red-800 border-red-200";
    case "Mock": return "bg-slate-100 text-slate-500 border-slate-200";
    case "Not configured": return "bg-slate-100 text-slate-400 border-slate-200";
    default: return "bg-slate-100 text-slate-400 border-slate-200";
  }
}

const CATEGORIES = [
  { id: "ai-security", label: "AI Security" },
  { id: "social-engineering", label: "Social Engineering" },
  { id: "network-security", label: "Network Security" },
  { id: "malware", label: "Malware" },
  { id: "denial-of-service", label: "Denial of Service" },
  { id: "data-loss", label: "Data Loss" },
];

export default function App() {
  const [orgId, setOrgId] = useState("");
  const [agentId, setAgentId] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [token, setToken] = useState("");
  const [health, setHealth] = useState<IntegrationHealth | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [results, setResults] = useState<SimulationResult[]>([]);
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [openRunId, setOpenRunId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const sseRef = useRef<EventSource | null>(null);

  const log = useCallback((msg: string) => {
    const ts = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev.slice(-199), `[${ts}] ${msg}`]);
  }, []);

  useEffect(() => {
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        setOrgId(payload.org ?? "");
        setAgentId(payload.sub ?? "");
      } catch {}
    }
  }, [token]);

  useEffect(() => {
    (async () => {
      try {
        const h = await api("/integrations/health");
        setHealth(h);
        setScenarios(
          (h.scenarios ?? []).map((s: any) => ({
            scenario_id: s.scenario_id,
            scenario_name: s.name,
            threat_category: s.threat_category,
            category: s.category,
          }))
        );
      } catch (e) {
        setError(`Failed to load integration health: ${(e as Error).message}`);
      }
    })();
  }, []);

  const login = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const data: any = await api("/ai-agent/authenticate", {
        method: "POST",
        body: JSON.stringify({
          agent_id: agentId,
          secret: "lab-secret-01",
        }),
      });
      setToken(data.access_token);
      localStorage.setItem("agentshield_token", data.access_token);
      setOrgId(data.organization_id);
    } catch (e) {
      setError(`Login failed: ${(e as Error).message}`);
    }
  }, [agentId]);

  const runAll = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !agentId) {
      setError("Organization and agent are required.");
      return;
    }
    setRunning(true);
    setError(null);
    setResults([]);
    setLogs([]);
    log("Starting execution of all scenarios through enforcement gateway");
    try {
      const payload: RunRequest = {
        organization_id: orgId,
        agent_id: agentId,
        session_id: sessionId || undefined,
      };
      const data: any = await api("/attack-simulation/run", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setResults(data.results ?? []);
      log(`Completed ${data.results?.length ?? 0} scenarios`);
    } catch (e) {
      setError(`Run failed: ${(e as Error).message}`);
    } finally {
      setRunning(false);
    }
  }, [orgId, agentId, sessionId, log]);

  const runScenario = useCallback(
    async (sid: string) => {
      if (!orgId || !agentId) {
        setError("Organization and agent are required.");
        return;
      }
      setRunning(true);
      setError(null);
      log(`Running scenario ${sid}`);
      try {
        const data: any = await api(`/attack-simulation/scenarios/${sid}/run`, {
          method: "POST",
          body: JSON.stringify({
            organization_id: orgId,
            agent_id: agentId,
            session_id: sessionId || undefined,
          }),
        });
        const r = (data.results ?? [])[0];
        if (r) {
          setResults((prev) => {
            const next = prev.filter((p) => p.scenario_id !== sid);
            next.push(r);
            return next;
          });
        }
        log(`Scenario ${sid}: ${r?.enforcement_result ?? "unknown"}`);
      } catch (e) {
        setError(`Scenario ${sid} failed: ${(e as Error).message}`);
      } finally {
        setRunning(false);
      }
    },
    [orgId, agentId, sessionId, log]
  );

  const openEvidence = useCallback(async (runId: string) => {
    setOpenRunId(runId);
    try {
      const data: any = await api(`/attack-simulation/runs/${runId}`);
      setEvidence(data.evidence ?? []);
    } catch (e) {
      setError(`Evidence load failed: ${(e as Error).message}`);
    }
  }, []);

  const downloadReport = useCallback(() => {
    const report = {
      generated_at: new Date().toISOString(),
      organization_id: orgId,
      results,
      health,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `agentshield-simulation-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    log("Downloaded JSON report");
  }, [orgId, results, health]);

  const filteredResults = categoryFilter
    ? results.filter((r) => r.category === categoryFilter)
    : results;

  const summary = {
    total: results.length,
    blocked: results.filter((r) => r.enforcement_result === "PASS").length,
    allowed: results.filter((r) => r.enforcement_result === "FAIL").length,
    errors: results.filter((r) => r.enforcement_result === "ERROR").length,
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="max-w-7xl mx-auto px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="rounded-lg bg-blue-900 px-3 py-1 text-white font-mono text-sm">AgentShield</span>
            <span className="text-lg font-semibold tracking-tight">Security Test Lab</span>
          </div>
          <div className="flex items-center gap-3">
            {!token ? (
              <form onSubmit={login} className="flex items-center gap-2">
                <input
                  className="border border-slate-300 rounded px-2 py-1 text-sm"
                  placeholder="agent id"
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                />
                <button className="btn-primary px-3 py-1 text-sm">Authenticate agent</button>
              </form>
            ) : (
              <div className="flex items-center gap-2 text-sm text-slate-600">
                <span className="font-medium">Org:</span> {orgId}
                <button
                  onClick={() => {
                    localStorage.removeItem("agentshield_token");
                    setToken("");
                    setOrgId("");
                    setAgentId("");
                  }}
                  className="text-red-600 hover:underline text-sm"
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
        {error && (
          <div className="max-w-7xl mx-auto px-4 py-2 bg-red-50 border border-red-100 text-red-800 rounded text-sm">
            {error}
          </div>
        )}
      </header>

      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Integration status */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="rounded-lg border p-4 bg-white shadow-sm">
            <h3 className="text-sm font-semibold text-slate-500 mb-1 uppercase tracking-wider">P1 — Security engine</h3>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium">{health?.p1_engine.name ?? "policy-engine"}</span>
              <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium border ${statusColor(health?.p1_engine.status ?? "Not configured")}`}>
                {health?.p1_engine.status ?? "Not configured"}
              </span>
            </div>
            <p className="text-xs text-slate-500">{health?.p1_engine.detail ?? ""}</p>
            <p className="text-xs text-slate-400 mt-1">{health?.p1_engine.backend ?? "—"} · {health?.p1_engine.checked_at ?? ""}</p>
          </div>
          <div className="rounded-lg border p-4 bg-white shadow-sm">
            <h3 className="text-sm font-semibold text-slate-500 mb-1 uppercase tracking-wider">P2 — Offline adapters</h3>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium">{health?.p2_adapters.name ?? "content-inspector"}</span>
              <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium border ${statusColor(health?.p2_adapters.status ?? "Not configured")}`}>
                {health?.p2_adapters.status ?? "Not configured"}
              </span>
            </div>
            <p className="text-xs text-slate-500">{health?.p2_adapters.detail ?? ""}</p>
            <p className="text-xs text-slate-400 mt-1">{health?.p2_adapters.backend ?? "—"} · {health?.p2_adapters.checked_at ?? ""}</p>
          </div>
          <div className="md:col-span-3 rounded-lg border p-4 bg-white shadow-sm">
            <h3 className="text-sm font-semibold text-slate-500 mb-2 uppercase tracking-wider">P3 — Online adapters</h3>
            <div className="grid grid-cols-2 gap-4">
              {[health?.p3_adapters?.egress_proxy, health?.p3_adapters?.browser_worker]
                .filter((x): x is NonNullable<typeof x> => Boolean(x))
                .map((c) => (
                <div key={c.name} className="rounded border p-3 bg-slate-50">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-600">{c.name}</span>
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium border ${statusColor(c.status ?? "Not configured")}`}>
                      {c.status ?? "Not configured"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">{c.detail ?? ""}</p>
                  <p className="text-[10px] text-slate-400 mt-1">{c.checked_at ?? ""}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Scenario catalog */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold">Test scenarios</h2>
            <div className="flex gap-2">
              <button
                onClick={() => setCategoryFilter(null)}
                className={`px-3 py-1 rounded text-sm border ${categoryFilter ? "border-slate-300 bg-white" : "border-blue-500 bg-blue-50 text-blue-700"}`}
              >
                All
              </button>
              {CATEGORIES.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setCategoryFilter(c.id)}
                  className={`px-3 py-1 rounded text-sm border ${categoryFilter === c.id ? "border-blue-500 bg-blue-50 text-blue-700" : "border-slate-300 bg-white"}`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>
          <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-4 py-2 font-medium text-slate-600 border-b">Category</th>
                  <th className="px-4 py-2 font-medium text-slate-600 border-b">Scenario</th>
                  <th className="px-4 py-2 font-medium text-slate-600 border-b">Action</th>
                </tr>
              </thead>
              <tbody>
                {scenarios
                  .filter((s) => !categoryFilter || s.category === categoryFilter)
                  .map((s) => (
                    <tr key={s.scenario_id} className="border-b hover:bg-slate-50/50">
                      <td className="px-4 py-3 text-slate-500">
                        {CATEGORIES.find((c) => c.id === s.category)?.label ?? s.category ?? "—"}
                      </td>
                      <td className="px-4 py-3 font-medium">{s.scenario_name}</td>
                      <td className="px-4 py-3">
                        <button
                          disabled={running || !token}
                          onClick={() => runScenario(s.scenario_id)}
                          className={`px-3 py-1.5 rounded text-sm border transition ${!token || running ? "border-slate-300 bg-slate-100 text-slate-400 cursor-not-allowed" : "border-blue-500 bg-blue-600 text-white hover:bg-blue-700"}`}
                        >
                          Run
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Run controls */}
        <section className="rounded-lg border p-5 bg-white shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
            <div>
              <h3 className="font-semibold text-slate-900">Execute campaign</h3>
              <p className="text-xs text-slate-500">Runs every scenario through the real AgentShield enforcement path.</p>
            </div>
            <form onSubmit={runAll} className="flex items-center gap-3">
              <input
                className="border border-slate-300 rounded px-3 py-2 text-sm w-48"
                placeholder="organization id"
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
              />
              <input
                className="border border-slate-300 rounded px-3 py-2 text-sm w-48"
                placeholder="agent id"
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
              />
              <input
                className="border border-slate-300 rounded px-3 py-2 text-sm w-48"
                placeholder="session id (optional)"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
              />
              <button
                disabled={running || !token}
                className={`px-4 py-2 rounded text-sm font-medium transition ${running || !token ? "border-slate-300 bg-slate-100 text-slate-400 cursor-not-allowed" : "bg-blue-600 text-white hover:bg-blue-700 border-transparent"}`}
              >
                {running ? "Running…" : "Run all scenarios"}
              </button>
            </form>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-center">
            {[
              { label: "Total", value: summary.total, color: "text-slate-900" },
              { label: "Blocked (PASS)", value: summary.blocked, color: "text-green-700" },
              { label: "Allowed (FAIL)", value: summary.allowed, color: "text-red-700" },
              { label: "Errors", value: summary.errors, color: "text-orange-700" },
            ].map((s) => (
              <div key={s.label} className="p-3 rounded bg-slate-50 border border-slate-100">
                <div className="text-xs text-slate-500 uppercase tracking-wider">{s.label}</div>
                <div className="text-xl font-mono font-bold {s.color}">{s.value}</div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex items-center gap-2">
            <button
              disabled={results.length === 0}
              onClick={downloadReport}
              className="px-3 py-1.5 rounded text-sm border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Download JSON report
            </button>
          </div>
        </section>

        {/* Results table */}
        {results.length > 0 && (
          <section className="rounded-lg border bg-white shadow-sm">
            <h3 className="px-4 py-3 font-semibold border-b border-slate-100 bg-slate-50">Execution results</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b">Scenario</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b">Category</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b">Decision</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b text-right">Attempted</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b text-right">Allowed</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b text-right">Blocked</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b text-right">Duration</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b">Detection</th>
                    <th className="px-4 py-2 font-medium text-slate-600 border-b">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.map((r) => (
                    <tr key={`${r.scenario_id}-${r.policy_decision}`} className="border-b hover:bg-slate-50/50">
                      <td className="px-4 py-3 font-medium">{r.scenario_name}</td>
                      <td className="px-4 py-3 text-slate-500">{r.category ?? "—"}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${r.enforcement_result === "PASS" ? "bg-green-100 text-green-700 border-green-200" : r.enforcement_result === "FAIL" ? "bg-red-100 text-red-700 border-red-200" : "bg-slate-100 text-slate-500 border-slate-200"}`}>
                          {r.enforcement_result}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right text-slate-500">{r.requests_attempted ?? "—"}</td>
                      <td className="px-4 py-3 text-right text-slate-500">{r.requests_allowed ?? "—"}</td>
                      <td className="px-4 py-3 text-right text-slate-500">{r.requests_blocked ?? "—"}</td>
                      <td className="px-4 py-3 text-right text-slate-500">{r.execution_duration_ms != null ? `${r.execution_duration_ms} ms` : "—"}</td>
                      <td className="px-4 py-3 text-slate-500">{r.detection_outcome ?? "—"}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => openEvidence(crypto.randomUUID())}
                          className="text-[10px] text-blue-600 underline hover:text-blue-800"
                        >
                          view
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Live execution log */}
        <section className="rounded-lg border bg-white shadow-sm">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 bg-slate-50">
            <h3 className="font-semibold">Live execution log</h3>
            <span className="text-[10px] text-slate-400">SSE stream from enforcement gateway</span>
          </div>
          <div className="p-4 font-mono text-xs text-slate-600 h-64 overflow-y-auto bg-slate-50 rounded-b-lg border-t border-slate-100">
            {logs.length ? logs.map((l, i) => <div key={i}>{l}</div>) : <span className="text-slate-400">No executions yet.</span>}
          </div>
        </section>

        {/* Evidence drawer */}
        {openRunId && (
          <div className="fixed inset-0 z-50 bg-black/40" onClick={() => setOpenRunId(null)}></div>
        )}
        {openRunId && (
          <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-white border-l border-slate-200 shadow-2xl flex flex-col">
            <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
              <h3 className="font-semibold">Evidence — {openRunId}</h3>
              <button onClick={() => setOpenRunId(null)} className="text-slate-400 hover:text-slate-600">×</button>
            </div>
            <div className="p-4 overflow-y-auto flex-1 font-mono text-xs">
              {evidence.length ? (
                evidence.map((e, i) => (
                  <div key={i} className="mb-3 p-2 rounded bg-slate-50 border border-slate-100">
                    <div className="text-xs font-medium text-slate-700 mb-1">{e.evidence_type}</div>
                    <div className="text-slate-600">{e.description}</div>
                    <pre className="mt-1 text-[10px] text-slate-500 overflow-x-auto">{JSON.stringify(e.content, null, 2)}</pre>
                  </div>
                ))
              ) : (
                <span className="text-slate-400">No evidence.</span>
              )}
            </div>
            <div className="px-4 py-3 border-t border-slate-100">
              <button onClick={() => setOpenRunId(null)} className="w-full px-3 py-1.5 rounded border border-slate-300 bg-white text-sm hover:bg-slate-50">Close</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
