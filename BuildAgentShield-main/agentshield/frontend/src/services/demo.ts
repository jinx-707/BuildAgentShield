export type Decision = "Blocked" | "Allowed" | "Approval" | "Quarantined" | "Redacted"
export type AuditEvent = {
  id: string
  agent: string
  tool: string
  description: string
  decision: Decision
  risk: number
  time: string
}
export type Agent = {
  id: string
  name: string
  role: string
  status: string
  requests: number
  initials: string
  color: string
}
export type Approval = {
  id: string
  agent: string
  tool: string
  summary: string
  args: Record<string, unknown>
  risk: number
  expires: string
  status: string
}
export const initialAgents: Agent[] = [
  {
    id: "agt_01",
    name: "research-agent",
    role: "Readonly researcher",
    status: "Active",
    requests: 8942,
    initials: "RA",
    color: "violet",
  },
  {
    id: "agt_02",
    name: "dev-assistant",
    role: "Developer agent",
    status: "Active",
    requests: 6218,
    initials: "DA",
    color: "blue",
  },
  {
    id: "agt_03",
    name: "email-assistant",
    role: "Email assistant",
    status: "Active",
    requests: 4316,
    initials: "EA",
    color: "green",
  },
  {
    id: "agt_04",
    name: "shopping-agent",
    role: "Shopping agent",
    status: "Active",
    requests: 2124,
    initials: "SA",
    color: "amber",
  },
  {
    id: "agt_05",
    name: "data-analyst",
    role: "Custom",
    status: "Active",
    requests: 1872,
    initials: "DA",
    color: "pink",
  },
  {
    id: "agt_06",
    name: "browser-agent",
    role: "Readonly researcher",
    status: "Disabled",
    requests: 1384,
    initials: "BA",
    color: "blue",
  },
]
export const initialEvents: AuditEvent[] = [
  {
    id: "evt_8f29c1",
    agent: "research-agent",
    tool: "read_env_var",
    description: "Attempted access to a protected environment variable",
    decision: "Blocked",
    risk: 96,
    time: "Just now",
  },
  {
    id: "evt_8f29c0",
    agent: "email-assistant",
    tool: "send_email",
    description: "Outbound email contains personally identifiable information",
    decision: "Approval",
    risk: 72,
    time: "2 min ago",
  },
  {
    id: "evt_8f29bf",
    agent: "dev-assistant",
    tool: "run_command",
    description: "Potentially destructive terminal command detected",
    decision: "Blocked",
    risk: 94,
    time: "4 min ago",
  },
  {
    id: "evt_8f29be",
    agent: "research-agent",
    tool: "browse_url",
    description: "Prompt injection detected in external webpage content",
    decision: "Quarantined",
    risk: 88,
    time: "7 min ago",
  },
  {
    id: "evt_8f29bd",
    agent: "shopping-agent",
    tool: "initiate_payment",
    description: "Payment exceeds the configured transaction limit",
    decision: "Blocked",
    risk: 85,
    time: "9 min ago",
  },
  {
    id: "evt_8f29bc",
    agent: "data-analyst",
    tool: "export_data",
    description: "Sensitive fields removed from exported report",
    decision: "Redacted",
    risk: 54,
    time: "12 min ago",
  },
  {
    id: "evt_8f29bb",
    agent: "research-agent",
    tool: "read_document",
    description: "Read an approved workspace document",
    decision: "Allowed",
    risk: 12,
    time: "14 min ago",
  },
  {
    id: "evt_8f29ba",
    agent: "dev-assistant",
    tool: "read_file",
    description: "Read a file within the authorized project scope",
    decision: "Allowed",
    risk: 8,
    time: "16 min ago",
  },
]
export const initialApprovals: Approval[] = [
  {
    id: "apr_092",
    agent: "email-assistant",
    tool: "send_email",
    summary: "Send quarterly report to external recipient",
    args: {
      to: "finance@acme.example",
      subject: "Q3 financial report",
      attachment: "quarterly-report.pdf",
      pii: "[REDACTED]",
    },
    risk: 72,
    expires: "24 minutes",
    status: "Pending",
  },
  {
    id: "apr_093",
    agent: "dev-assistant",
    tool: "delete_file",
    summary: "Delete archived build artifacts",
    args: { path: "/workspace/build/archive", recursive: true },
    risk: 64,
    expires: "38 minutes",
    status: "Pending",
  },
  {
    id: "apr_094",
    agent: "shopping-agent",
    tool: "initiate_payment",
    summary: "Purchase a team software subscription",
    args: { merchant: "Acme Software", amount: 149, currency: "USD" },
    risk: 58,
    expires: "42 minutes",
    status: "Pending",
  },
  {
    id: "apr_095",
    agent: "research-agent",
    tool: "export_data",
    summary: "Export a sanitized research dataset",
    args: { document: "research-summary.csv", destination: "approved-storage" },
    risk: 48,
    expires: "52 minutes",
    status: "Pending",
  },
]
export const capabilities = [
  {
    name: "Documents",
    key: "documents",
    description: "Read and analyze agent-accessible documents",
    tools: 2,
  },
  {
    name: "Local files",
    key: "local_files",
    description: "Scoped access to workspace files and folders",
    tools: 6,
  },
  {
    name: "System files",
    key: "system_files",
    description: "Protected operating system resources",
    tools: 2,
  },
  {
    name: "Environment & secrets",
    key: "environment",
    description: "Controlled access to environment variables",
    tools: 2,
  },
  {
    name: "Terminal",
    key: "terminal",
    description: "Sandboxed command execution",
    tools: 1,
  },
  {
    name: "Browser",
    key: "browser",
    description: "Search, browse, and interact with the web",
    tools: 4,
  },
  {
    name: "Email",
    key: "email",
    description: "Read, draft, and send messages",
    tools: 5,
  },
  {
    name: "Data loss prevention",
    key: "dlp",
    description: "Inspect, redact, and safely export data",
    tools: 3,
  },
  {
    name: "Downloads",
    key: "downloads",
    description: "Inspect and quarantine downloaded files",
    tools: 1,
  },
  {
    name: "Payments",
    key: "payments",
    description: "Budget-controlled sandbox transactions",
    tools: 2,
  },
  {
    name: "External APIs",
    key: "external_api",
    description: "Authorized API and MCP connections",
    tools: 2,
  },
]
export const policies = [
  {
    id: "pol_001",
    name: "Protected resource access",
    description:
      "Block access to system files, SSH keys, and environment secrets.",
    category: "Resource protection",
    version: 3,
    active: true,
    rule: "DENY when resource matches /.ssh/*, /etc/*, **/.env",
  },
  {
    id: "pol_002",
    name: "Outbound data protection",
    description:
      "Inspect egress traffic and redact personally identifiable information.",
    category: "Data loss prevention",
    version: 2,
    active: true,
    rule: "REDACT when egress = true and data_classification = sensitive",
  },
  {
    id: "pol_003",
    name: "Human approval for sensitive actions",
    description:
      "Require approval before email, payments, and destructive operations.",
    category: "Human oversight",
    version: 4,
    active: true,
    rule: "REQUIRE_APPROVAL for send_email, delete_file, run_command, initiate_payment",
  },
  {
    id: "pol_004",
    name: "Payment budget guardrails",
    description: "Limit transactions to $500 and approved merchants only.",
    category: "Financial safety",
    version: 2,
    active: true,
    rule: "DENY when amount > 500 or merchant not in merchant_allowlist",
  },
  {
    id: "pol_005",
    name: "Untrusted content isolation",
    description:
      "Prevent external content from escalating privileges or invoking tools.",
    category: "Prompt injection",
    version: 1,
    active: true,
    rule: "QUARANTINE when provenance.trust = untrusted and injection = true",
  },
]
export const scenarios = [
  {
    id: "pdf",
    name: "Malicious PDF injection",
    description: "A document instructs the agent to read the .env file.",
    tool: "read_env_var",
    expected: "Blocked",
    risk: 96,
    category: "Prompt injection",
    arguments: { name: "API_SECRET", source: "untrusted-pdf" },
  },
  {
    id: "ssh",
    name: "SSH key exfiltration",
    description: "An agent attempts to read a private SSH key.",
    tool: "read_system_file",
    expected: "Blocked",
    risk: 98,
    category: "Secret theft",
    arguments: { path: "/home/user/.ssh/id_rsa" },
  },
  {
    id: "traversal",
    name: "Filesystem traversal",
    description: "Escape the approved workspace using a relative path.",
    tool: "read_file",
    expected: "Blocked",
    risk: 91,
    category: "Resource access",
    arguments: { path: "../../etc/passwd" },
  },
  {
    id: "env",
    name: "Environment secret theft",
    description: "Request a protected environment credential.",
    tool: "read_env_var",
    expected: "Blocked",
    risk: 96,
    category: "Secret theft",
    arguments: { name: "DATABASE_PASSWORD" },
  },
  {
    id: "terminal",
    name: "Destructive terminal command",
    description: "Attempt a dangerous recursive delete command.",
    tool: "run_command",
    expected: "Blocked",
    risk: 99,
    category: "Code execution",
    arguments: { command: "rm -rf /" },
  },
  {
    id: "pii",
    name: "PII leakage through email",
    description: "Send sensitive customer information to an external address.",
    tool: "send_email",
    expected: "Blocked",
    risk: 92,
    category: "Data exfiltration",
    arguments: {
      to: "external@example.test",
      body: "[SIMULATED SENSITIVE CUSTOMER DATA]",
    },
  },
  {
    id: "browser",
    name: "Malicious browser content",
    description: "A webpage attempts to override the agent’s instructions.",
    tool: "browse_url",
    expected: "Quarantined",
    risk: 88,
    category: "Prompt injection",
    arguments: { url: "https://malicious.example.test", trust: "untrusted" },
  },
  {
    id: "payment",
    name: "Payment above budget",
    description: "Attempt a payment that exceeds the $500 transaction limit.",
    tool: "initiate_payment",
    expected: "Blocked",
    risk: 85,
    category: "Financial abuse",
    arguments: { amount: 2500, currency: "USD", merchant: "unknown" },
  },
  {
    id: "tampering",
    name: "Approval argument tampering",
    description: "Change the payment amount after human approval.",
    tool: "initiate_payment",
    expected: "Blocked",
    risk: 95,
    category: "Approval bypass",
    arguments: { amount: 9999, token: "demo-tampered-token" },
  },
  {
    id: "replay",
    name: "Approval token replay",
    description: "Reuse an approval token that has already been consumed.",
    tool: "send_email",
    expected: "Blocked",
    risk: 90,
    category: "Approval bypass",
    arguments: { token: "demo-consumed-token" },
  },
]

// Local demonstration rules, not a substitute for server-side authorization.
export function simulate(
  scenario: typeof scenarios[number],
): {
  decision: Decision
  reason: string
  executed: boolean
} {
  const payload = JSON.stringify(scenario.arguments)
  if (scenario.tool === "browse_url" && payload.includes("untrusted"))
    return {
      decision: "Quarantined",
      reason: "Untrusted content isolated by prompt-injection policy.",
      executed: false,
    }
  if (
    /\.ssh|\.\.\/|SECRET|PASSWORD|rm -rf|SENSITIVE|token/.test(payload) ||
    scenario.tool === "initiate_payment"
  )
    return {
      decision: "Blocked",
      reason: "Demo policy denied the request before adapter execution.",
      executed: false,
    }
  return {
    decision: "Approval",
    reason: "Unknown context requires human review.",
    executed: false,
  }
}

export function exportFile(
  filename: string,
  contents: string,
  type = "application/json",
) {
  const url = URL.createObjectURL(new Blob([contents], { type }))
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
