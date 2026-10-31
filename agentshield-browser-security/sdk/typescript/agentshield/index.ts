/**
 * AgentShield TypeScript SDK for AI agent integration.
 *
 * Mediates AI agent actions (navigate, browser actions, tool calls) through
 * the AgentShield enforcement architecture: Policy Engine -> Browser Worker
 * -> Egress Proxy.
 *
 * Agent credentials (agentId + secret) are held by the caller; the secret is
 * never logged and is only sent in the authenticated request to AgentShield.
 */

export class AgentShieldError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = "AgentShieldError";
  }
}

export class AgentShieldAuthError extends AgentShieldError {
  constructor(message = "invalid agent id or secret") {
    super(message, 401);
    this.name = "AgentShieldAuthError";
  }
}

export interface AgentShieldClientOptions {
  baseUrl: string;
  agentId: string;
  secret: string;
  timeout?: number;
}

export interface AuthenticateResult {
  agentId: string;
  organizationId: string | null;
  name: string | null;
}

export interface ActionOptions {
  action: string;
  target?: string;
  sessionId?: string;
  toolName?: string;
  toolArgs?: Record<string, unknown>;
}

export interface ActionResult {
  executionId: string;
  agentId: string;
  organizationId: string;
  action: string;
  decision: string;
  reason: string;
  severity: string;
  riskScore: number | null;
  threat: Record<string, unknown>;
  dlp: Record<string, unknown>;
  risk: Record<string, unknown>;
  enforcement: Record<string, unknown> | null;
  createdAt: string | null;
}

export class AgentShieldClient {
  private baseUrl: string;
  private agentId: string;
  private secret: string;
  private timeout: number;
  private accessToken: string | null = null;
  private organizationId: string | null = null;

  constructor(options: AgentShieldClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.agentId = options.agentId;
    this.secret = options.secret;
    this.timeout = options.timeout ?? 30000;
  }

  async authenticate(): Promise<AuthenticateResult> {
    const resp = await fetch(`${this.baseUrl}/v1/ai-agent/authenticate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: this.agentId, secret: this.secret }),
    });

    if (resp.status === 401) {
      throw new AgentShieldAuthError();
    }
    if (!resp.ok) {
      throw new AgentShieldError(
        `authentication failed: ${resp.status} ${await resp.text()}`,
        resp.status,
      );
    }

    const data = (await resp.json()) as Record<string, unknown>;
    this.accessToken = (data.access_token ?? data.token) as string | null;
    this.organizationId = (data.organization_id ?? null) as string | null;

    return {
      agentId: (data.agent_id ?? this.agentId) as string,
      organizationId: this.organizationId,
      name: (data.name ?? null) as string | null,
    };
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }
    return headers;
  }

  private async post<T>(
    path: string,
    payload: Record<string, unknown>,
  ): Promise<T> {
    if (this.accessToken === null) {
      await this.authenticate();
    }
    let resp = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(payload),
    });

    if (resp.status === 401) {
      await this.authenticate();
      resp = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(payload),
      });
    }

    if (!resp.ok) {
      throw new AgentShieldError(
        `request failed: ${resp.status} ${await resp.text()}`,
        resp.status,
      );
    }

    return (await resp.json()) as T;
  }

  async navigate(options: {
    url: string;
    sessionId?: string;
    waitUntil?: string;
    timeoutMs?: number;
  }): Promise<ActionResult> {
    return this.post<ActionResult>("/v1/ai-agent/action", {
      action: "navigate",
      target: options.url,
      session_id: options.sessionId,
      tool_args: {
        wait_until: options.waitUntil ?? "networkidle2",
        timeout_ms: options.timeoutMs ?? 15000,
      },
    });
  }

  async action(options: ActionOptions): Promise<ActionResult> {
    return this.post<ActionResult>("/v1/ai-agent/action", {
      action: options.action,
      target: options.target,
      session_id: options.sessionId,
      tool_name: options.toolName,
      tool_args: options.toolArgs ?? {},
    });
  }

  async toolCall(options: {
    toolName: string;
    toolArgs?: Record<string, unknown>;
    sessionId?: string;
  }): Promise<ActionResult> {
    return this.action({
      action: "tool_call",
      toolName: options.toolName,
      toolArgs: options.toolArgs,
      sessionId: options.sessionId,
    });
  }
}

export { AgentShieldClient as default };
