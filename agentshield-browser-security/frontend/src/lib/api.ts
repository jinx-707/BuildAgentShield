const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

interface ApiOptions extends RequestInit {
  authToken?: string;
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: ApiOptions = {},
  ): Promise<T> {
    const { authToken, headers = {}, ...rest } = options;

    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(headers as Record<string, string>),
    };

    if (authToken) {
      requestHeaders['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...rest,
      headers: requestHeaders,
    });

    if (!response.ok) {
      const errorData = (await response.json().catch(() => ({}))) as any;
      throw new Error(
        errorData.detail?.message ||
          errorData.message ||
          `API error: ${response.status}`,
      );
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json();
  }

  // ------------------------------------------------------------------
  // Auth
  // ------------------------------------------------------------------
  async login(email: string, password: string) {
    return this.request<any>('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async logout(authToken?: string) {
    return this.request<any>('/v1/auth/logout', {
      method: 'POST',
      authToken,
    });
  }

  async register(payload: {
    email: string;
    password: string;
    full_name?: string;
    organization_name: string;
    organization_slug: string;
  }) {
    return this.request<any>('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async me(authToken: string) {
    return this.request<any>('/v1/auth/me', { authToken });
  }

  // ------------------------------------------------------------------
  // Dashboard
  // ------------------------------------------------------------------
  async dashboard(orgId: string, authToken: string) {
    return this.request<any>(
      `/v1/organizations/${orgId}/dashboard`,
      { authToken },
    );
  }

  // ------------------------------------------------------------------
  // Organizations
  // ------------------------------------------------------------------
  async listOrganizations(authToken: string) {
    return this.request<any[]>('/v1/organizations', { authToken });
  }

  async getOrganization(orgId: string, authToken: string) {
    return this.request<any>(`/v1/organizations/${orgId}`, { authToken });
  }

  // ------------------------------------------------------------------
  // Users
  // ------------------------------------------------------------------
  async listOrgUsers(orgId: string, authToken: string) {
    return this.request<any[]>(`/v1/organizations/${orgId}/users`, {
      authToken,
    });
  }

  // ------------------------------------------------------------------
  // Agents
  // ------------------------------------------------------------------
  async listAgents(orgId: string, authToken: string) {
    return this.request<any[]>(`/v1/organizations/${orgId}/agents`, {
      authToken,
    });
  }

  async createAgent(orgId: string, name: string, authToken: string) {
    return this.request<any>(`/v1/organizations/${orgId}/agents`, {
      method: 'POST',
      body: JSON.stringify({ name }),
      authToken,
    });
  }

  async revokeAgent(agentId: string, authToken: string) {
    return this.request<any>(`/v1/agents/${agentId}/revoke`, {
      method: 'POST',
      authToken,
    });
  }

  // ------------------------------------------------------------------
  // Policies
  // ------------------------------------------------------------------
  async listPolicies(orgId: string, authToken: string) {
    return this.request<any[]>(`/v1/organizations/${orgId}/policies`, {
      authToken,
    });
  }

  async createPolicy(orgId: string, payload: any, authToken: string) {
    return this.request<any>(`/v1/organizations/${orgId}/policies`, {
      method: 'POST',
      body: JSON.stringify(payload),
      authToken,
    });
  }

  async getPolicy(policyId: string, authToken: string) {
    return this.request<any>(`/v1/policies/${policyId}`, { authToken });
  }

  async updatePolicy(policyId: string, payload: any, authToken: string) {
    return this.request<any>(`/v1/policies/${policyId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
      authToken,
    });
  }

  async listPolicyVersions(orgId: string, policyId: string, authToken: string) {
    return this.request<any[]>(
      `/v1/organizations/${orgId}/policies/${policyId}/versions`,
      { authToken },
    );
  }

  async rollbackPolicy(orgId: string, policyId: string, version: number, authToken: string) {
    return this.request<any>(
      `/v1/organizations/${orgId}/policies/${policyId}/rollback`,
      {
        method: 'POST',
        body: JSON.stringify({ version }),
        authToken,
      },
    );
  }

  async activatePolicy(orgId: string, policyId: string, authToken: string) {
    return this.request<any>(
      `/v1/organizations/${orgId}/policies/${policyId}/activate`,
      { method: 'POST', authToken },
    );
  }

  async deactivatePolicy(orgId: string, policyId: string, authToken: string) {
    return this.request<any>(
      `/v1/organizations/${orgId}/policies/${policyId}/deactivate`,
      { method: 'POST', authToken },
    );
  }

  // ------------------------------------------------------------------
  // Deployments
  // ------------------------------------------------------------------
  async listDeployments(orgId: string, authToken: string) {
    return this.request<any[]>(`/v1/organizations/${orgId}/deployments`, {
      authToken,
    });
  }

  // ------------------------------------------------------------------
  // Audit
  // ------------------------------------------------------------------
  async listAuditEvents(orgId: string, authToken: string, params?: {
    limit?: number;
    offset?: number;
  }) {
    const qs = new URLSearchParams(params as Record<string, string>);
    return this.request<any>(
      `/v1/organizations/${orgId}/audit?${qs.toString()}`,
      { authToken },
    );
  }

  // ------------------------------------------------------------------
  // Security incidents
  // ------------------------------------------------------------------
  async listIncidents(orgId: string, authToken: string) {
    return this.request<any[]>(`/v1/organizations/${orgId}/incidents`, {
      authToken,
    });
  }

  // ------------------------------------------------------------------
  // Browser (preserved existing contracts)
  // ------------------------------------------------------------------
  async navigate(data: any, authToken: string, agentId?: string) {
    return this.request<any>('/v1/browser/navigate', {
      method: 'POST',
      body: JSON.stringify(data),
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async createSession(data: any = {}, authToken: string, agentId?: string) {
    return this.request<any>('/v1/browser/session', {
      method: 'POST',
      body: JSON.stringify(data),
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async getSession(sessionId: string, authToken: string, agentId?: string) {
    return this.request<any>(`/v1/browser/session/${sessionId}`, {
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async closeSession(sessionId: string, authToken: string, agentId?: string) {
    return this.request<any>(`/v1/browser/session/${sessionId}`, {
      method: 'DELETE',
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async search(data: any, authToken: string, agentId?: string) {
    return this.request<any>('/v1/browser/search', {
      method: 'POST',
      body: JSON.stringify(data),
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async extract(data: any, authToken: string, agentId?: string) {
    return this.request<any>('/v1/browser/extract', {
      method: 'POST',
      body: JSON.stringify(data),
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async action(data: any, authToken: string, agentId?: string) {
    return this.request<any>('/v1/browser/action', {
      method: 'POST',
      body: JSON.stringify(data),
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }

  async screenshot(data: any, authToken: string, agentId?: string) {
    return this.request<any>('/v1/browser/screenshot', {
      method: 'POST',
      body: JSON.stringify(data),
      authToken,
      ...(agentId ? { headers: { 'X-Agent-ID': agentId } } : {}),
    });
  }
}

export const apiClient = new ApiClient();
