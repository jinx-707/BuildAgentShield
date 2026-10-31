'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';
import LayoutShell from '@/components/layout-shell';

export default function Agents() {
  const { user, isAuthenticated } = useAuth();
  const orgId = user?.organization_id;
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [agentName, setAgentName] = useState('');

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    setLoading(true);
    apiClient
      .listAgents(orgId, user?.token || '')
      .then((data: any[]) => setAgents(data || []))
      .catch((err: any) => setError(err.message || 'Failed to load agents'))
      .finally(() => setLoading(false));
  }, [isAuthenticated, orgId, user?.token]);

  const createAgent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agentName) return;
    try {
      const data = await apiClient.createAgent(orgId!, agentName, user?.token || '');
      setAgents([...agents, data]);
      setAgentName('');
    } catch (err: any) {
      setError(err.message || 'Failed to create agent');
    }
  };

  const revokeAgent = async (agentId: string) => {
    if (!window.confirm('Revoke this agent? Its credentials will be invalidated.')) return;
    try {
      await apiClient.revokeAgent(agentId, user?.token || '');
      setAgents(agents.map((a) => (a.agent_id === agentId ? { ...a, status: 'revoked' } : a)));
    } catch (err: any) {
      setError(err.message || 'Failed to revoke agent');
    }
  };

  if (!isAuthenticated) return null;
  if (loading) {
    return <LayoutShell><div className="p-8">Loading…</div></LayoutShell>;
  }

  return (
    <LayoutShell>
      <div className="px-4 py-6 sm:px-0">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Agent Management</h2>
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Register Agent</h3>
          <form onSubmit={createAgent} className="flex gap-3">
            <input
              type="text"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              placeholder="Agent name"
              className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 px-3 py-2"
              required
            />
            <button
              type="submit"
              className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
            >
              Register
            </button>
          </form>
          <p className="text-xs text-gray-500 mt-2">
            The agent credential secret is shown only once at creation. Store it securely.
          </p>
        </div>

        <div className="bg-white shadow rounded-lg overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="p-4 text-sm font-semibold text-gray-700">Name</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Agent ID</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Status</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Last Activity</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(agents || []).map((agent) => (
                <tr key={agent.id || agent.agent_id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="p-4 text-gray-900">{agent.name}</td>
                  <td className="p-4 text-sm text-gray-900 font-mono">{agent.agent_id}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                      agent.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                    }`}>
                      {agent.status}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-gray-600">
                    {agent.last_activity_at || '—'}
                  </td>
                  <td className="p-4">
                    {agent.status === 'active' ? (
                      <button
                        onClick={() => revokeAgent(agent.agent_id)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Revoke
                      </button>
                    ) : (
                      <span className="text-sm text-gray-400">Revoked</span>
                    )}
                  </td>
                </tr>
              ))}
              {(agents || []).length === 0 && (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-gray-500">
                    No agents registered yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </LayoutShell>
  );
}
