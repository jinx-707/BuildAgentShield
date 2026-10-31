'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';
import LayoutShell from '@/components/layout-shell';

export default function Sessions() {
  const { user, isAuthenticated } = useAuth();
  const orgId = user?.organization_id;
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    setLoading(true);
    apiClient
      .listAuditEvents(orgId, user?.token || '', { limit: 200, offset: 0 })
      .then((data: any) => {
        const events = data?.events || [];
        const seen = new Set<string>();
        const list: any[] = [];
        for (const ev of events) {
          if (ev.type === 'session.create' && ev.session_id && !seen.has(ev.session_id)) {
            seen.add(ev.session_id);
            list.push({
              session_id: ev.session_id,
              agent: ev.agent || '—',
              target: ev.target || '—',
              decision: ev.decision || 'allow',
              created_at: ev.timestamp || ev.created_at,
            });
          }
        }
        setSessions(list);
        setLoading(false);
      })
      .catch((err: any) => setError(err.message || 'Failed to load sessions'))
      .finally(() => setLoading(false));
  }, [isAuthenticated, orgId, user?.token]);

  const terminate = async (sessionId: string) => {
    // Find an agent id to terminate with; use session's agent if available
    const s = sessions.find((x) => x.session_id === sessionId);
    try {
      await apiClient.closeSession(sessionId, user?.token || '', s?.agent || undefined);
      setSessions(sessions.map((x) => (x.session_id === sessionId ? { ...x, status: 'terminated' } : x)));
    } catch (err: any) {
      setError(err.message || 'Failed to terminate session');
    }
  };

  if (!isAuthenticated) return null;
  if (loading) {
    return <LayoutShell><div className="p-8">Loading…</div></LayoutShell>;
  }

  return (
    <LayoutShell>
      <div className="px-4 py-6 sm:px-0">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Browser Sessions</h2>
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}
        <div className="bg-white shadow rounded-lg overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="p-4 text-sm font-semibold text-gray-700">Session ID</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Agent</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Current URL</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Decision</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Created</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Action</th>
              </tr>
            </thead>
            <tbody>
              {(sessions || []).map((s) => (
                <tr key={s.session_id} className="border-b border-gray-100">
                  <td className="p-4 text-sm text-gray-900 font-mono">{s.session_id}</td>
                  <td className="p-4 text-sm text-gray-700">{s.agent}</td>
                  <td className="p-4 text-sm text-gray-600">{s.target}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                      s.decision === 'allow' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                    }`}>
                      {s.decision}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-gray-600">{s.created_at}</td>
                  <td className="p-4">
                    <button
                      onClick={() => terminate(s.session_id)}
                      className="text-red-600 hover:text-red-800 text-sm"
                    >
                      Terminate
                    </button>
                  </td>
                </tr>
              ))}
              {(sessions || []).length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-gray-500">
                    No sessions recorded yet.
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
