'use client';

import { useEffect, useState, useRef } from 'react';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';
import LayoutShell from '@/components/layout-shell';

export default function Events() {
  const { user, isAuthenticated } = useAuth();
  const orgId = user?.organization_id;
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    setLoading(true);
    apiClient
      .listAuditEvents(orgId, user?.token || '', { limit: 50, offset: 0 })
      .then((data: any) => {
        setEvents((data?.events || []).slice().reverse());
        setLoading(false);
      })
      .catch((err: any) => setError(err.message || 'Failed to load events'))
      .finally(() => setLoading(false));
  }, [isAuthenticated, orgId, user?.token]);

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    const token = user?.token || '';
    const url = `${(process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000')}/v1/audit/stream?org_id=${encodeURIComponent(orgId)}&token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    esRef.current = es;
    setConnected(true);

    es.onopen = () => setConnected(true);
    es.onmessage = (e: MessageEvent) => {
      try {
        const ev = JSON.parse(e.data);
        if (ev.type === 'heartbeat') return;
        setEvents((prev) => [ev, ...prev].slice(0, 100));
      } catch {
        // ignore malformed
      }
    };
    es.onerror = () => {
      setConnected(false);
      es.close();
    };

    return () => {
      es.close();
      esRef.current = null;
      setConnected(false);
    };
  }, [isAuthenticated, orgId, user?.token]);

  if (!isAuthenticated) return null;
  if (loading) {
    return <LayoutShell><div className="p-8">Loading…</div></LayoutShell>;
  }

  return (
    <LayoutShell>
      <div className="px-4 py-6 sm:px-0">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Security Events</h2>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-gray-400'}`}></span>
            <span className="text-sm text-gray-600">{connected ? 'Live' : 'Disconnected'}</span>
          </div>
        </div>
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}
        <div className="bg-white shadow rounded-lg overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="p-4 text-sm font-semibold text-gray-700">Time</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Event Type</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Actor</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Session</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Target</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Decision</th>
              </tr>
            </thead>
            <tbody>
              {(events || []).map((e, i) => (
                <tr key={e.id || i} className="border-b border-gray-100">
                  <td className="p-4 text-sm text-gray-600 font-mono">{e.timestamp || e.created_at}</td>
                  <td className="p-4 text-sm text-gray-700">{e.event_type || e.type}</td>
                  <td className="p-4 text-sm text-gray-600">{e.actor || '—'}</td>
                  <td className="p-4 text-sm text-gray-600 font-mono">{e.session_id || '—'}</td>
                  <td className="p-4 text-sm text-gray-600 truncate max-w-xs">{e.target || '—'}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                      e.decision === 'allow' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                    }`}>
                      {e.decision || '—'}
                    </span>
                  </td>
                </tr>
              ))}
              {(events || []).length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-gray-500">
                    No security events yet. Events stream here in real time.
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
