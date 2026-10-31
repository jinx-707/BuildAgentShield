'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';
import LayoutShell from '@/components/layout-shell';

export default function Audit() {
  const { user, isAuthenticated } = useAuth();
  const orgId = user?.organization_id;
  const [events, setEvents] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const limit = 20;

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    setLoading(true);
    apiClient
      .listAuditEvents(orgId, user?.token || '', { limit, offset })
      .then((data: any) => {
        setEvents(data?.events || []);
        setTotal(data?.total || 0);
        setLoading(false);
      })
      .catch((err: any) => setError(err.message || 'Failed to load audit logs'))
      .finally(() => setLoading(false));
  }, [isAuthenticated, orgId, user?.token, offset]);

  const pageCount = Math.ceil(total / limit);

  if (!isAuthenticated) return null;
  if (loading) {
    return <LayoutShell><div className="p-8">Loading…</div></LayoutShell>;
  }

  return (
    <LayoutShell>
      <div className="px-4 py-6 sm:px-0">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Audit Logs</h2>
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}
        <div className="bg-white shadow rounded-lg overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="p-4 text-sm font-semibold text-gray-700">ID</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Event Type</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Actor</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Session</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Decision</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Time</th>
              </tr>
            </thead>
            <tbody>
              {(events || []).map((e) => (
                <tr key={e.id || e.event_id} className="border-b border-gray-100">
                  <td className="p-4 text-sm text-gray-900 font-mono">{e.id || e.event_id}</td>
                  <td className="p-4 text-sm text-gray-700">{e.event_type || e.type}</td>
                  <td className="p-4 text-sm text-gray-600">{e.actor || '—'}</td>
                  <td className="p-4 text-sm text-gray-600 font-mono">{e.session_id || '—'}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                      e.decision === 'allow' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                    }`}>
                      {e.decision || '—'}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-gray-600">{e.timestamp || e.created_at}</td>
                </tr>
              ))}
              {(events || []).length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-gray-500">
                    No audit records yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="mt-4 flex justify-between items-center text-sm text-gray-600">
          <span>Showing {offset + 1} to {Math.min(offset + limit, total)} of {total} records</span>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="px-3 py-1 rounded border border-gray-300 hover:bg-gray-100 disabled:opacity-50"
            >
              Prev
            </button>
            <span>Page {Math.floor(offset / limit) + 1} of {pageCount}</span>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="px-3 py-1 rounded border border-gray-300 hover:bg-gray-100 disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </LayoutShell>
  );
}
