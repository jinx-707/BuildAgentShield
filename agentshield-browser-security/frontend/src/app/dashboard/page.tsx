'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';
import LayoutShell from '@/components/layout-shell';

export default function Dashboard() {
  const { user, isAuthenticated } = useAuth();
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const orgId = user?.organization_id;

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    setLoading(true);
    apiClient
      .dashboard(orgId, user?.token || '')
      .then((data: any) => {
        setMetrics(data);
        setLoading(false);
      })
      .catch((err: any) => {
        setError(err.message || 'Failed to load dashboard');
        setLoading(false);
      });
  }, [isAuthenticated, orgId, user?.token]);

  if (!isAuthenticated) return null;
  if (loading) {
    return (
      <LayoutShell>
        <div className="p-8">Loading…</div>
      </LayoutShell>
    );
  }

  return (
    <LayoutShell>
      <div className="px-4 py-6 sm:px-0">
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Security Overview</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <MetricCard
            title="Registered Agents"
            value={metrics?.registered_agents ?? 0}
            subtitle="Agents in your organization"
          />
          <MetricCard
            title="Active Sessions"
            value={metrics?.active_sessions ?? 0}
            subtitle="Live browser sessions"
          />
          <MetricCard
            title="Total Requests"
            value={metrics?.total_requests ?? 0}
            subtitle="Browser requests evaluated"
          />
          <MetricCard
            title="Blocked Requests"
            value={metrics?.blocked_requests ?? 0}
            subtitle="Denied by policy"
            variant="red"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white shadow rounded-lg p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Traffic Decision</h3>
            <div className="space-y-4">
              <DecisionRow label="Allowed" value={metrics?.allowed_requests ?? 0} total={metrics?.total_requests ?? 1} color="green" />
              <DecisionRow label="Blocked" value={metrics?.blocked_requests ?? 0} total={metrics?.total_requests ?? 1} color="red" />
              <DecisionRow label="Policy Violations" value={metrics?.policy_violations ?? 0} total={metrics?.total_requests ?? 1} color="yellow" />
            </div>
          </div>

          <div className="bg-white shadow rounded-lg p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Security Incidents</h3>
            <div className="flex items-center gap-4">
              <span className="text-3xl font-bold text-red-600">{metrics?.security_incidents ?? 0}</span>
              <p className="text-gray-600">open incidents this period</p>
            </div>
          </div>
        </div>

        <div className="mt-8 bg-white shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Service Health</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(metrics?.service_health || {}).map(([service, status]) => (
              <div key={service} className="flex items-center justify-between p-3 bg-gray-50 rounded border border-gray-100">
                <span className="text-sm text-gray-700 capitalize">{String(service).replace('_', ' ')}</span>
                <span className={`text-xs font-medium rounded-full px-2 py-1 ${
                  String(status) === 'ok' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                }`}>
                  {String(status)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </LayoutShell>
  );
}

function MetricCard({ title, value, subtitle, variant }: { title: string; value: number; subtitle: string; variant?: string }) {
  const color =
    variant === 'red'
      ? 'bg-red-100 text-red-600 border border-red-200'
      : 'bg-blue-100 text-blue-600 border border-blue-200';
  return (
    <div className="bg-white overflow-hidden shadow rounded-lg border border-gray-100">
      <div className="p-5">
        <div className="flex items-center">
          <div className={`flex-shrink-0 h-10 w-10 rounded-full flex items-center justify-center ${color}`}>
            <span className="text-sm font-bold">{title.charAt(0)}</span>
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">{title}</dt>
              <dd className="text-2xl font-bold text-gray-900">{value}</dd>
              <dt className="text-xs text-gray-400">{subtitle}</dt>
            </dl>
          </div>
        </div>
      </div>
    </div>
  );
}

function DecisionRow({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total ? Math.round((value / total) * 100) : 0;
  const barColor =
    color === 'green' ? 'bg-green-600' : color === 'red' ? 'bg-red-600' : 'bg-yellow-600';
  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="text-gray-600">{label}</span>
        <span className="font-medium text-gray-900">{value}</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div className={`${barColor} h-2 rounded-full`} style={{ width: `${Math.min(pct, 100)}%` }}></div>
      </div>
      <div className="flex justify-between text-xs text-gray-400">
        <span>0%</span>
        <span>{pct}%</span>
      </div>
    </div>
  );
}
