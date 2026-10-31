'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';
import LayoutShell from '@/components/layout-shell';

export default function Policies() {
  const { user, isAuthenticated } = useAuth();
  const orgId = user?.organization_id;
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: '',
    description: '',
    allowed_domains: 'example.com',
    blocked_domains: '',
    default_domain_policy: 'deny',
    allowed_ports: '80,443',
    allow_private_networks: false,
    is_default: false,
  });

  useEffect(() => {
    if (!isAuthenticated || !orgId) return;
    setLoading(true);
    apiClient
      .listPolicies(orgId, user?.token || '')
      .then((data: any[]) => setPolicies(data || []))
      .catch((err: any) => setError(err.message || 'Failed to load policies'))
      .finally(() => setLoading(false));
  }, [isAuthenticated, orgId, user?.token]);

  const createPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiClient.createPolicy(orgId!, form, user?.token || '');
      setOpen(false);
      setForm({
        name: '',
        description: '',
        allowed_domains: 'example.com',
        blocked_domains: '',
        default_domain_policy: 'deny',
        allowed_ports: '80,443',
        allow_private_networks: false,
        is_default: false,
      });
      const data = await apiClient.listPolicies(orgId!, user?.token || '');
      setPolicies(data || []);
    } catch (err: any) {
      setError(err.message || 'Failed to create policy');
    }
  };

  const activate = async (policyId: string) => {
    try {
      await apiClient.activatePolicy(orgId!, policyId, user?.token || '');
      await refresh();
    } catch (err: any) {
      setError(err.message || 'Failed to activate policy');
    }
  };

  const deactivate = async (policyId: string) => {
    try {
      await apiClient.deactivatePolicy(orgId!, policyId, user?.token || '');
      await refresh();
    } catch (err: any) {
      setError(err.message || 'Failed to deactivate policy');
    }
  };

  const rollback = async (policyId: string, version: number) => {
    if (!window.confirm(`Roll back policy to version ${version}?`)) return;
    try {
      await apiClient.rollbackPolicy(orgId!, policyId, version, user?.token || '');
      await refresh();
    } catch (err: any) {
      setError(err.message || 'Failed to roll back policy');
    }
  };

  const refresh = async () => {
    const data = await apiClient.listPolicies(orgId!, user?.token || '');
    setPolicies(data || []);
  };

  if (!isAuthenticated) return null;
  if (loading) {
    return <LayoutShell><div className="p-8">Loading…</div></LayoutShell>;
  }

  return (
    <LayoutShell>
      <div className="px-4 py-6 sm:px-0">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Policy Management</h2>
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}
        <div className="flex justify-between items-end mb-6">
          <button
            onClick={() => setOpen(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 flex items-center gap-2 text-sm"
          >
            <span>+</span> Create Policy
          </button>
        </div>

        <div className="bg-white shadow rounded-lg overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="p-4 text-sm font-semibold text-gray-700">Name</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Version</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Status</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Default Domain</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Allowed Domains</th>
                <th className="p-4 text-sm font-semibold text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(policies || []).map((p) => (
                <tr key={p.id} className="border-b border-gray-100">
                  <td className="p-4 text-gray-900">{p.name}</td>
                  <td className="p-4 text-sm text-gray-700 font-mono">v{p.version}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                      p.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'
                    }`}>
                      {p.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-gray-600">{p.default_domain_policy}</td>
                  <td className="p-4 text-sm text-gray-600 truncate max-w-xs">
                    {(p.allowed_domains || []).join(', ') || '—'}
                  </td>
                  <td className="p-4">
                    <div className="flex gap-2">
                      {p.is_active ? (
                        <button
                          onClick={() => deactivate(p.id)}
                          className="text-amber-600 hover:text-amber-800 text-sm"
                        >
                          Deactivate
                        </button>
                      ) : (
                        <button
                          onClick={() => activate(p.id)}
                          className="text-green-600 hover:text-green-800 text-sm"
                        >
                          Activate
                        </button>
                      )}
                      <button
                        onClick={() => {
                          apiClient.listPolicyVersions(orgId!, p.id, user?.token || '').then((vs) => {
                            const v = vs?.[0]?.version;
                            if (v != null) rollback(p.id, v);
                          });
                        }}
                        className="text-blue-600 hover:text-blue-800 text-sm"
                      >
                        Rollback
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {(policies || []).length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-gray-500">
                    No policies yet. Create your first policy.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {open && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
            <div className="bg-white rounded-lg shadow-xl w-full max-w-md p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">Create Policy</h3>
              <form onSubmit={createPolicy} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Name</label>
                  <input
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Allowed Domains (comma-separated)</label>
                  <input
                    value={form.allowed_domains}
                    onChange={(e) => setForm({ ...form, allowed_domains: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Blocked Domains</label>
                  <input
                    value={form.blocked_domains}
                    onChange={(e) => setForm({ ...form, blocked_domains: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Default Domain Policy</label>
                  <select
                    value={form.default_domain_policy}
                    onChange={(e) => setForm({ ...form, default_domain_policy: e.target.value })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  >
                    <option value="deny">Deny (Fail-Closed)</option>
                    <option value="allow">Allow</option>
                  </select>
                </div>
                <div className="flex gap-4 pt-2">
                  <button
                    type="button"
                    onClick={() => setOpen(false)}
                    className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded"
                  >
                    Cancel
                  </button>
                  <button type="submit" className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Create
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </LayoutShell>
  );
}
