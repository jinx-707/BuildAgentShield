'use client';

import { useState } from 'react';
import { apiClient } from '@/lib/api';
import Link from 'next/link';

const scenarios = [
  { id: 'redirect-metadata', name: 'Malicious Redirect to Metadata', description: 'Test redirect to 169.254.169.254 (AWS metadata)' },
  { id: 'private-ip', name: 'Direct Private IP Access', description: 'Attempt to navigate to private/internal IP' },
  { id: 'prompt-injection', name: 'Prompt Injection Content', description: 'Navigate to page with injection payloads' },
  { id: 'cross-session', name: 'Cross-Agent Session Isolation', description: 'Test session isolation between agents' },
];

export default function AttackLab() {
  const [selectedScenario, setSelectedScenario] = useState('');
  const [agentId, setAgentId] = useState('attacker-agent-1');
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runScenario = async () => {
    setLoading(true);
    setError(null);
    setResults(null);
    
    try {
      if (selectedScenario === 'private-ip') {
        const result = await apiClient.navigate({ url: 'http://192.168.1.1/' }, agentId);
        setResults({ type: 'success', data: result });
      } else if (selectedScenario === 'redirect-metadata') {
        // This would need a server that redirects, but we test with the API
        const result = await apiClient.navigate({ url: 'http://httpbin.org/redirect-to?url=http://169.254.169.254/' }, agentId);
        setResults({ type: 'success', data: result });
      } else {
        setResults({ type: 'info', data: { message: 'Scenario requires controlled test environment. See demo documentation.' } });
      }
    } catch (err: any) {
      setResults({ type: 'blocked', error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Link href="/dashboard" className="text-xl font-bold text-gray-900">AgentShield</Link>
            </div>
            <div className="flex space-x-4 items-center">
              <Link href="/dashboard" className="text-gray-700 hover:text-gray-900 px-3 py-2">Dashboard</Link>
              <Link href="/sessions" className="text-gray-700 hover:text-gray-900 px-3 py-2">Sessions</Link>
              <Link href="/search" className="text-gray-700 hover:text-gray-900 px-3 py-2">Search</Link>
              <Link href="/events" className="text-gray-700 hover:text-gray-900 px-3 py-2">Events</Link>
              <Link href="/audit" className="text-gray-700 hover:text-gray-900 px-3 py-2">Audit</Link>
              <Link href="/policies" className="text-gray-700 hover:text-gray-900 px-3 py-2">Policies</Link>
              <Link href="/attacks" className="text-gray-900 hover:text-gray-700 px-3 py-2">Attack Lab</Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Attack Laboratory</h2>
          <p className="text-gray-600 mb-6">Controlled security simulations in isolated environment</p>
          
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700">Agent ID</label>
              <input
                type="text"
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="mt-1 block w-full max-w-md rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              />
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Select Scenario</h3>
            <div className="space-y-3 mb-6">
              {scenarios.map((scenario) => (
                <label key={scenario.id} className="flex items-start p-3 border rounded cursor-pointer hover:bg-gray-50">
                  <input
                    type="radio"
                    name="scenario"
                    value={scenario.id}
                    checked={selectedScenario === scenario.id}
                    onChange={(e) => setSelectedScenario(e.target.value)}
                    className="mt-1"
                  />
                  <div className="ml-3">
                    <div className="text-sm font-medium text-gray-900">{scenario.name}</div>
                    <div className="text-sm text-gray-500">{scenario.description}</div>
                  </div>
                </label>
              ))}
            </div>
            <button
              onClick={runScenario}
              disabled={!selectedScenario || loading}
              className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 disabled:opacity-50"
            >
              {loading ? 'Running...' : 'Run Simulation'}
            </button>
          </div>

          {results && (
            <div className={`bg-white shadow rounded-lg p-6 ${results.type === 'blocked' ? 'border-l-4 border-red-500' : results.type === 'success' ? 'border-l-4 border-green-500' : 'border-l-4 border-blue-500'}`}>
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {results.type === 'blocked' ? 'Attack Blocked' : results.type === 'success' ? 'Result' : 'Info'}
              </h3>
              {results.type === 'blocked' ? (
                <pre className="bg-red-50 p-4 rounded overflow-auto text-sm">{results.error}</pre>
              ) : (
                <pre className="bg-gray-50 p-4 rounded overflow-auto text-sm">{JSON.stringify(results.data, null, 2)}</pre>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
