'use client';

import { useState } from 'react';
import { apiClient } from '@/lib/api';
import Link from 'next/link';

export default function Search() {
  const [query, setQuery] = useState('example security');
  const [agentId, setAgentId] = useState('test-agent-1');
  const [authToken, setAuthToken] = useState('');
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await apiClient.search({ query, max_results: 10 }, agentId, authToken || undefined);
      setResults(result);
    } catch (err: any) {
      setError(err.message);
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
              <Link href="/search" className="text-gray-900 hover:text-gray-700 px-3 py-2">Search</Link>
              <Link href="/events" className="text-gray-700 hover:text-gray-900 px-3 py-2">Events</Link>
              <Link href="/audit" className="text-gray-700 hover:text-gray-900 px-3 py-2">Audit</Link>
              <Link href="/policies" className="text-gray-700 hover:text-gray-900 px-3 py-2">Policies</Link>
              <Link href="/attacks" className="text-gray-700 hover:text-gray-900 px-3 py-2">Attack Lab</Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Secure Web Search</h2>
          
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <form onSubmit={handleSearch} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Agent ID</label>
                  <input
                    type="text"
                    value={agentId}
                    onChange={(e) => setAgentId(e.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Auth Token</label>
                  <input
                    type="password"
                    value={authToken}
                    onChange={(e) => setAuthToken(e.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Search Query</label>
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? 'Searching...' : 'Search'}
              </button>
            </form>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
              {error}
            </div>
          )}

          {results && (
            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Results ({results.results?.length || 0})
              </h3>
              <div className="space-y-4">
                {results.results?.map((result: any, idx: number) => (
                  <div key={idx} className="border-b border-gray-200 pb-4 last:border-0">
                    <h4 className="text-base font-medium text-blue-600 hover:underline">
                      <a href={result.url} target="_blank" rel="noopener noreferrer">{result.title}</a>
                    </h4>
                    <p className="text-sm text-green-700 mt-1">{result.url}</p>
                    <p className="text-sm text-gray-600 mt-2">{result.snippet}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
