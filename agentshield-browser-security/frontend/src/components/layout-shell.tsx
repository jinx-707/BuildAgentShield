'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useAuth } from '@/components/auth-provider';
import { apiClient } from '@/lib/api';

export const navLinks = [
  { href: '/dashboard', label: 'Dashboard', icon: 'Dashboard' },
  { href: '/agents', label: 'Agents', icon: 'Agent' },
  { href: '/sessions', label: 'Sessions', icon: 'Session' },
  { href: '/policies', label: 'Policies', icon: 'Policy' },
  { href: '/events', label: 'Security Events', icon: 'Event' },
  { href: '/audit', label: 'Audit Logs', icon: 'Audit' },
];

export default function LayoutShell({ children }: { children: React.ReactNode }) {
  const { user, logout, isAuthenticated } = useAuth();
  const [open, setOpen] = useState(true);

  useEffect(() => {
    if (!isAuthenticated) {
      // handled by middleware-style redirect in pages
    }
  }, [isAuthenticated]);

  const orgId = user?.organization_id;
  const orgName = user?.organization_name || 'Organization';

  return (
    <div className="flex h-screen bg-gray-50">
      <aside className="hidden lg:flex lg:w-64 flex-col border-r border-gray-200 bg-white">
        <div className="p-6">
          <Link href="/dashboard" className="text-xl font-bold text-gray-900 flex items-center gap-2">
            <span className="bg-blue-100 text-blue-600 p-2 rounded">A</span>
            AgentShield
          </Link>
          <p className="text-xs text-gray-500 mt-1">{orgName}</p>
          <p className="text-xs text-gray-400">{orgId}</p>
        </div>
        <nav className="flex-1 px-4 space-y-1">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-lg transition col
                hover:bg-blue-50 hover:text-blue-700"
            >
              <span className="w-5 text-gray-400">{link.icon[0]}</span>
              {link.label}
            </Link>
          ))}
        </nav>
        <div className="p-4 border-t border-gray-200">
          <button
            onClick={() => logout().then(() => {})}
            className="w-full text-sm text-red-600 hover:text-red-700 flex items-center gap-2"
          >
            <span className="w-5">⏻</span>
            Sign out
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="border-b border-gray-200 bg-white px-6 py-4 flex justify-between items-center shrink-0">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setOpen(!open)}
              className="lg:hidden p-2 text-gray-600 hover:bg-gray-100 rounded"
            >
              ☰
            </button>
            <h1 className="text-lg font-semibold text-gray-900">
              {navLinks.find((l) => l.href === window.location.pathname)?.label ||
                'Dashboard'}
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500">{user?.role || 'viewer'}</span>
            <span className="w-2 h-2 rounded-full bg-green-500"></span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
