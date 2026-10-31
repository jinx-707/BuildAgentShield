'use client';

import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { apiClient } from '@/lib/api';

const TOKEN_KEY = 'agentshield_auth_token';
const USER_KEY = 'agentshield_user';

interface AuthContextType {
  token: string | null;
  user: any | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (payload: any) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const stored = typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null;
    const storedUser = typeof window !== 'undefined' ? localStorage.getItem(USER_KEY) : null;
    if (stored) {
      setToken(stored);
      try {
        setUser(JSON.parse(storedUser || 'null'));
      } catch {
        setUser(null);
      }
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, password: string) => {
    const data = await apiClient.login(email, password);
    const userWithToken = { ...data, token: data.access_token };
    setToken(data.access_token);
    setUser(userWithToken);
    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_KEY, JSON.stringify(userWithToken));
  };

  const register = async (payload: any) => {
    await apiClient.register(payload);
  };

  const logout = async () => {
    try {
      await apiClient.logout(token || undefined);
    } catch {
      // ignore logout errors
    }
    setToken(null);
    setUser(null);
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  };

  const value = {
    token,
    user,
    isLoading,
    login,
    register,
    logout,
    isAuthenticated: !!token,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
