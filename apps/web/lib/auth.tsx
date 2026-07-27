"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { authApi, tokens, workspace, workspaceApi, type User } from "./api";

interface AuthState {
  user: User | null;
  workspaceName: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [workspaceName, setWorkspaceName] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  // Ensure a workspace exists and is selected; returns its name.
  const ensureWorkspace = useCallback(async () => {
    let list = await workspaceApi.list();
    if (list.length === 0) {
      const w = await workspaceApi.create("My Workspace");
      list = [w];
    }
    const current = list.find((w) => w.id === workspace.id) || list[0];
    workspace.set(current.id);
    setWorkspaceName(current.name);
  }, []);

  const bootstrap = useCallback(async () => {
    if (!tokens.access) {
      setLoading(false);
      return;
    }
    try {
      const me = await authApi.me();
      setUser(me);
      await ensureWorkspace();
    } catch {
      tokens.clear();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [ensureWorkspace]);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  const afterAuth = useCallback(async () => {
    const me = await authApi.me();
    setUser(me);
    await ensureWorkspace();
    router.push("/dashboard");
  }, [ensureWorkspace, router]);

  const login = useCallback(
    async (email: string, password: string) => {
      const t = await authApi.login(email, password);
      tokens.set(t.access_token, t.refresh_token);
      await afterAuth();
    },
    [afterAuth]
  );

  const register = useCallback(
    async (email: string, password: string, fullName: string) => {
      const t = await authApi.register(email, password, fullName);
      tokens.set(t.access_token, t.refresh_token);
      await afterAuth();
    },
    [afterAuth]
  );

  const logout = useCallback(() => {
    const r = tokens.refresh;
    if (r) authApi.logout(r).catch(() => {});
    tokens.clear();
    setUser(null);
    setWorkspaceName(null);
    router.push("/login");
  }, [router]);

  return (
    <AuthContext.Provider value={{ user, workspaceName, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
