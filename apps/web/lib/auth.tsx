"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

import { authApi, tokens, workspace, workspaceApi, type User } from "./api";

interface AuthState {
  user: User | null;
  workspaceName: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [workspaceName, setWorkspaceName] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  // AUTH GENERATION -- the guard against a STALE async result overwriting a NEWER session.
  //
  // Every async path here (bootstrap, afterAuth, ensureWorkspace) awaits the network and then
  // writes React state. Nothing stopped an OLD in-flight chain from landing AFTER a newer auth
  // operation and clobbering it. Measured against a model of this exact state machine:
  //   * login while a slow bootstrap was pending -> bootstrap's catch ran tokens.clear() +
  //     setUser(null) AFTER the login succeeded, so the dashboard guard bounced the user back
  //     to /login with no error shown (the reported symptom);
  //   * logout while a bootstrap was pending -> bootstrap's setUser(me) RESURRECTED the user
  //     after logout had cleared it;
  //   * a stale ensureWorkspace landed setWorkspaceName() of a PREVIOUS tenant's workspace
  //     after logout.
  //
  // Every operation that creates or destroys a session (login/register via afterAuth, and
  // logout) bumps this counter FIRST. Any async chain captures it on entry and refuses to
  // write state if it is no longer current. A useRef (not useState) is required: the update
  // must be synchronous and immediately visible to already-running async closures -- a
  // useState update is scheduled and would lose this millisecond-scale race.
  const authGeneration = useRef(0);

  // Ensure a workspace exists and is selected; returns its name.
  // `gen` is the caller's auth generation: a stale caller must not write workspace state (it
  // would surface a previous tenant's workspace name after logout).
  const ensureWorkspace = useCallback(async (gen: number) => {
    let list = await workspaceApi.list();
    if (gen !== authGeneration.current) return;
    if (list.length === 0) {
      const w = await workspaceApi.create("My Workspace");
      if (gen !== authGeneration.current) return;
      list = [w];
    }
    const current = list.find((w) => w.id === workspace.id) || list[0];
    if (gen !== authGeneration.current) return;
    workspace.set(current.id);
    setWorkspaceName(current.name);
  }, []);

  // F-08: the access token is memory-only, so a reload ALWAYS starts with none. Session
  // recovery therefore runs unconditionally: `authApi.me()` 401s, the api wrapper performs its
  // one-shot refresh using the HttpOnly cookie, and the call is retried with the fresh access
  // token. No refresh token is ever read by this code -- if the cookie is missing or revoked
  // the refresh simply fails and we land unauthenticated, which is the correct outcome.
  const bootstrap = useCallback(async () => {
    // Captured on entry; every write below is refused if a newer auth operation has since
    // bumped the counter. The `catch` guard is the critical one -- that is the branch that
    // used to wipe a freshly-established session.
    const gen = authGeneration.current;
    try {
      const me = await authApi.me();
      if (gen !== authGeneration.current) return;
      setUser(me);
      await ensureWorkspace(gen);
    } catch {
      if (gen !== authGeneration.current) return;
      tokens.clear();
      setUser(null);
    } finally {
      // Only the current generation may release the loading gate: a stale bootstrap flipping
      // it would let the dashboard guard evaluate `!user` before the new session is in place.
      if (gen === authGeneration.current) setLoading(false);
    }
  }, [ensureWorkspace]);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  const afterAuth = useCallback(async () => {
    // Bump FIRST: from here on, any bootstrap that was already in flight is stale and can no
    // longer clear the token/user it is about to establish.
    authGeneration.current += 1;
    const gen = authGeneration.current;
    try {
      const me = await authApi.me();
      if (gen !== authGeneration.current) return;   // a logout raced us -- stay logged out
      setUser(me);
      await ensureWorkspace(gen);
      if (gen !== authGeneration.current) return;
      router.push("/dashboard");
    } finally {
      // The dashboard guard renders a spinner while `loading` is true. bootstrap's `finally`
      // is the only other place that clears it, and a stale bootstrap is now blocked from
      // doing so -- so a successful login must release the gate itself, and a FAILED one must
      // not leave the app spinning forever either.
      if (gen === authGeneration.current) setLoading(false);
    }
  }, [ensureWorkspace, router]);

  const login = useCallback(
    async (email: string, password: string) => {
      const t = await authApi.login(email, password);
      tokens.set(t.access_token);   // F-08: refresh arrives as an HttpOnly cookie
      await afterAuth();
    },
    [afterAuth]
  );

  const register = useCallback(
    async (email: string, password: string, fullName: string) => {
      const t = await authApi.register(email, password, fullName);
      tokens.set(t.access_token);   // F-08: refresh arrives as an HttpOnly cookie
      await afterAuth();
    },
    [afterAuth]
  );

  // F-08: the server revokes the refresh token AND expires the cookie; we drop the in-memory
  // access token and the workspace hint. Awaited so the cookie is actually gone before we
  // navigate -- a fire-and-forget call could race the redirect and leave it set.
  const logout = useCallback(async () => {
    // Bump BEFORE the await: a bootstrap already in flight must not be able to setUser(me)
    // after we clear it. Without this, logging out while a bootstrap was pending RESURRECTED
    // the user -- verified against a model of this state machine.
    authGeneration.current += 1;
    try {
      await authApi.logout();
    } catch {
      // Even if the call fails, drop local state: a client that keeps using a token it
      // believes is revoked is worse than one that re-authenticates.
    }
    tokens.clear();
    setUser(null);
    setWorkspaceName(null);
    setLoading(false);
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
