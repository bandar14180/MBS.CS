/**
 * AUTH RACE + REFRESH CONCURRENCY -- regression tests.
 *
 * TWO INDEPENDENT DEFECTS ARE COVERED HERE.
 *
 * ISSUE A -- `auth.tsx` stale-write race.
 * Every async path in AuthProvider awaits the network and then writes React state, and nothing
 * stopped an OLD in-flight chain from landing after a NEWER auth operation:
 *   * a slow `bootstrap()` that 401s ran `tokens.clear(); setUser(null)` AFTER a login had
 *     succeeded -- the dashboard guard then bounced the user back to /login showing no error,
 *     which is exactly the reported symptom ("I click Sign in and nothing happens");
 *   * `logout()` while a bootstrap was pending let that bootstrap's `setUser(me)` RESURRECT
 *     the user after logout had cleared it;
 *   * a stale `ensureWorkspace()` wrote a PREVIOUS tenant's workspace name after logout.
 * Fixed with an `authGeneration` ref: session-creating/destroying operations bump it, and every
 * async chain refuses to write state once its captured generation is no longer current.
 *
 * ISSUE B -- `api.ts` double refresh rotation.
 * `refreshInFlight` only de-dupes OVERLAPPING callers; it is cleared in `finally`. React
 * StrictMode invokes effects twice and the second mount starts AFTER the first refresh settled,
 * so a second rotation fired using a cookie the first had already rotated away. Server-side
 * that is indistinguishable from a replay, so F-04 revoked the whole token family and session
 * recovery failed on every reload. Fixed by briefly remembering the settled result.
 *
 * These tests drive the REAL modules and mock only `fetch`, so they exercise the shipped
 * control flow rather than a re-implementation of it.
 */
import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider, useAuth } from "./auth";
import { tokens, workspace } from "./api";

// --------------------------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------------------------

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: pushMock }),
}));

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e?: unknown) => void };
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e?: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
    headers: { get: () => "application/json" },
  } as unknown as Response;
}

const USER = { id: "u1", email: "a@b.c", full_name: "A", status: "active", mfa_enabled: false };
const WS = { id: "w1", name: "Primary Workspace", plan_tier: "pilot" };

/** A tiny probe component that surfaces the provider's state for assertions. */
function Probe() {
  const { user, workspaceName, loading } = useAuth();
  return (
    <div>
      <span data-testid="user">{user ? user.email : "null"}</span>
      <span data-testid="ws">{workspaceName ?? "null"}</span>
      <span data-testid="loading">{String(loading)}</span>
    </div>
  );
}

let authRef: ReturnType<typeof useAuth> | null = null;
function Capture() {
  authRef = useAuth();
  return null;
}

function renderProvider() {
  return render(
    <AuthProvider>
      <Probe />
      <Capture />
    </AuthProvider>
  );
}

beforeEach(() => {
  pushMock.mockClear();
  authRef = null;
  tokens.clear();
  localStorage.clear();
  // Reset api.ts's module-level refresh coalescing between tests by advancing the clock.
  vi.useRealTimers();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// --------------------------------------------------------------------------------------------
// ISSUE A -- auth.tsx generation guard
// --------------------------------------------------------------------------------------------

describe("ISSUE A -- stale bootstrap must never overwrite a newer session", () => {
  it("1+2+3. a slow, failing bootstrap cannot clear a session established by login", async () => {
    const meGate = deferred<Response>();
    let meCalls = 0;

    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith("/users/me")) {
        meCalls += 1;
        // 1st call = bootstrap's (held open, then fails). 2nd = afterAuth's (succeeds).
        if (meCalls === 1) return meGate.promise;
        return jsonResponse(USER);
      }
      if (u.endsWith("/auth/refresh")) return jsonResponse({ detail: "no cookie" }, 401);
      if (u.endsWith("/auth/login")) return jsonResponse({ access_token: "NEW", refresh_token: "x" });
      if (u.endsWith("/workspaces")) return jsonResponse([WS]);
      return jsonResponse({}, 404);
    }));

    renderProvider();
    await waitFor(() => expect(authRef).not.toBeNull());

    // Log in while bootstrap's me() is still pending.
    await act(async () => { await authRef!.login("a@b.c", "pw"); });
    expect(screen.getByTestId("user").textContent).toBe("a@b.c");

    // Now let the STALE bootstrap fail. Pre-fix this ran tokens.clear() + setUser(null).
    await act(async () => {
      meGate.resolve(jsonResponse({ detail: "unauthorized" }, 401));
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(screen.getByTestId("user").textContent).toBe("a@b.c");   // session survived
    });
    expect(tokens.access).toBe("NEW");                                // token not cleared
    expect(pushMock).toHaveBeenCalledWith("/dashboard");
  });

  it("4+5. logout during a pending bootstrap does not resurrect the user or a stale workspace", async () => {
    const meGate = deferred<Response>();

    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = String(url);
      if (u.endsWith("/users/me")) return meGate.promise;      // bootstrap holds here
      if (u.endsWith("/auth/logout")) return jsonResponse({});
      if (u.endsWith("/auth/refresh")) return jsonResponse({ detail: "no" }, 401);
      if (u.endsWith("/workspaces")) return jsonResponse([WS]);
      return jsonResponse({}, 404);
    }));

    renderProvider();
    await waitFor(() => expect(authRef).not.toBeNull());

    await act(async () => { await authRef!.logout(); });
    expect(screen.getByTestId("user").textContent).toBe("null");

    // The stale bootstrap now SUCCEEDS -- it must still not write anything.
    await act(async () => {
      meGate.resolve(jsonResponse(USER));
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(screen.getByTestId("user").textContent).toBe("null");    // no resurrection
      expect(screen.getByTestId("ws").textContent).toBe("null");      // no stale tenant name
    });
    expect(pushMock).toHaveBeenCalledWith("/login");
  });

  it("6. afterAuth releases the loading gate so the dashboard guard can render", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = String(url);
      if (u.endsWith("/auth/login")) return jsonResponse({ access_token: "T", refresh_token: "x" });
      if (u.endsWith("/users/me")) return jsonResponse(USER);
      if (u.endsWith("/workspaces")) return jsonResponse([WS]);
      return jsonResponse({}, 404);
    }));

    renderProvider();
    await waitFor(() => expect(authRef).not.toBeNull());
    await act(async () => { await authRef!.login("a@b.c", "pw"); });

    await waitFor(() => {
      expect(screen.getByTestId("loading").textContent).toBe("false");
      expect(screen.getByTestId("user").textContent).toBe("a@b.c");
    });
  });

  it("7. StrictMode's double bootstrap leaves consistent state", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = String(url);
      if (u.endsWith("/users/me")) return jsonResponse({ detail: "unauthorized" }, 401);
      if (u.endsWith("/auth/refresh")) return jsonResponse({ detail: "no cookie" }, 401);
      return jsonResponse({}, 404);
    }));

    // React.StrictMode double-invokes effects, exactly as the dev app does.
    const { StrictMode } = await import("react");
    render(
      <StrictMode>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </StrictMode>
    );

    await waitFor(() => expect(screen.getByTestId("loading").textContent).toBe("false"));
    expect(screen.getByTestId("user").textContent).toBe("null");
    expect(screen.getByTestId("ws").textContent).toBe("null");
  });

  it("8. register while a bootstrap is pending -- the newer auth generation wins", async () => {
    const meGate = deferred<Response>();
    let meCalls = 0;

    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = String(url);
      if (u.endsWith("/users/me")) {
        meCalls += 1;
        if (meCalls === 1) return meGate.promise;
        return jsonResponse(USER);
      }
      if (u.endsWith("/auth/register")) return jsonResponse({ access_token: "R", refresh_token: "x" });
      if (u.endsWith("/auth/refresh")) return jsonResponse({ detail: "no" }, 401);
      if (u.endsWith("/workspaces")) return jsonResponse([WS]);
      return jsonResponse({}, 404);
    }));

    renderProvider();
    await waitFor(() => expect(authRef).not.toBeNull());
    await act(async () => { await authRef!.register("a@b.c", "pw", "A"); });

    await act(async () => {
      meGate.resolve(jsonResponse({ detail: "unauthorized" }, 401));
      await Promise.resolve();
    });

    await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("a@b.c"));
    expect(tokens.access).toBe("R");
  });
});

// --------------------------------------------------------------------------------------------
// ISSUE B -- api.ts refresh concurrency
// --------------------------------------------------------------------------------------------

describe("ISSUE B -- refresh must not rotate the cookie twice in a burst", () => {
  // api.ts keeps `refreshInFlight` and the coalesce cache at MODULE scope, and vitest reuses
  // one module instance for the whole file -- so a refresh in one test would still be inside
  // the coalesce window in the next, and the later tests would silently exercise nothing.
  // Reset the module registry before each test so every case starts from a clean api.ts.
  beforeEach(() => {
    vi.resetModules();
  });

  /** Counts how many times /auth/refresh actually hits the network. */
  function refreshCounter(opts: { refreshOk: boolean; meAlwaysUnauthorized?: boolean }) {
    let refreshCalls = 0;
    let meCalls = 0;
    const fetchMock = vi.fn(async (url: string) => {
      const u = String(url);
      if (u.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        return opts.refreshOk
          ? jsonResponse({ access_token: `ROTATED-${refreshCalls}` })
          : jsonResponse({ detail: "invalid" }, 401);
      }
      if (u.endsWith("/users/me")) {
        meCalls += 1;
        // Tests that COUNT refreshes keep every me() unauthorized, so each call genuinely
        // reaches the 401 -> tryRefresh path. (Serving a 200 to a later me() would mean that
        // call never attempted a refresh at all, and the counter would be measuring the mock
        // rather than the coalescing behaviour under test.) The wrapper's retry is one-shot,
        // so an always-401 endpoint simply settles as a failed call -- which is what these
        // tests want. Tests that assert on resulting STATE let the retry succeed.
        if (opts.meAlwaysUnauthorized || !opts.refreshOk) {
          return jsonResponse({ detail: "unauthorized" }, 401);
        }
        return meCalls === 1 ? jsonResponse({ detail: "unauthorized" }, 401) : jsonResponse(USER);
      }
      return jsonResponse({}, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
    return { get calls() { return refreshCalls; } };
  }

  it("9. concurrent same-tick 401s trigger exactly ONE network refresh", async () => {
    const c = refreshCounter({ refreshOk: true, meAlwaysUnauthorized: true });
    const { authApi } = await import("./api");
    await Promise.all([
      authApi.me().catch(() => null),
      authApi.me().catch(() => null),
      authApi.me().catch(() => null),
    ]);
    expect(c.calls).toBe(1);
  });

  it("10. StrictMode's SEQUENTIAL pair also triggers exactly ONE (the fix)", async () => {
    const c = refreshCounter({ refreshOk: true, meAlwaysUnauthorized: true });
    const { authApi } = await import("./api");
    // Sequential: the first settles before the second starts -- refreshInFlight is already
    // null, so pre-fix this rotated twice and F-04 revoked the family.
    await authApi.me().catch(() => null);
    await authApi.me().catch(() => null);
    expect(c.calls).toBe(1);
  });

  it("11. a genuine later refresh still rotates (coalescing must not block real refreshes)", async () => {
    const c = refreshCounter({ refreshOk: true, meAlwaysUnauthorized: true });
    const { authApi } = await import("./api");
    await authApi.me().catch(() => null);
    expect(c.calls).toBe(1);

    // Advance only the clock the coalesce window reads. Fake timers cannot be used here: the
    // request chain is awaited promises, not scheduled callbacks, so advancing timers would
    // never let the fetch settle. This proves the window is TIME-BOUNDED -- it suppresses the
    // StrictMode burst but never a genuine refresh after the token has actually aged.
    const realNow = Date.now.bind(Date);
    const spy = vi.spyOn(Date, "now").mockImplementation(() => realNow() + 60_000);
    try {
      await authApi.me().catch(() => null);
    } finally {
      spy.mockRestore();
    }
    expect(c.calls).toBe(2);                       // a genuine refresh still rotates
  });

  it("12. a FAILED refresh is never cached as a success", async () => {
    const c = refreshCounter({ refreshOk: false });
    const api = await import("./api");
    const { authApi } = api;
    await authApi.me().catch(() => null);
    const afterFirst = c.calls;
    // A failure must be retried, not served from the coalesce cache.
    await authApi.me().catch(() => null);
    expect(c.calls).toBeGreaterThan(afterFirst);
    expect(api.tokens.access).toBeNull();      // no phantom session
  });

  it("13. a successful refresh leaves the new access token usable in memory only", async () => {
    refreshCounter({ refreshOk: true });
    const api = await import("./api");
    await api.authApi.me().catch(() => null);
    expect(api.tokens.access).toMatch(/^ROTATED-/);
    // F-08 invariants must hold: nothing persisted, no readable refresh token.
    expect(api.tokens.refresh).toBeNull();
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      expect(localStorage.getItem(k) ?? "").not.toMatch(/ROTATED-/);
    }
    expect(sessionStorage.length).toBe(0);
  });
});
