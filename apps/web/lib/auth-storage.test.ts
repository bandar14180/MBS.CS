/**
 * F-08 -- token storage contract (frontend half).
 *
 * Before: both the access AND refresh tokens lived in localStorage, so any XSS could read a
 * 7-day refresh credential and mint access tokens at will. Now the refresh token is an
 * HttpOnly cookie this code cannot see, and the access token is memory-only.
 *
 * These tests assert the STORAGE CONTRACT rather than mocking it away: they drive the real
 * `tokens` object and then inspect the real jsdom localStorage/sessionStorage.
 */
import { beforeEach, describe, expect, it } from "vitest";

import { tokens } from "./api";

describe("F-08 token storage", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    tokens.clear();
  });

  it("never persists the access token to localStorage or sessionStorage", () => {
    tokens.set("access-token-value");
    expect(tokens.access).toBe("access-token-value");   // available in memory
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      expect(localStorage.getItem(k)).not.toContain("access-token-value");
    }
    expect(sessionStorage.length).toBe(0);
  });

  it("has no readable refresh token at all (it is an HttpOnly cookie)", () => {
    tokens.set("access-token-value", "refresh-token-value");
    expect(tokens.refresh).toBeNull();
    // the refresh value must not have been written anywhere JS can reach
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      expect(localStorage.getItem(k)).not.toContain("refresh-token-value");
    }
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).not.toContain("refresh-token-value");
  });

  it("does not use the legacy mbs_access / mbs_refresh storage keys", () => {
    tokens.set("a", "b");
    expect(localStorage.getItem("mbs_access")).toBeNull();
    expect(localStorage.getItem("mbs_refresh")).toBeNull();
  });

  it("clear() drops the in-memory access token", () => {
    tokens.set("a");
    tokens.clear();
    expect(tokens.access).toBeNull();
  });

  it("keeps nothing in storage that could survive a reload", () => {
    // A real page reload re-evaluates the module and drops `accessToken` (module scope).
    // What we can assert deterministically here is the precondition for that: after setting
    // both tokens, NOTHING persistent holds either value, so a reload has nothing to restore.
    tokens.set("access-value", "refresh-value");
    const persisted: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      persisted.push(String(localStorage.getItem(localStorage.key(i)!)));
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      persisted.push(String(sessionStorage.getItem(sessionStorage.key(i)!)));
    }
    const blob = persisted.join("|") + "|" + document.cookie;
    expect(blob).not.toContain("access-value");
    expect(blob).not.toContain("refresh-value");
  });
});
