import "@testing-library/jest-dom/vitest";

import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// Unmount between tests so one test's DOM can never satisfy the next one's query.
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
  window.localStorage.clear();
});

// The app reads tokens/workspace from localStorage (lib/api.ts). jsdom provides a real
// implementation, so nothing is stubbed here -- but the workspace id must be present or
// every `ws()` path helper throws "No workspace selected" before a component can render.
window.localStorage.setItem("mbs_workspace", "00000000-0000-0000-0000-000000000001");
