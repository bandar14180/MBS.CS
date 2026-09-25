import path from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// FE-2: component tests for the Next.js app.
//
// jsdom rather than a real browser: these cover component STATE and RENDERING LOGIC (filter
// wiring, overdue computation, optimistic-lock version propagation, frozen-vs-live display),
// which is where the risk actually is. End-to-end browser behaviour is a separate concern and
// is deliberately not simulated here.
//
// The `@/` alias mirrors tsconfig.json's `paths`, so tests import modules exactly as the app
// does -- a test that resolved imports differently from the build would prove nothing about
// the shipped bundle.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./") },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    // Only our own tests; never walk node_modules or build output.
    include: ["**/*.test.ts", "**/*.test.tsx"],
    exclude: ["node_modules/**", ".next/**"],
    // Deterministic in CI: no watch, no interactive reporter.
    watch: false,
  },
});
