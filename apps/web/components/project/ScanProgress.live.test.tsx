import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, waitFor, act } from "@testing-library/react";

import { I18nProvider } from "@/lib/i18n";
import { ScanProgress } from "@/components/project/ScanProgress";
import { scanApi, type Scan, type ToolRun } from "@/lib/api";

// RUNTIME-CAPTURED regression cover.
//
// WHY THIS FILE EXISTS, SEPARATELY FROM ScanProgress.test.tsx: the hand-written unit
// tests passed the whole time the running application was broken. They pass because
// they mock `scanApi` with hand-authored objects, so they only ever proved that the
// component renders rows for a payload the TEST invented. They could not see the actual
// defect, which was not in this component at all: the live `tool_runs` table was missing
// the `effective_command`/`timed_out` columns that the ORM declares (migration
// a3b4c5d6e7f8 was never applied to the running database), so every
// GET .../scans/{id}/tool-runs answered 500 (OperationalError, MySQL 1054) and `runs`
// stayed null forever.
//
// The fixtures below are NOT hand-written. They are the verbatim bodies of the two live
// HTTP 200 responses from the running stack (through nginx -> api -> mysql) after the
// migration was applied. Rendering the real component against the real wire format is
// what proves the tool rows actually appear -- and if the API's shape ever drifts from
// what this component reads (as it just did), re-capturing these files makes that
// failure show up here instead of only in a browser.
import liveScans from "./live_scans.json";
import liveToolRuns from "./live_toolruns.json";

// The captured bodies keep their exact wire SHAPE; the workspace/project/scan/target ids
// were replaced with stable synthetic ones and the scanned hostnames redacted, so no real
// engagement data lives in the repo. Only the shape and the per-tool statuses matter here.
const LIVE_SCAN_ID = "9c5792fc-84f4-5d79-957b-0fb7b7743741";

function wrap(ui: React.ReactNode) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

function rows(container: HTMLElement) {
  return container.querySelectorAll("ol > li");
}

const scan = (liveScans as Scan[]).find((s) => s.id === LIVE_SCAN_ID) as Scan;
const runs = liveToolRuns as unknown as ToolRun[];

describe("ScanProgress against live captured API payloads", () => {
  beforeEach(() => {
    vi.spyOn(scanApi, "toolRuns").mockResolvedValue(runs);
    // Keep the pipeline on its static fallback: this test is about the tool-runs payload,
    // not about the capabilities endpoint.
    vi.spyOn(scanApi, "pipeline").mockRejectedValue(new Error("offline"));
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("the captured payloads carry the two fields the component reads", () => {
    // Guards the bug's real origin: the scan row must carry requested_modules, and the
    // tool-runs body must be an array of rows with tool_name/status.
    expect(scan.config?.requested_modules).toHaveLength(12);
    expect(Array.isArray(runs)).toBe(true);
    expect(runs.length).toBeGreaterThan(0);
    for (const r of runs) {
      expect(typeof r.tool_name).toBe("string");
      expect(typeof r.status).toBe("string");
    }
  });

  it("renders one row per tool from the live response", async () => {
    const { container } = wrap(<ScanProgress projectId="p1" scan={scan} />);
    await waitFor(() => expect(rows(container).length).toBe(12));

    // Every tool the live scan requested has its OWN row, in pipeline order.
    const labels = Array.from(rows(container)).map((li) => li.textContent || "");
    for (const tool of ["Subfinder", "Amass", "Dnsx", "Httpx", "WhatWeb", "Naabu",
                        "Nmap", "Katana", "Ffuf", "Arjun", "Nuclei", "Nuclei DAST"]) {
      expect(labels.some((l) => l.includes(tool))).toBe(true);
    }
  });

  it("renders each row's state from the live status, not a placeholder", async () => {
    const { container } = wrap(<ScanProgress projectId="p1" scan={scan} />);
    await waitFor(() => expect(rows(container).length).toBe(12));

    // The live rows really do carry per-tool statuses; assert the DOM reflects them
    // rather than showing every stage as waiting.
    const byTool = new Map(runs.map((r) => [r.tool_name, r.status]));
    const completed = Array.from(rows(container)).filter((li) =>
      li.querySelector(".text-emerald-400")
    );
    const expectedCompleted = runs.filter((r) => r.status === "completed").length;
    expect(completed.length).toBe(expectedCompleted);
    expect(expectedCompleted).toBeGreaterThan(0);
    expect(byTool.size).toBe(runs.length);
  });

  it("a 500 from tool-runs still shows every stage row (the pre-fix failure mode)", async () => {
    // This is exactly what the running app did before migration a3b4c5d6e7f8: the endpoint
    // answered 500. The rows must still come from scan.config.requested_modules, and the
    // failure must be surfaced rather than swallowed.
    vi.mocked(scanApi.toolRuns).mockRejectedValue(new Error("500 internal_error"));
    const { container } = wrap(<ScanProgress projectId="p1" scan={scan} />);
    await waitFor(() => expect(rows(container).length).toBe(12));
    // ...and the failure is surfaced rather than swallowed.
    await waitFor(() => expect(container.textContent).toContain("500 internal_error"));
  });

  it("polls tool-runs every 3s while the scan is live", async () => {
    vi.useFakeTimers();
    try {
      const spy = vi.spyOn(scanApi, "toolRuns").mockResolvedValue(runs);
      const liveScan = { ...scan, status: "running" } as Scan;
      wrap(<ScanProgress projectId="p1" scan={liveScan} />);
      await act(async () => {
        await Promise.resolve();
      });
      expect(spy).toHaveBeenCalledTimes(1);
      await act(async () => {
        vi.advanceTimersByTime(3000);
        await Promise.resolve();
      });
      expect(spy).toHaveBeenCalledTimes(2);
      await act(async () => {
        vi.advanceTimersByTime(3000);
        await Promise.resolve();
      });
      expect(spy).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });
});
