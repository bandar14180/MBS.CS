import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";

import { I18nProvider } from "@/lib/i18n";
import { ScanProgress } from "@/components/project/ScanProgress";
import { scanApi, type Scan, type ToolRun } from "@/lib/api";

// Regression cover for the scan-progress pipeline view.
//
// THE BUG THIS LOCKS DOWN: the per-tool rows disappeared from the scan card, leaving only
// the target, the comma-separated module line and the live indicator. The stage list was
// gated on `runs === null`, and the tool-runs poll swallowed every error with `catch {}` --
// so one failing (or not-yet-answered) request blanked the entire pipeline and said nothing
// about why. The stage list is derived from scan.config.requested_modules, which is already
// on the scan row, so it must render regardless of that fetch.

function wrap(ui: React.ReactNode) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

const ALL_TOOLS = [
  "subfinder", "amass", "dnsx", "httpx", "whatweb", "naabu",
  "nmap", "katana", "ffuf", "arjun", "nuclei", "nuclei-dast",
];

function mkScan(status: string, modules: string[] = ALL_TOOLS, extra: Partial<Scan> = {}): Scan {
  return {
    id: "scan-1",
    target_id: "target-1",
    scan_type: "web",
    status,
    created_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
    completed_at: null,
    config: { requested_modules: modules },
    ...extra,
  } as Scan;
}

function mkRun(tool: string, status: string, over: Partial<ToolRun> = {}): ToolRun {
  return {
    id: `run-${tool}`,
    tool_name: tool,
    tool_version: "1.0",
    status,
    exit_code: status === "completed" ? 0 : null,
    raw_output_ref: null,
    started_at: new Date().toISOString(),
    completed_at: status === "running" ? null : new Date().toISOString(),
    error_message: null,
    duration_seconds: status === "running" ? null : 4,
    ...over,
  } as ToolRun;
}

function rows(container: HTMLElement) {
  return container.querySelectorAll("ol > li");
}

describe("ScanProgress", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // The pipeline endpoint only supplies ORDER; lib/pipeline.ts falls back on its own.
    vi.spyOn(scanApi, "pipeline").mockResolvedValue([] as any);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders one row per requested tool with its backend state", async () => {
    vi.spyOn(scanApi, "toolRuns").mockResolvedValue([
      mkRun("subfinder", "completed"),
      mkRun("httpx", "running"),
    ]);

    const { container } = wrap(<ScanProgress projectId="p1" scan={mkScan("running")} />);

    await waitFor(() => expect(rows(container)).toHaveLength(ALL_TOOLS.length));
    expect(screen.getByText(/Subfinder/)).toBeInTheDocument();
    expect(screen.getByText(/Nuclei DAST/)).toBeInTheDocument();
    // States come from the ToolRun rows, not from the overall scan status.
    expect(container.textContent).toMatch(/Completed/);
    expect(container.textContent).toMatch(/Running/);
  });

  it("keeps the tool rows visible when the tool-runs request fails", async () => {
    vi.spyOn(scanApi, "toolRuns").mockRejectedValue(new Error("boom"));

    const { container } = wrap(<ScanProgress projectId="p1" scan={mkScan("running")} />);

    // The failure is surfaced rather than swallowed...
    await waitFor(() => expect(container.textContent).toMatch(/boom/));
    // ...and the regression itself: this used to collapse to a lone spinner with zero rows.
    expect(rows(container)).toHaveLength(ALL_TOOLS.length);
  });

  it("keeps the last good rows when a later poll fails", async () => {
    const spy = vi
      .spyOn(scanApi, "toolRuns")
      .mockResolvedValueOnce([mkRun("subfinder", "completed")])
      .mockRejectedValue(new Error("transient"));

    const { container } = wrap(<ScanProgress projectId="p1" scan={mkScan("running")} />);
    await waitFor(() => expect(container.textContent).toMatch(/Completed/));

    // A failing poll must not erase the completed state already reported.
    await waitFor(() => expect(spy.mock.calls.length).toBeGreaterThanOrEqual(1));
    expect(container.textContent).toMatch(/Completed/);
    expect(rows(container)).toHaveLength(ALL_TOOLS.length);
  });

  it("polls every 3 seconds while the scan is live, and stops when terminal", async () => {
    vi.useFakeTimers();
    const spy = vi.spyOn(scanApi, "toolRuns").mockResolvedValue([]);

    const { rerender } = render(
      <I18nProvider>
        <ScanProgress projectId="p1" scan={mkScan("running")} />
      </I18nProvider>
    );

    await act(async () => { await Promise.resolve(); });
    const initial = spy.mock.calls.length;
    expect(initial).toBe(1);

    await act(async () => { vi.advanceTimersByTime(3000); });
    expect(spy.mock.calls.length).toBe(initial + 1);

    await act(async () => { vi.advanceTimersByTime(3000); });
    expect(spy.mock.calls.length).toBe(initial + 2);

    // Terminal scan: the interval is torn down, so no further polling.
    rerender(
      <I18nProvider>
        <ScanProgress projectId="p1" scan={mkScan("completed")} />
      </I18nProvider>
    );
    await act(async () => { await Promise.resolve(); });
    const afterTerminal = spy.mock.calls.length;
    await act(async () => { vi.advanceTimersByTime(9000); });
    expect(spy.mock.calls.length).toBe(afterTerminal);
  });

  it("a cancelled scan does not report un-run tools as completed", async () => {
    vi.spyOn(scanApi, "toolRuns").mockResolvedValue([mkRun("subfinder", "completed")]);

    const { container } = wrap(<ScanProgress projectId="p1" scan={mkScan("cancelled")} />);

    // Wait for the one real ToolRun to land before counting.
    await waitFor(() => expect(container.textContent).toMatch(/Completed/));
    expect(rows(container)).toHaveLength(ALL_TOOLS.length);
    // Exactly one tool actually completed; the rest must NOT inherit a success state
    // just because the scan as a whole reached a terminal status.
    const completedCount = (container.textContent?.match(/Completed/g) || []).length;
    expect(completedCount).toBe(1);
    const cancelledCount = (container.textContent?.match(/Did not run \(scan cancelled\)/g) || []).length;
    expect(cancelledCount).toBe(ALL_TOOLS.length - 1);
  });

  it("renders a failed tool with its error message", async () => {
    vi.spyOn(scanApi, "toolRuns").mockResolvedValue([
      mkRun("httpx", "failed", { error_message: "connection refused" }),
    ]);

    const { container } = wrap(<ScanProgress projectId="p1" scan={mkScan("failed")} />);

    await waitFor(() => expect(container.textContent).toMatch(/connection refused/));
    expect(rows(container)).toHaveLength(ALL_TOOLS.length);
  });

  it("shows a tool that produced a run even if it was not in requested_modules", async () => {
    // AI planner / schedule / API-initiated scans can run a tool this form never selected.
    vi.spyOn(scanApi, "toolRuns").mockResolvedValue([mkRun("amass", "completed")]);

    const { container } = wrap(
      <ScanProgress projectId="p1" scan={mkScan("running", ["subfinder"])} />
    );

    await waitFor(() => expect(rows(container)).toHaveLength(2));
    expect(container.textContent).toMatch(/Amass/);
  });
});
