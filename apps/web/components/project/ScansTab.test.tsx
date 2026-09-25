import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { I18nProvider } from "@/lib/i18n";
import { ScansTab } from "@/components/project/ScansTab";
import { scanApi, scheduleApi, type Target } from "@/lib/api";
import { FALLBACK_PIPELINE } from "@/lib/pipeline";

// Cover for the "select all" tool-selection shortcut on the New Scan form.
//
// The invariant these lock down: "select all" is a SELECTION shortcut only. It expands to
// the same explicit tool names an operator would tick by hand, so the POST body is
// indistinguishable from a hand-picked full selection and the server's active-testing
// authorization check (apps/api/modules/scans/service.py) still sees -- and can still
// reject -- every active tool. There is deliberately no "all tools" mode on the wire.

const ALL_TOOLS = FALLBACK_PIPELINE.map((p) => p.name);
// Mirrors ScansTab's DEFAULT_MODULES: passive/recon only, active tools opt-in.
const DEFAULT_MODULES = ["subfinder", "httpx", "naabu", "nmap", "katana"];
const ACTIVE_TOOLS = ["ffuf", "arjun", "nuclei", "nuclei-dast"];

const TARGETS: Target[] = [
  { id: "t1", value: "example.com", type: "domain" } as Target,
];

function wrap() {
  return render(
    <I18nProvider>
      <ScansTab projectId="p1" targets={TARGETS} />
    </I18nProvider>
  );
}

/** The tool checkboxes are the ones labelled with a pipeline tool name; the form also
 *  carries an unrelated "Use AI planner" checkbox that must never be swept up. */
function toolBox(name: string): HTMLInputElement {
  const label = screen
    .getAllByText(name, { selector: "span" })
    .map((el) => el.closest("label"))
    .find(Boolean) as HTMLElement;
  return label.querySelector('input[type="checkbox"]') as HTMLInputElement;
}

function checkedTools(): string[] {
  return ALL_TOOLS.filter((n) => toolBox(n).checked);
}

function allControl() {
  return screen.getByRole("button", { name: /select all|clear all/i });
}

describe("ScansTab tool selection", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(scanApi, "pipeline").mockResolvedValue(FALLBACK_PIPELINE as any);
    vi.spyOn(scanApi, "list").mockResolvedValue([] as any);
    vi.spyOn(scheduleApi, "list").mockResolvedValue([] as any);
  });

  it("starts on the passive defaults with the control offering Select all", async () => {
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    expect(checkedTools()).toEqual(DEFAULT_MODULES);
    // No active tool is pre-selected: active testing stays opt-in per scan.
    for (const tool of ACTIVE_TOOLS) expect(toolBox(tool).checked).toBe(false);
    expect(allControl()).toHaveTextContent(/select all/i);
  });

  it("selects every available tool and flips the control to Clear all", async () => {
    const user = userEvent.setup();
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    await user.click(allControl());

    // Every individual checkbox reflects the new state, not just the control.
    expect(checkedTools()).toEqual(ALL_TOOLS);
    for (const tool of ALL_TOOLS) expect(toolBox(tool).checked).toBe(true);
    expect(allControl()).toHaveTextContent(/clear all/i);
  });

  it("deselects every tool when Clear all is clicked", async () => {
    const user = userEvent.setup();
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    await user.click(allControl()); // -> all selected, control is now "Clear all"
    await user.click(allControl()); // -> clear

    expect(checkedTools()).toEqual([]);
    for (const tool of ALL_TOOLS) expect(toolBox(tool).checked).toBe(false);
    expect(allControl()).toHaveTextContent(/select all/i);
    // Nothing selected => nothing to submit.
    expect(screen.getByRole("button", { name: /start scan/i })).toBeDisabled();
  });

  it("selects the remaining tools from a partial selection", async () => {
    const user = userEvent.setup();
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    // Defaults are a partial selection already; add one more to be explicit.
    await user.click(toolBox("nuclei"));
    expect(checkedTools()).toEqual([...DEFAULT_MODULES, "nuclei"].filter((n) => ALL_TOOLS.includes(n)).sort(
      (a, b) => ALL_TOOLS.indexOf(a) - ALL_TOOLS.indexOf(b)
    ));
    expect(allControl()).toHaveTextContent(/select all/i);

    await user.click(allControl());

    expect(checkedTools()).toEqual(ALL_TOOLS);
  });

  it("returns to Select all when one tool is deselected after Select all", async () => {
    const user = userEvent.setup();
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    await user.click(allControl());
    expect(allControl()).toHaveTextContent(/clear all/i);

    await user.click(toolBox("nmap"));

    expect(toolBox("nmap").checked).toBe(false);
    expect(allControl()).toHaveTextContent(/select all/i);
    // Every other tool keeps its state: the control is derived, it does not re-write
    // the selection.
    expect(checkedTools()).toEqual(ALL_TOOLS.filter((n) => n !== "nmap"));
  });

  it("submits exactly the selected tools, in pipeline order, with no duplicates", async () => {
    const user = userEvent.setup();
    const create = vi.spyOn(scanApi, "create").mockResolvedValue({ id: "s1" } as any);
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    // Toggle around a bit so a naive "append on select all" would double-add.
    await user.click(allControl()); // all
    await user.click(toolBox("httpx")); // off
    await user.click(toolBox("httpx")); // back on
    await user.click(allControl()); // clear
    await user.click(allControl()); // all again

    await user.click(screen.getByRole("button", { name: /start scan/i }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const submitted = create.mock.calls[0][3] as string[];

    expect(submitted).toEqual(ALL_TOOLS);
    expect(new Set(submitted).size).toBe(submitted.length);
    // The explicit list goes on the wire -- no "all tools" sentinel/mode.
    expect(submitted).not.toContain("all");
  });

  it("submits only the hand-picked subset after a partial selection", async () => {
    const user = userEvent.setup();
    const create = vi.spyOn(scanApi, "create").mockResolvedValue({ id: "s1" } as any);
    wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    await user.click(allControl()); // all
    await user.click(allControl()); // clear
    await user.click(toolBox("subfinder"));
    await user.click(toolBox("httpx"));

    await user.click(screen.getByRole("button", { name: /start scan/i }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][3]).toEqual(["subfinder", "httpx"]);
  });

  it("keeps the active-tool warning and authorization semantics intact", async () => {
    const user = userEvent.setup();
    const create = vi.spyOn(scanApi, "create").mockResolvedValue({ id: "s1" } as any);
    const { container } = wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    // Active tools stay marked as such, and the authorization note stays on screen,
    // including once "select all" has pulled them in.
    await user.click(allControl());
    expect(container.textContent).toMatch(/active modules require a target with active-testing authorization/i);
    // nuclei/nuclei-dast remain flagged as the vulnerability-detection tools, and the
    // "recon-only is not a clean bill of health" note is still shown.
    expect(container.textContent).toMatch(/finds vulnerabilities/i);
    expect(container.textContent).toMatch(/only nuclei and nuclei-dast can report vulnerabilities/i);

    for (const tool of ACTIVE_TOOLS) {
      const label = toolBox(tool).closest("label") as HTMLElement;
      expect(label.textContent).toMatch(/\(active\)/i);
    }

    // "Select all" does not pre-authorize anything: the active tools are sent by name so
    // the server-side scope check is the thing that decides.
    await user.click(screen.getByRole("button", { name: /start scan/i }));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const submitted = create.mock.calls[0][3] as string[];
    for (const tool of ACTIVE_TOOLS) expect(submitted).toContain(tool);
  });

  it("surfaces a server authorization rejection of active tools unchanged", async () => {
    const user = userEvent.setup();
    // What apps/api/modules/scans/service.py raises for a target whose scope does not
    // allow active testing. The UI must report it, never pre-empt or swallow it.
    vi.spyOn(scanApi, "create").mockRejectedValue(
      new Error("Active testing not authorized for this target; requested active module(s): nuclei")
    );
    const { container } = wrap();
    await waitFor(() => expect(toolBox("subfinder")).toBeInTheDocument());

    await user.click(allControl());
    await user.click(screen.getByRole("button", { name: /start scan/i }));

    await waitFor(() =>
      expect(container.textContent).toMatch(/active testing not authorized for this target/i)
    );
    // The selection is left alone so the operator can deselect the active tools and retry.
    expect(checkedTools()).toEqual(ALL_TOOLS);
  });
});
