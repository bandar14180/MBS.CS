/**
 * FE-2: RemediationTab state/logic tests.
 *
 * These target the behaviour that would actually break silently and be expensive to catch in
 * review or manually:
 *
 *   - the OVERDUE rule, which must mirror the server's exactly (a past due date AND still
 *     outstanding). Getting this wrong makes the list contradict the progress panel, whose
 *     counts come from the same rule server-side;
 *   - FILTER wiring -- a filter that does not reach the API silently shows the wrong page;
 *   - the OPTIMISTIC LOCK: every mutation must send the item's current `version`, or a stale
 *     write clobbers someone else's change;
 *   - 409 handling, which must surface the translated conflict message rather than a raw error;
 *   - `verified` / `risk_accepted` must NOT be offered in the transition control -- they are
 *     guarded server-side and a UI that offers them builds a control that always fails.
 *
 * The api module is mocked at the module boundary so these are deterministic and hit no
 * network; the component's own logic is exercised for real.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { I18nProvider } from "@/lib/i18n";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    remediationApi: {
      list: vi.fn(),
      get: vi.fn(),
      sync: vi.fn(),
      progress: vi.fn(),
      update: vi.fn(),
      transition: vi.fn(),
      events: vi.fn(),
      evidence: vi.fn(),
      uploadEvidence: vi.fn(),
      verifications: vi.fn(),
      requestVerification: vi.fn(),
      completeVerification: vi.fn(),
      riskAcceptances: vi.fn(),
      acceptRisk: vi.fn(),
      revokeRiskAcceptance: vi.fn(),
    },
    memberApi: { list: vi.fn(), roles: vi.fn(), invite: vi.fn(), updateRole: vi.fn(), remove: vi.fn() },
  };
});

import { ApiError, memberApi, remediationApi, type RemediationItem, type RemediationProgress } from "@/lib/api";
import { RemediationTab } from "./RemediationTab";

const PROJECT = "11111111-1111-1111-1111-111111111111";

function item(over: Partial<RemediationItem> = {}): RemediationItem {
  return {
    id: "aaaaaaaa-0000-0000-0000-000000000001",
    workspace_id: "00000000-0000-0000-0000-000000000001",
    project_id: PROJECT,
    issue_key: "template:cmd-injection",
    vulnerability_id: "bbbbbbbb-0000-0000-0000-000000000001",
    remediation_id: null,
    title: "Command Injection",
    status: "proposed",
    priority: "high",
    assignee_user_id: null,
    due_date: null,
    notes: null,
    notes_source: null,
    source: "system",
    resolved_at: null,
    verified_at: null,
    version: 3,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

const PROGRESS: RemediationProgress = {
  total: 1, proposed: 1, accepted: 0, in_progress: 0, awaiting_verification: 0,
  verified: 0, closed: 0, risk_accepted: 0, rejected: 0, reopened: 0,
  open: 1, resolved: 0, overdue: 0, completion_percent: 0,
};

function renderTab() {
  return render(
    <I18nProvider>
      <RemediationTab projectId={PROJECT} />
    </I18nProvider>,
  );
}

/**
 * FE-9: `<Label>` now carries `htmlFor` and each control an `id`, so controls are reachable by
 * their accessible name. Going through getByLabelText rather than the DOM structure means
 * these tests also FAIL if that association is ever broken -- i.e. they guard the a11y fix,
 * not merely tolerate it.
 */
function selectFor(labelText: string): HTMLSelectElement {
  return screen.getByLabelText(labelText, { selector: "select" }) as HTMLSelectElement;
}

/**
 * The item ROW. "Overdue" also labels a metric in the progress panel, so overdue assertions
 * must be scoped here rather than searched for across the whole document.
 */
async function itemRow(): Promise<HTMLElement> {
  const title = await screen.findByText("Command Injection");
  const row = title.closest("button");
  if (!row) throw new Error("item row button not found");
  return row as HTMLElement;
}

/** Open the item's detail panel and wait for it to mount. */
async function openDetail(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(await itemRow());
  await screen.findByText("Timeline");
}

beforeEach(() => {
  vi.mocked(memberApi.list).mockResolvedValue([]);
  vi.mocked(remediationApi.progress).mockResolvedValue(PROGRESS);
  vi.mocked(remediationApi.list).mockResolvedValue([item()]);
  vi.mocked(remediationApi.events).mockResolvedValue([]);
  vi.mocked(remediationApi.evidence).mockResolvedValue([]);
  vi.mocked(remediationApi.verifications).mockResolvedValue([]);
  vi.mocked(remediationApi.riskAcceptances).mockResolvedValue([]);
});

describe("RemediationTab — loading and rendering", () => {
  it("renders the items returned by the API", async () => {
    renderTab();
    expect(await screen.findByText("Command Injection")).toBeInTheDocument();
    expect(screen.getByText("template:cmd-injection")).toBeInTheDocument();
  });

  it("shows the empty state when there is no remediation work", async () => {
    vi.mocked(remediationApi.list).mockResolvedValue([]);
    renderTab();
    expect(
      await screen.findByText(/No remediation items yet/i),
    ).toBeInTheDocument();
  });

  it("surfaces an API error instead of rendering a broken list", async () => {
    vi.mocked(remediationApi.list).mockRejectedValue(new Error("backend exploded"));
    renderTab();
    expect(await screen.findByText("backend exploded")).toBeInTheDocument();
  });

  it("renders progress from the server rollup, not from the item list", async () => {
    vi.mocked(remediationApi.progress).mockResolvedValue({
      ...PROGRESS, total: 8, open: 5, resolved: 3, overdue: 2, completion_percent: 38,
    });
    renderTab();
    expect(await screen.findByText("38% complete")).toBeInTheDocument();
  });
});

describe("RemediationTab — the overdue rule (must mirror the server)", () => {
  const PAST = "2020-01-01T00:00:00Z";
  const FUTURE = "2999-01-01T00:00:00Z";

  it("marks a past-due item that is still outstanding as overdue", async () => {
    vi.mocked(remediationApi.list).mockResolvedValue([
      item({ due_date: PAST, status: "in_progress" }),
    ]);
    renderTab();
    expect(within(await itemRow()).getByText("Overdue")).toBeInTheDocument();
  });

  it.each(["verified", "closed", "risk_accepted", "rejected"] as const)(
    "does NOT mark finished work (%s) as overdue even when past its due date",
    async (status) => {
      vi.mocked(remediationApi.list).mockResolvedValue([item({ due_date: PAST, status })]);
      renderTab();
      expect(within(await itemRow()).queryByText("Overdue")).not.toBeInTheDocument();
    },
  );

  it("does not mark a future due date as overdue", async () => {
    vi.mocked(remediationApi.list).mockResolvedValue([
      item({ due_date: FUTURE, status: "in_progress" }),
    ]);
    renderTab();
    expect(within(await itemRow()).queryByText("Overdue")).not.toBeInTheDocument();
  });

  it("does not mark an item with no due date as overdue", async () => {
    vi.mocked(remediationApi.list).mockResolvedValue([
      item({ due_date: null, status: "in_progress" }),
    ]);
    renderTab();
    expect(within(await itemRow()).queryByText("Overdue")).not.toBeInTheDocument();
  });
});

describe("RemediationTab — controls are programmatically labelled (FE-9)", () => {
  it("associates each filter label with its control, so assistive tech can name it", async () => {
    renderTab();
    await screen.findByText("Command Injection");

    // getByLabelText resolves ONLY through htmlFor/id (or nesting/aria-*). A <label> that
    // merely sits next to its control would not be found here, which is exactly the defect
    // FE-9 fixed.
    for (const name of ["Status", "Priority"]) {
      const control = screen.getByLabelText(name, { selector: "select" });
      expect(control).toBeInTheDocument();
      expect(control.id).not.toBe("");
    }
  });

  it("gives every rendered label an explicit target", async () => {
    const { container } = renderTab();
    await screen.findByText("Command Injection");

    // Every label must actually name a control, by EITHER of the two valid associations:
    // htmlFor pointing at a real id, or the control nested inside the label (which the
    // "Overdue only" checkbox uses). An htmlFor pointing at nothing is as useless as none.
    for (const label of Array.from(container.querySelectorAll("label"))) {
      const target = label.getAttribute("for");
      const wraps = label.querySelector("input, select, textarea") !== null;
      expect(
        wraps || Boolean(target),
        `label "${label.textContent}" names no control`,
      ).toBe(true);
      if (target) {
        expect(
          container.querySelector(`#${CSS.escape(target)}`),
          `label "${label.textContent}" points at missing #${target}`,
        ).not.toBeNull();
      }
    }
  });
});

describe("RemediationTab — filters reach the API", () => {
  it("passes the selected status to the API", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("Command Injection");

    await user.selectOptions(selectFor("Status"), "in_progress");

    await waitFor(() =>
      expect(remediationApi.list).toHaveBeenCalledWith(
        PROJECT, expect.objectContaining({ status: "in_progress" }),
      ),
    );
  });

  it("passes the overdue-only filter to the API", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByText("Command Injection");

    await user.click(screen.getByRole("checkbox"));

    await waitFor(() =>
      expect(remediationApi.list).toHaveBeenCalledWith(
        PROJECT, expect.objectContaining({ overdue: true }),
      ),
    );
  });

  it("sends undefined (not an empty string) when a filter is cleared", async () => {
    renderTab();
    await screen.findByText("Command Injection");
    // First load has no filters selected -- they must be undefined so the query string is
    // omitted entirely rather than sent as `?status=`.
    expect(remediationApi.list).toHaveBeenCalledWith(PROJECT, {
      status: undefined, priority: undefined, overdue: undefined,
    });
  });
});

describe("RemediationTab — optimistic locking and conflicts", () => {
  it("sends the item's current version on a transition", async () => {
    const user = userEvent.setup();
    vi.mocked(remediationApi.list).mockResolvedValue([item({ version: 7 })]);
    vi.mocked(remediationApi.transition).mockResolvedValue(item({ version: 8, status: "accepted" }));
    renderTab();

    await openDetail(user);
    await user.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      // (projectId, itemId, version, toStatus) -- the component passes no `detail`.
      expect(remediationApi.transition).toHaveBeenCalledWith(
        PROJECT, "aaaaaaaa-0000-0000-0000-000000000001", 7, "accepted",
      ),
    );
  });

  it("shows the translated conflict message on a 409 rather than a raw error", async () => {
    const user = userEvent.setup();
    vi.mocked(remediationApi.transition).mockRejectedValue(
      new ApiError(409, "Remediation item was modified by someone else"),
    );
    renderTab();

    await openDetail(user);
    await user.click(screen.getByRole("button", { name: "Apply" }));

    expect(
      await screen.findByText(/This item was changed by someone else/i),
    ).toBeInTheDocument();
  });

  it("sends the version when saving owner/due-date/priority/notes", async () => {
    const user = userEvent.setup();
    vi.mocked(remediationApi.list).mockResolvedValue([item({ version: 5 })]);
    vi.mocked(remediationApi.update).mockResolvedValue(item({ version: 6 }));
    renderTab();

    await openDetail(user);
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(remediationApi.update).toHaveBeenCalledWith(
        PROJECT, expect.any(String), expect.objectContaining({ version: 5 }),
      ),
    );
  });
});

describe("RemediationTab — guarded statuses are never offered", () => {
  it("omits `verified` and `risk_accepted` from the transition control", async () => {
    const user = userEvent.setup();
    renderTab();
    await openDetail(user);

    // "Change status" is a section HEADING (a <div>), not a <label> -- take the select from
    // the section it heads.
    const heading = screen.getByText("Change status");
    const select = heading.parentElement?.querySelector("select");
    if (!select) throw new Error("transition select not found");
    const offered = within(select as HTMLSelectElement)
      .getAllByRole("option")
      .map((o) => (o as HTMLOptionElement).value);

    expect(offered).not.toContain("verified");
    expect(offered).not.toContain("risk_accepted");
    // and it still offers the legitimate human targets
    expect(offered).toContain("accepted");
    expect(offered).toContain("in_progress");
  });
});

describe("RemediationTab — sync", () => {
  it("syncs then reloads the list", async () => {
    const user = userEvent.setup();
    vi.mocked(remediationApi.sync).mockResolvedValue([]);
    renderTab();
    await screen.findByText("Command Injection");
    const before = vi.mocked(remediationApi.list).mock.calls.length;

    await user.click(screen.getByRole("button", { name: "Sync from findings" }));

    await waitFor(() => expect(remediationApi.sync).toHaveBeenCalledWith(PROJECT));
    await waitFor(() =>
      expect(vi.mocked(remediationApi.list).mock.calls.length).toBeGreaterThan(before),
    );
  });
});
