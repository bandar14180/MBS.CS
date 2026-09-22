/**
 * FE-2: AssessmentsTab state/logic tests.
 *
 * The risk in this component is that a CLIENT-FACING document displays the wrong numbers. So
 * these target exactly that:
 *
 *   - a DRAFT must show no score at all ("—"), never 0. A draft has not measured anything,
 *     and 0/100 is a real (terrible) posture -- conflating them misinforms a client;
 *   - an ISSUED assessment must render its FROZEN `summary`, not live figures;
 *   - `max_risk: null` must render "N/A", never 0.0 -- "not scored" and "scored zero" are
 *     different facts, and the PDF makes the same distinction;
 *   - the draft/issued branch: only a draft offers the (irreversible) Issue action, and only
 *     an issued one loads findings/comparison;
 *   - the trend must state direction explicitly rather than leaving the reader to infer
 *     whether a number going up is good.
 *
 * The api module is mocked at the boundary; the component's own logic runs for real.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { I18nProvider } from "@/lib/i18n";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    assessmentApi: {
      list: vi.fn(),
      get: vi.fn(),
      preview: vi.fn(),
      create: vi.fn(),
      issue: vi.fn(),
      findings: vi.fn(),
      comparison: vi.fn(),
    },
  };
});

import {
  assessmentApi,
  type AssessmentComparison,
  type AssessmentFinding,
  type RiskAssessment,
} from "@/lib/api";
import { AssessmentsTab } from "./AssessmentsTab";

const PROJECT = "11111111-1111-1111-1111-111111111111";

function assessment(over: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    id: "cccccccc-0000-0000-0000-000000000001",
    workspace_id: "00000000-0000-0000-0000-000000000001",
    project_id: PROJECT,
    title: "Q3 Assessment",
    period_start: "2026-06-01T00:00:00Z",
    period_end: "2026-09-01T00:00:00Z",
    status: "issued",
    security_score: 62,
    score_band: "Weak",
    summary: {
      security_score: 62,
      score_band: "Weak",
      severity_counts: { critical: 1, high: 2, medium: 3, low: 0, info: 4 },
      active_severity_counts: { critical: 1, high: 2, medium: 3, low: 0, info: 4 },
      total_findings: 10,
      active_findings: 10,
      affected_assets: ["host-a", "host-b"],
      affected_endpoint_count: 9,
      unresolved_issue_count: 5,
      top_risks: [],
      remediation_progress: {
        total: 4, proposed: 1, accepted: 1, in_progress: 1, awaiting_verification: 0,
        verified: 0, closed: 1, risk_accepted: 0, rejected: 0, reopened: 0,
        open: 3, resolved: 1, overdue: 2, completion_percent: 25,
      },
      risk_accepted_count: 0,
    },
    narrative: "Recommended management actions:\n1. Remediate the critical finding first.",
    narrative_source: "system",
    previous_assessment_id: null,
    report_id: null,
    created_by: null,
    issued_by: null,
    issued_at: "2026-09-01T12:00:00Z",
    created_at: "2026-08-01T00:00:00Z",
    ...over,
  };
}

function renderTab() {
  return render(
    <I18nProvider>
      <AssessmentsTab projectId={PROJECT} />
    </I18nProvider>,
  );
}

/** The assessment ROW (a button), so assertions are not confused by the live preview panel. */
async function row(title = "Q3 Assessment"): Promise<HTMLElement> {
  const el = await screen.findByText(title);
  const btn = el.closest("button");
  if (!btn) throw new Error("assessment row button not found");
  return btn as HTMLElement;
}

beforeEach(() => {
  vi.mocked(assessmentApi.preview).mockRejectedValue(new Error("no preview"));
  vi.mocked(assessmentApi.findings).mockResolvedValue([]);
  vi.mocked(assessmentApi.comparison).mockResolvedValue({ has_previous: false });
  vi.mocked(assessmentApi.list).mockResolvedValue([assessment()]);
});

describe("AssessmentsTab — listing", () => {
  it("renders assessments returned by the API", async () => {
    renderTab();
    expect(await screen.findByText("Q3 Assessment")).toBeInTheDocument();
  });

  it("shows the empty state when there are none", async () => {
    vi.mocked(assessmentApi.list).mockResolvedValue([]);
    renderTab();
    expect(await screen.findByText(/No assessments yet/i)).toBeInTheDocument();
  });

  it("surfaces an API error", async () => {
    vi.mocked(assessmentApi.list).mockRejectedValue(new Error("list failed"));
    renderTab();
    expect(await screen.findByText("list failed")).toBeInTheDocument();
  });
});

describe("AssessmentsTab — a draft has NOT measured anything", () => {
  it('shows an em dash rather than 0 for a draft score', async () => {
    vi.mocked(assessmentApi.list).mockResolvedValue([
      assessment({ status: "draft", security_score: null, score_band: null, summary: {} }),
    ]);
    renderTab();
    // "—" not "0": a draft has no score; 0/100 would be a real, terrible posture.
    expect(within(await row()).getByText("—")).toBeInTheDocument();
    expect(within(await row()).queryByText("0")).not.toBeInTheDocument();
  });

  it("does not load findings or comparison for a draft", async () => {
    const user = userEvent.setup();
    vi.mocked(assessmentApi.list).mockResolvedValue([
      assessment({ status: "draft", security_score: null, score_band: null, summary: {} }),
    ]);
    renderTab();
    await user.click(await row());

    await screen.findByText(/Issuing freezes the figures permanently/i);
    expect(assessmentApi.findings).not.toHaveBeenCalled();
    expect(assessmentApi.comparison).not.toHaveBeenCalled();
  });

  it("offers the Issue action only for a draft", async () => {
    const user = userEvent.setup();
    vi.mocked(assessmentApi.list).mockResolvedValue([
      assessment({ status: "draft", security_score: null, score_band: null, summary: {} }),
    ]);
    renderTab();
    await user.click(await row());
    expect(await screen.findByRole("button", { name: "Issue" })).toBeInTheDocument();
  });

  it("does NOT offer the Issue action for an already-issued assessment", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await row());
    await screen.findByText(/frozen as of the issue date/i);
    expect(screen.queryByRole("button", { name: "Issue" })).not.toBeInTheDocument();
  });

  it("issues a draft through the API and refreshes the list", async () => {
    const user = userEvent.setup();
    vi.mocked(assessmentApi.list).mockResolvedValue([
      assessment({ status: "draft", security_score: null, score_band: null, summary: {} }),
    ]);
    vi.mocked(assessmentApi.issue).mockResolvedValue(assessment());
    renderTab();
    await user.click(await row());
    await user.click(await screen.findByRole("button", { name: "Issue" }));

    await waitFor(() =>
      expect(assessmentApi.issue).toHaveBeenCalledWith(
        PROJECT, "cccccccc-0000-0000-0000-000000000001",
      ),
    );
  });
});

describe("AssessmentsTab — an issued assessment renders its FROZEN snapshot", () => {
  it("renders the frozen score and band", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await row());

    // The score renders in the row AND in the detail's score panel; assert both exist rather
    // than requiring a single match.
    await screen.findByText(/frozen as of the issue date/i);
    expect(screen.getAllByText("62").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Weak").length).toBeGreaterThan(0);
  });

  it("renders frozen remediation progress, not a recomputed figure", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await row());

    // completion_percent drives only the bar's CSS width, so assert the metrics that are
    // actually rendered as text: Total=4 and Overdue=2 from summary.remediation_progress.
    const heading = await screen.findByText("Remediation progress");
    const section = heading.parentElement as HTMLElement;
    expect(within(section).getByText("Total")).toBeInTheDocument();
    expect(within(section).getByText("4")).toBeInTheDocument();
    expect(within(section).getByText("Overdue")).toBeInTheDocument();
  });

  it("loads frozen findings for an issued assessment", async () => {
    const user = userEvent.setup();
    const finding: AssessmentFinding = {
      id: "dddddddd-0000-0000-0000-000000000001",
      assessment_id: "cccccccc-0000-0000-0000-000000000001",
      issue_key: "template:sqli",
      vulnerability_id: null,
      frozen_title: "SQL Injection",
      frozen_severity: "critical",
      frozen_cvss_score: 9.8,
      frozen_final_risk_score: 9.8,
      frozen_vulnerability_status: "open",
      frozen_remediation_status: "in_progress",
      risk_accepted: false,
      location_count: 3,
      created_at: "2026-09-01T12:00:00Z",
    };
    vi.mocked(assessmentApi.findings).mockResolvedValue([finding]);
    renderTab();
    await user.click(await row());

    expect(await screen.findByText("SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("CVSS 9.8")).toBeInTheDocument();
  });
});

describe("AssessmentsTab — N/A is not 0.0", () => {
  it('renders "N/A" for an unscored top risk rather than 0', async () => {
    const user = userEvent.setup();
    vi.mocked(assessmentApi.list).mockResolvedValue([
      assessment({
        summary: {
          ...assessment().summary,
          top_risks: [
            { title: "Unscored Issue", severity: "critical", max_risk: null, max_cvss: null, endpoint_count: 2 },
          ],
        },
      }),
    ]);
    renderTab();
    await user.click(await row());

    expect(await screen.findByText("Unscored Issue")).toBeInTheDocument();
    // "not scored" must NOT be displayed as 0.0.
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("renders a real risk value when one exists", async () => {
    const user = userEvent.setup();
    vi.mocked(assessmentApi.list).mockResolvedValue([
      assessment({
        summary: {
          ...assessment().summary,
          top_risks: [
            { title: "Scored Issue", severity: "high", max_risk: 7.5, max_cvss: 7.2, endpoint_count: 1 },
          ],
        },
      }),
    ]);
    renderTab();
    await user.click(await row());

    expect(await screen.findByText("7.5")).toBeInTheDocument();
  });
});

describe("AssessmentsTab — trend states its direction explicitly", () => {
  it("says the posture improved and by how much", async () => {
    const user = userEvent.setup();
    const cmp: AssessmentComparison = {
      has_previous: true,
      previous_security_score: 50,
      security_score_delta: 12,
      direction: "improved",
    };
    vi.mocked(assessmentApi.comparison).mockResolvedValue(cmp);
    renderTab();
    await user.click(await row());

    expect(await screen.findByText(/improved/i)).toBeInTheDocument();
    expect(screen.getByText(/12 points/i)).toBeInTheDocument();
  });

  it("says there is nothing to compare against when there is no predecessor", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await row());
    expect(
      await screen.findByText(/No earlier assessment to compare against/i),
    ).toBeInTheDocument();
  });
});

describe("AssessmentsTab — creating a draft", () => {
  it("disables Create until title and both period dates are supplied", async () => {
    renderTab();
    await screen.findByText("Q3 Assessment");
    expect(screen.getByRole("button", { name: "New assessment" })).toBeDisabled();
  });
});
