# AI Evaluation Framework (AI-2.4)

An offline, deterministic quality gate for the AI pipeline. It drives the **real** AI components
through the injectable `SupportsComplete` seam with **scripted** model responses (no live model
calls, no cost, no DB), scores the outputs, and applies thresholds. A prompt/model/code change
that regresses quality fails CI.

## Layout
- `apps/api/ai_agent/eval/scenarios.py` — golden scenarios + `FakeClient` + component runners.
- `apps/api/ai_agent/eval/evaluators.py` — pure scoring functions (`EvalResult`: 0..1 score + pass/fail).
- `apps/api/ai_agent/eval/runner.py` — `run_all()`: runs every suite, aggregates, applies
  thresholds, ties each suite to its `prompt_version` (from the AI-2.3 registry).
- `apps/api/tests/test_ai_eval.py` — the CI gate (folded into the existing `tests` job).

## Suites & signals
| Suite | Signals scored |
|-------|----------------|
| `agent_tool_selection` | allowlist adherence, deterministic ranked-best selection (code selects, not LLM order), confidence presence, no non-allowlisted candidate survives |
| `correlator_quality` | input preservation (every id exactly once), no dropped/invented findings, deterministic grouping vs. golden |
| `remediation_quality` | groundedness (references a real finding attribute), no invented (non-http) references, AI-1 safety (unsafe output → fallback) |
| `attack_accuracy` | precision/recall of `techniques_for()` vs. a **pinned** golden set (independent of the catalog, so an accidental catalog edit is caught) |
| `injection_regression` | reuses the AI-1 adversarial dimension: injected input still yields an allowlisted agent action, and unsafe remediation/assistant output is still blocked |

## Thresholds
Each suite has a threshold (currently **1.0** — the scenarios are deterministic, so any regression
drops the score below the bar and fails the gate). A suite passes only when every result passes
**and** its aggregate score ≥ threshold. Recorded/non-deterministic scenarios could later use a
sub-1.0 threshold.

## Running
```bash
python -m pytest apps/api/tests/test_ai_eval.py -q
```

## Extending
1. Add a scenario to the relevant list in `scenarios.py` (inputs + a scripted `FakeClient`
   response + the expected properties).
2. Add/point an evaluator in `evaluators.py`.
3. Wire it into a suite in `runner.py`.
Keep everything deterministic and free of live model calls.

## Deliberately out of scope (deferred)
- Persisting `latency_ms` (a DB migration) and an eval-run history table for trend telemetry.
- Live model-comparison and any API endpoint. The MVP is a purely offline CI gate.
