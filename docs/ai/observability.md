# AI Observability & SLOs (AI-2.5)

Metrics, alerts, and a Grafana dashboard for the AI pipeline. Additive and metrics-only — no
runtime behavior change, no API, no migration. All labels are low-cardinality.

## Metrics (Prometheus)
Exposed on `api:8000/metrics` (assistant Q&A) and `worker:9100` (scan-time agents), both scraped.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `mbs_ai_calls_total` | counter | provider, model, agent_role | successful AI calls |
| `mbs_ai_tokens_total` | counter | provider, model, direction | tokens (prompt/completion) |
| `mbs_ai_cost_usd_total` | counter | provider, model | estimated spend |
| `mbs_ai_decision_total` | counter | action | autonomous agent decisions |
| `mbs_ai_failover_total` | counter | from_provider, to_provider | provider failovers (AI-2.1) |
| `mbs_ai_budget_blocked_total` | counter | agent_role | calls blocked by the budget cap (AI-2.2A) |
| **`mbs_ai_latency_seconds`** | **histogram** | agent_role | **latency of successful AI calls (AI-2.5)** |
| **`mbs_ai_errors_total`** | **counter** | provider | **AI calls that ultimately failed (AI-2.5)** |

`mbs_ai_latency_seconds` is observed in `emit_usage` (success path). `mbs_ai_errors_total` is
incremented in `BaseAIProvider.complete_json` when a call ultimately fails (terminal error or
exhausted retries). Budget blocks are counted separately (not as errors).

## Alerts (`infra/prometheus/alerts.yml`)
| Alert | Condition | Meaning |
|-------|-----------|---------|
| `MbsAiCostHigh` | `increase(mbs_ai_cost_usd_total[1h]) > 5` | AI spend spike |
| `MbsAiBudgetBlocking` | `increase(mbs_ai_budget_blocked_total[1h]) > 0` | a workspace hit its AI budget |
| **`MbsAiLatencySlo`** | `histogram_quantile(0.95, …[10m]) > 30s` | AI p95 latency SLO breached |
| **`MbsAiErrorRateHigh`** | errors / (errors + calls) `> 0.2` over 15m | AI error rate above 20% |
| **`MbsAiFailoverActive`** | `increase(mbs_ai_failover_total[15m]) > 0` | primary provider degraded (running on a fallback) |

## Grafana dashboard
`infra/grafana/ai-dashboard.json` — an **importable artifact** (no Grafana service is bundled;
deploy your own Grafana against the existing Prometheus and import the JSON):

1. Grafana → Dashboards → **Import** → upload `infra/grafana/ai-dashboard.json`.
2. Select your Prometheus data source when prompted (`DS_PROMETHEUS`).

Panels: AI spend rate by model, calls/min by agent role, tokens/min by direction, latency p50/p95,
error rate, and failover / budget-block counts. It references only exported metrics (asserted by
`tests/test_ai_observability.py`).

## Deliberately deferred
- Persisting `latency_ms` in `ai_usage` (a DB migration) for historical latency analysis.
- A bundled Grafana **service** in the compose stack (kept out on purpose; import the JSON instead).
