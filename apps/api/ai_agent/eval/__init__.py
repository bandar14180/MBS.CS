"""AI-2.4 -- offline AI evaluation framework.

Deterministic, zero-runtime-cost quality gates for the AI pipeline. Scenarios drive the REAL
components through the injectable SupportsComplete seam with scripted model responses (no live
calls), score the outputs, and apply thresholds so a prompt/model/code change that regresses
quality fails CI. See runner.run_all().
"""
