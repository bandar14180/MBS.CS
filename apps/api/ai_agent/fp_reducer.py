import json
from dataclasses import dataclass

from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.ai_agent.prompts.fp_reducer import (
    FP_REDUCER_PROMPT_VERSION,
    FP_REDUCER_SYSTEM,
    FP_REDUCER_USER_TEMPLATE,
)

_VALID_CONFIDENCE = {"low", "medium", "high"}


@dataclass
class FPAssessment:
    finding_id: str
    likely_false_positive: bool
    confidence: str
    reasoning: str


@dataclass
class FPResult:
    assessments: list[FPAssessment]
    model_version: str
    prompt_version: str = FP_REDUCER_PROMPT_VERSION


class FPReducer:
    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or get_ai_client()

    def assess(self, findings: list[dict]) -> FPResult:
        """`findings`: list of dicts each with at least `id`. Returns a
        suggestion per input finding. Constrained in code (blueprint §7 step 6:
        'suggest, never decide; log, never silently drop'): assessments are
        filtered back to the exact input ids, unknown ids dropped, and any input
        finding the model skipped is returned as a conservative not-FP default so
        every finding is accounted for."""
        input_ids = [str(f["id"]) for f in findings]
        if not input_ids:
            return FPResult(assessments=[], model_version=self._client.model_version)

        user = FP_REDUCER_USER_TEMPLATE.format(findings_json=json.dumps(findings, default=str, indent=2))
        raw = self._client.complete_json(FP_REDUCER_SYSTEM, user)

        id_set = set(input_ids)
        by_id: dict[str, FPAssessment] = {}
        for a in raw.get("assessments", []):
            fid = str(a.get("id", ""))
            if fid not in id_set or fid in by_id:
                continue
            confidence = str(a.get("confidence", "low")).lower()
            by_id[fid] = FPAssessment(
                finding_id=fid,
                likely_false_positive=bool(a.get("likely_false_positive", False)),
                confidence=confidence if confidence in _VALID_CONFIDENCE else "low",
                reasoning=str(a.get("reasoning", "")),
            )

        # Any input finding the model didn't assess -> conservative not-FP default.
        for fid in input_ids:
            by_id.setdefault(
                fid, FPAssessment(fid, likely_false_positive=False, confidence="low", reasoning="not assessed")
            )
        return FPResult(
            assessments=[by_id[fid] for fid in input_ids],
            model_version=self._client.model_version,
        )
