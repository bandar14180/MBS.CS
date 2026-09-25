import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.service import get_project
from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.assets.models import MAX_ASSET_VALUE_LENGTH, Asset

logger = logging.getLogger("mbs.assets")


class AssetValueTooLong(ValueError):
    """An asset value exceeds what the column can store.

    Raised INSTEAD of letting MySQL raise DataError(1406) mid-transaction. The distinction
    matters: a driver-level DataError poisons the surrounding transaction (every subsequent
    statement on that connection fails until rollback), which is precisely how one
    over-long URL destroyed a whole scan's ToolRun bookkeeping in incident 615d0e0b. A
    Python-level exception raised BEFORE the statement is issued leaves the transaction
    clean, so the caller can skip this one asset and carry on with the rest.
    """

    def __init__(self, length: int, limit: int) -> None:
        super().__init__(
            f"asset value is {length} characters, exceeding the {limit}-character limit"
        )
        self.length = length
        self.limit = limit


def validate_asset_value(value: str) -> str:
    """Return `value` unchanged, or raise AssetValueTooLong.

    DELIBERATELY NOT A TRUNCATION. Silently storing `value[:2048]` would fabricate a URL
    that was never observed: it is not fetchable, it is not what the crawler found, and as
    evidence it is actively misleading -- a truncated URL can also collide with a genuinely
    different one under the uniqueness key. An asset we cannot store faithfully is skipped
    and logged, never quietly corrupted.
    """
    if len(value) > MAX_ASSET_VALUE_LENGTH:
        raise AssetValueTooLong(len(value), MAX_ASSET_VALUE_LENGTH)
    return value


# Metadata key holding the per-tool observation log for an asset that more than one tool
# discovered. See `merge_asset_metadata` for why this exists and what it may never do.
OBSERVATIONS_KEY = "observations"

# Cap the observation log so a long-lived asset re-discovered by every tool on every scan
# cannot grow the JSON column without bound. OLDEST entries are dropped first (the newest
# observation is always the most operationally relevant), and the CURRENT tool's observation
# is always retained -- it is merged in after truncation.
MAX_OBSERVATIONS = 20

# The provenance keys the orchestrator stamps on every finding (see orchestrator._run_single_tool).
# These identify WHICH tool run observed the asset, and are exactly what a wholesale metadata
# replacement used to destroy.
_PROVENANCE_KEYS = (
    "discovered_by_tool", "discovered_by_tool_version", "discovered_in_tool_run", "in_scope",
)


# Provenance classification for a recorded observation. The platform already keeps these
# three tiers distinct in the agent's reasoning (see state_projection.summarize_prior_beliefs:
# observed / inferred / hypotheses-UNVERIFIED); this names the tier explicitly on the asset
# record so a stored relationship can never be read as more than it is.
#
# A tool-discovered asset is always OBSERVED: a scanner saw it. INFERRED is reserved for a
# classification DERIVED from observations (api_intel's endpoint kind, auth_state's label) and
# is never written here. VERIFIED belongs exclusively to the vulnerability verification path
# and is NEVER reachable from discovery -- an asset observation is not evidence, and no amount
# of correlation promotes one. That is the invariant test_asset_knowledge_model pins.
PROVENANCE_OBSERVED = "OBSERVED"
PROVENANCE_INFERRED = "INFERRED"
PROVENANCE_VERIFIED = "VERIFIED"

# The only provenance an asset observation may carry. VERIFIED is deliberately absent: it is
# not a value this code path is permitted to write.
_ASSET_PROVENANCE = PROVENANCE_OBSERVED


def _observation_of(metadata: dict) -> dict:
    """The provenance-only slice of one tool's metadata, used as its observation record.

    Stamped OBSERVED: a scanner actually saw this asset in this tool run. Nothing here is
    inferred and nothing is verified -- see PROVENANCE_OBSERVED."""
    observation = {k: metadata[k] for k in _PROVENANCE_KEYS if k in metadata}
    if observation:
        observation["provenance"] = _ASSET_PROVENANCE
    return observation


def _union_tech(existing: object, incoming: object) -> list[str] | None:
    """Union of two tools' technology observations for the SAME service, order-stable.

    WHY THIS KEY IS SPECIAL. httpx and whatweb both emit `asset_type="http_service"` for the
    same URL and both write `tech` -- httpx from its own fingerprinting, whatweb from its
    plugin set. They observe genuinely DIFFERENT technologies on the same service, so
    last-writer-wins silently discarded one tool's entire technology list (and `tech` feeds
    attack_graph's service attributes, so the loss propagated). A union is the truthful
    reading: both tools really did observe their entries.

    This is deliberately the ONLY key merged this way. It is a set-like observation where
    both values are simultaneously true; a status_code or title is a point-in-time scalar
    where the newest reading supersedes the old, and unioning those would invent a state the
    service was never in. Returns None when neither side has a usable list, leaving the
    normal last-writer-wins path untouched."""
    def _as_list(v: object) -> list[str]:
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(i) for i in v if isinstance(i, (str, int, float))]
        return []

    combined = _as_list(existing) + _as_list(incoming)
    if not combined:
        return None
    seen: set[str] = set()
    out: list[str] = []
    for tech in combined:
        if tech not in seen:
            seen.add(tech)
            out.append(tech)
    return out


def merge_asset_metadata(existing: dict | None, incoming: dict) -> dict:
    """Merge a NEW observation of an already-known asset into its stored metadata, without
    discarding what a previous tool observed.

    WHY THIS EXISTS. `upsert_asset` previously did `on_duplicate_key_update(metadata=<new>)`,
    replacing the whole JSON document. Assets are deliberately keyed on
    (target_id, asset_type, value) so an asset outlives individual scans -- but that same
    grain means SEVERAL TOOLS legitimately discover the SAME row: katana crawls a URL, arjun
    then confirms its parameters, httpx probes the service whatweb fingerprints. Each call
    overwrote the last, so the stored asset ended up claiming it was discovered by whichever
    tool happened to run LAST, and every earlier tool's provenance was silently lost. That
    directly contradicts the correlation requirement to preserve multiple observations and
    their source/tool provenance.

    WHAT THIS DOES. Scalar keys are still last-writer-wins (the newest observation of a
    status code or title is the current truth, and history lives in `observations`), but:

      * every DISTINCT observing tool run is appended to an `observations` list, and
      * keys the incoming tool did not report are PRESERVED from the existing document
        rather than dropped -- arjun reporting `has_params` must not erase katana's
        `status_code`.

    WHAT THIS MUST NEVER DO. It never merges across assets: the caller reaches one row via
    the (target_id, asset_type, value) unique key, so this only ever combines observations OF
    THE SAME asset, and tenancy is enforced by that key, not here. It never invents an
    observation -- each entry is a tool run that actually ran. It draws no security
    conclusion: an observation is OBSERVED provenance, never evidence and never verification.
    Conflicting values stay traceable precisely because the superseded observation remains in
    the list rather than being erased.
    """
    existing = existing or {}
    if not isinstance(existing, dict):
        # A non-dict stored document is unreadable, not authoritative. Treat it as absent
        # rather than raising: losing an asset row over malformed metadata would be worse.
        existing = {}

    merged = {**existing, **incoming}

    # A discovery path may never assert a verification tier at the TOP level either. The
    # observation records below are built from `_PROVENANCE_KEYS` alone, so a hostile input
    # cannot reach them -- but a stray top-level `provenance` would still sit on the asset
    # document and read as a claim about the asset as a whole. Discovery observes; it does
    # not verify, so this key is owned by the observation records and stripped from the
    # document itself.
    merged.pop("provenance", None)

    # `tech` is the one set-like observation two tools make of the same service -- unioned
    # rather than overwritten, because httpx and whatweb both genuinely observed their own
    # entries. Every other key stays last-writer-wins; see _union_tech.
    if "tech" in existing or "tech" in incoming:
        union = _union_tech(existing.get("tech"), incoming.get("tech"))
        if union is not None:
            merged["tech"] = union

    # `inferred_keys` names which of this document's keys are INFERRED rather than OBSERVED
    # (api_intel's is_api/api_kind/api_version, auth_state's auth_state). Like `tech` it is
    # set-like and contributed by DIFFERENT tools for the same asset: katana tags the API
    # classification, httpx tags the auth state. Last-writer-wins would let httpx's marker
    # erase katana's, leaving `is_api` on the document with nothing recording that it was
    # inferred -- i.e. silently promoting an inference to an observation, which is exactly
    # the distinction Prompt 26 requires be preserved. Unioned for the same reason `tech` is:
    # both statements are simultaneously true of the merged document.
    if "inferred_keys" in existing or "inferred_keys" in incoming:
        marks = _union_tech(existing.get("inferred_keys"), incoming.get("inferred_keys"))
        if marks is not None:
            # Only keys actually PRESENT on the merged document may be marked -- a key that
            # no longer exists must not carry a dangling provenance claim.
            marks = sorted(k for k in marks if k in merged)
            if marks:
                merged["inferred_keys"] = marks
            else:
                merged.pop("inferred_keys", None)

    prior = existing.get(OBSERVATIONS_KEY)
    observations: list[dict] = [o for o in prior if isinstance(o, dict)] if isinstance(prior, list) else []

    incoming_observation = _observation_of(incoming)
    if incoming_observation:
        # Identity of an observation is its TOOL RUN: the same tool re-observing the asset in
        # a later run is a genuinely new observation, while a duplicate within one run is not.
        run_id = incoming_observation.get("discovered_in_tool_run")
        if not any(o.get("discovered_in_tool_run") == run_id for o in observations):
            observations = observations[-(MAX_OBSERVATIONS - 1):] + [incoming_observation]
        else:
            observations = observations[-MAX_OBSERVATIONS:]

    if observations:
        merged[OBSERVATIONS_KEY] = observations
    return merged


async def upsert_asset(
    db: AsyncSession,
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    asset_type: str,
    value: str,
    metadata: dict,
) -> None:
    """Insert-or-touch: assets outlive individual scans (blueprint §3), so a
    re-scan that re-discovers the same asset updates last_seen/metadata rather
    than creating a duplicate. Keyed on the (target_id, asset_type, value)
    unique constraint -- physically enforced over a generated SHA-256 of `value`,
    because a 2048-character utf8mb4 column cannot fit in an InnoDB index key
    (see migration f7a8b9c0d1e2).

    Metadata is MERGED, not replaced: several tools legitimately discover the same asset,
    and a wholesale replacement silently destroyed every earlier tool's provenance. See
    `merge_asset_metadata`.

    Raises AssetValueTooLong for a value the column cannot hold, BEFORE issuing any SQL,
    so the caller's transaction is never poisoned by a driver-level DataError.
    """
    validate_asset_value(value)
    now = datetime.now(timezone.utc)
    # Read the CURRENT document so a re-discovery merges into it instead of replacing it
    # (see merge_asset_metadata). Scoped by the same (project_id, target_id, asset_type,
    # value) grain the unique constraint enforces, so this can only ever read the one row
    # the upsert is about to touch -- it crosses no tenant and no asset boundary.
    existing = (
        await db.execute(
            select(Asset.metadata_).where(
                Asset.project_id == project_id,
                Asset.target_id == target_id,
                Asset.asset_type == asset_type,
                Asset.value == value,
            )
        )
    ).scalar_one_or_none()
    metadata = merge_asset_metadata(existing, metadata)
    # Target Asset.__table__, not the mapped class: on the declarative class the
    # name `metadata` is SQLAlchemy's MetaData object (the column's ORM attr is
    # metadata_), so mysql_insert(Asset).values(metadata=...) grabs the wrong thing
    # ("'MetaData' object has no attribute '_bulk_update_tuples'"). Against the
    # Table, keys are physical column names -- so "metadata" is the column.
    # Phase 0 MySQL cutover: pg_insert(...).on_conflict_do_update(constraint=...) ->
    # mysql_insert(...).on_duplicate_key_update(...) -- see risk/service.py's
    # upsert_risk_score for the fuller explanation of why no constraint name is needed.
    stmt = mysql_insert(Asset.__table__).values(
        project_id=project_id,
        target_id=target_id,
        asset_type=asset_type,
        value=value,
        metadata=metadata,
        first_seen=now,
        last_seen=now,
    )
    stmt = stmt.on_duplicate_key_update(last_seen=now, metadata=metadata)
    await db.execute(stmt)


async def list_assets(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Asset], int]:
    # AUDIT-010: verify the project EXISTS IN THIS WORKSPACE before listing.
    #
    # The query below is correctly scoped, so a cross-tenant project id never leaked data --
    # it returned `200 []`. But `200 []` and `404` are different answers to the same
    # question, and this API already answers it with 404 everywhere else (the single-resource
    # getters, and the reports/targets list endpoints, which call get_project for exactly
    # this reason). An empty 200 says "this project is yours and has nothing"; the truth is
    # "this project is not yours". Beyond the inconsistency, it is a weak existence oracle:
    # a caller could tell a real foreign project id from a random UUID if the two ever
    # diverged, and it hides genuine client bugs behind a success response.
    await get_project(db, workspace_id, project_id)
    query = select(Asset).where(Asset.project_id == project_id).order_by(Asset.first_seen, Asset.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_asset(db: AsyncSession, workspace_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset
