"""Read-only HistoricalStore -> secured-claim shadow bridge candidate c3.

The bridge imports only explicitly tagged source claims and persists them as
NONFINAL assertion events in the isolated secured-claim store.

It never:
- reviews/promotes a HistoricalStore claim;
- mutates HistoricalStore;
- maps a source assertion directly into an operative allowance/valuation/
  priority/plan determination;
- writes to main/model/Hugging Face state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Any, Protocol, Tuple, runtime_checkable

from .secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    EventAuthorityState,
    UnresolvedLegalState,
)
from .secured_claim_store import SecuredClaimStore


SHADOW_PROFILE_VERSION = "secured-claim-shadow-v1"

ALLOWED_ASSERTION_EVENT_TYPES = {
    "CLAIM_ASSERTION_EVENT",
    "LIEN_ASSERTION_EVENT",
    "VALUATION_ASSERTION_EVENT",
    "PRIORITY_ASSERTION_EVENT",
    "PAYMENT_ASSERTION_EVENT",
    "PLAN_TREATMENT_ASSERTION_EVENT",
    "SECTION_506C_ASSERTION_EVENT",
    "SECTION_506B_COMPONENT_ASSERTION_EVENT",
}


@runtime_checkable
class HistoricalStoreReadProtocol(Protocol):
    def claim_bundle(self, claim_id: str) -> dict[str, Any]: ...
    def claim_promotion_blockers(self, claim_id: str) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class SecuredClaimShadowImportResult:
    source_claim_id: str
    source_status: str
    bundle_sha256: str
    evidence_snapshot: Tuple[str, ...]
    blocker_codes: Tuple[str, ...]
    event: CanonicalEvent
    persisted_event_id: str
    replay_idempotent: bool


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _required_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UnresolvedLegalState(f"{name} is required")
    return value.strip()


def _parse_iso_datetime(name: str, value: Any) -> datetime:
    text = _required_text(name, value)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise UnresolvedLegalState(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise UnresolvedLegalState(f"{name} must include timezone")
    return parsed


def _parse_metadata(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise UnresolvedLegalState("claim metadata_json must be JSON text or object")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UnresolvedLegalState("claim metadata_json is invalid JSON") from exc
    if not isinstance(value, dict):
        raise UnresolvedLegalState("claim metadata_json must decode to an object")
    return value


def _evidence_snapshot(rows: list[dict[str, Any]]) -> Tuple[str, ...]:
    snapshot: list[str] = []
    for row in rows:
        evidence_id = _required_text("evidence_id", row.get("evidence_id"))
        digest = (
            row.get("representation_content_sha256")
            or row.get("excerpt_sha256")
            or row.get("content_sha256")
        )
        if not isinstance(digest, str) or len(digest) != 64:
            digest = _sha256_json(row)
        snapshot.append(f"{evidence_id}:{digest.lower()}")
    return tuple(snapshot)


def _source_recorded_at(
    claim: dict[str, Any],
    reviews: list[dict[str, Any]],
) -> datetime:
    candidates: list[str] = []
    created = claim.get("created_at_utc")
    if isinstance(created, str) and created.strip():
        candidates.append(created)
    for review in reviews:
        value = review.get("created_at_utc")
        if isinstance(value, str) and value.strip():
            candidates.append(value)
    if not candidates:
        raise UnresolvedLegalState("source claim has no deterministic recorded time")
    parsed = [_parse_iso_datetime("source recorded_at", value) for value in candidates]
    return max(parsed)


class SecuredClaimShadowBridge:
    """Mirror one tagged HistoricalStore claim into isolated assertion storage."""

    def __init__(self, *, target_store: SecuredClaimStore) -> None:
        self.target_store = target_store

    def mirror_claim(
        self,
        *,
        source_store: HistoricalStoreReadProtocol,
        claim_id: str,
    ) -> SecuredClaimShadowImportResult:
        if not isinstance(source_store, HistoricalStoreReadProtocol):
            raise TypeError(
                "source_store must expose claim_bundle and claim_promotion_blockers"
            )

        bundle = source_store.claim_bundle(claim_id)
        claim = bundle.get("claim")
        evidence = bundle.get("evidence")
        reviews = bundle.get("reviews")
        if not isinstance(claim, dict):
            raise UnresolvedLegalState("claim bundle is missing claim object")
        if not isinstance(evidence, list) or not all(
            isinstance(row, dict) for row in evidence
        ):
            raise UnresolvedLegalState("claim evidence must be a list of objects")
        if not isinstance(reviews, list) or not all(
            isinstance(row, dict) for row in reviews
        ):
            raise UnresolvedLegalState("claim reviews must be a list of objects")

        source_claim_id = _required_text("source claim_id", claim.get("claim_id"))
        if source_claim_id != claim_id:
            raise UnresolvedLegalState("claim bundle does not match requested claim_id")

        source_status = _required_text("source status", claim.get("status"))
        if source_status not in {"PROPOSED", "VALIDATED"}:
            raise UnresolvedLegalState(
                "shadow import accepts only non-canonical PROPOSED/VALIDATED claims"
            )

        snapshot = _evidence_snapshot(evidence)
        if not snapshot:
            raise UnresolvedLegalState(
                "shadow import requires at least one evidence snapshot"
            )

        metadata = _parse_metadata(claim.get("metadata_json"))
        profile = metadata.get("secured_claim_shadow")
        if not isinstance(profile, dict):
            raise UnresolvedLegalState(
                "claim lacks explicit secured_claim_shadow metadata"
            )

        event_type = _required_text("shadow event_type", profile.get("event_type"))
        if event_type not in ALLOWED_ASSERTION_EVENT_TYPES:
            raise UnresolvedLegalState(
                "shadow import may create assertion events only"
            )

        effective_at = _parse_iso_datetime(
            "shadow event_effective_at", profile.get("event_effective_at")
        )

        authority_doc = profile.get("authority")
        if not isinstance(authority_doc, dict):
            raise UnresolvedLegalState("shadow authority object is required")
        authority = AuthorityReference(
            authority_id=_required_text(
                "authority_id", authority_doc.get("authority_id")
            ),
            authority_type=_required_text(
                "authority_type", authority_doc.get("authority_type")
            ),
            citation=_required_text("citation", authority_doc.get("citation")),
            jurisdiction=(
                _required_text("jurisdiction", authority_doc.get("jurisdiction"))
                if authority_doc.get("jurisdiction") is not None
                else None
            ),
            effective_date=(
                _parse_iso_datetime(
                    "authority effective_date",
                    authority_doc.get("effective_date"),
                )
                if authority_doc.get("effective_date") is not None
                else None
            ),
        )

        blockers = tuple(
            sorted(
                _required_text("blocker code", row.get("code"))
                for row in source_store.claim_promotion_blockers(claim_id)
            )
        )
        bundle_hash = _sha256_json(bundle)
        evidence_hash = hashlib.sha256(
            _canonical_json_bytes(snapshot)
        ).hexdigest()
        event_id = f"hist-shadow:{claim_id}:{bundle_hash}"

        payload = (
            ("shadow_profile_version", SHADOW_PROFILE_VERSION),
            ("source_claim_id", claim_id),
            ("source_status", source_status),
            ("source_document_id", str(claim.get("document_id") or "")),
            ("source_predicate", str(claim.get("predicate") or "")),
            ("source_object_value", str(claim.get("object_value") or "")),
            ("source_claim_text_sha256", hashlib.sha256(
                str(claim.get("claim_text") or "").encode("utf-8")
            ).hexdigest()),
            ("source_bundle_sha256", bundle_hash),
            ("evidence_snapshot_sha256", evidence_hash),
            ("evidence_count", str(len(snapshot))),
            ("blocker_codes_json", json.dumps(blockers, separators=(",", ":"))),
        )

        event = CanonicalEvent(
            event_id=event_id,
            event_type=event_type,
            event_effective_at=effective_at,
            event_recorded_at=_source_recorded_at(claim, reviews),
            authority=authority,
            payload=payload,
            authority_state=EventAuthorityState.NONFINAL,
        )

        before = self.target_store.health()["event_count"]
        self.target_store.append_event(event)
        after = self.target_store.health()["event_count"]

        return SecuredClaimShadowImportResult(
            source_claim_id=claim_id,
            source_status=source_status,
            bundle_sha256=bundle_hash,
            evidence_snapshot=snapshot,
            blocker_codes=blockers,
            event=event,
            persisted_event_id=event.event_id,
            replay_idempotent=(before == after),
        )
