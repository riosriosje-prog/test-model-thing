"""Human-gated assertion -> legal-determination bridge candidate c4.

This module does not infer legal determinations from source assertions.
A determination event can be emitted only when:

1. every bound source event exists and is an allowed NONFINAL assertion;
2. the human authorization binds the exact SHA-256 of each source assertion;
3. the requested determination family is compatible with the assertion family;
4. a distinct legal authority is supplied for the determination;
5. the requested authority state is OPERATIVE or FINAL;
6. the authorization decision is exactly AUTHORIZE_DETERMINATION.

The human authorization governs GALIA's representation. It does not substitute
for the legal authority recorded on the resulting canonical event.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Mapping, Sequence, Tuple

from .secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    EventAuthorityState,
    UnresolvedLegalState,
)
from .secured_claim_store import SecuredClaimStore


class DeterminationDecision(str, Enum):
    AUTHORIZE_DETERMINATION = "AUTHORIZE_DETERMINATION"


ASSERTION_TO_DETERMINATION = {
    "CLAIM_ASSERTION_EVENT": {"CLAIM_ALLOWANCE_EVENT"},
    "LIEN_ASSERTION_EVENT": {"LIEN_PRIORITY_EVENT"},
    "VALUATION_ASSERTION_EVENT": {"VALUATION_EVENT"},
    "PRIORITY_ASSERTION_EVENT": {"LIEN_PRIORITY_EVENT"},
    "PAYMENT_ASSERTION_EVENT": {"PAYMENT_EVENT"},
    "PLAN_TREATMENT_ASSERTION_EVENT": {"PLAN_TREATMENT_EVENT"},
}

ALLOWED_DETERMINATION_STATES = {
    EventAuthorityState.OPERATIVE,
    EventAuthorityState.FINAL,
}


@dataclass(frozen=True, slots=True)
class BoundAssertion:
    event_id: str
    expected_sha256: str

    def validate(self) -> None:
        if not self.event_id.strip():
            raise UnresolvedLegalState("bound assertion event_id is required")
        if len(self.expected_sha256) != 64:
            raise UnresolvedLegalState(
                "bound assertion expected_sha256 must be 64 hex characters"
            )
        try:
            int(self.expected_sha256, 16)
        except ValueError as exc:
            raise UnresolvedLegalState(
                "bound assertion expected_sha256 must be hexadecimal"
            ) from exc


@dataclass(frozen=True, slots=True)
class HumanDeterminationAuthorization:
    authorization_id: str
    decision: DeterminationDecision
    reviewer: str
    rationale: str
    issued_at: datetime
    determination_event_type: str
    determination_effective_at: datetime
    determination_authority_state: EventAuthorityState
    legal_authority: AuthorityReference
    bound_assertions: Tuple[BoundAssertion, ...]
    determination_payload: Tuple[Tuple[str, str], ...] = ()

    def validate(self) -> None:
        for name, value in (
            ("authorization_id", self.authorization_id),
            ("reviewer", self.reviewer),
            ("rationale", self.rationale),
            ("determination_event_type", self.determination_event_type),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if self.decision is not DeterminationDecision.AUTHORIZE_DETERMINATION:
            raise UnresolvedLegalState(
                "human decision must be AUTHORIZE_DETERMINATION"
            )
        if self.issued_at.tzinfo is None:
            raise UnresolvedLegalState("issued_at must include timezone")
        if self.determination_effective_at.tzinfo is None:
            raise UnresolvedLegalState(
                "determination_effective_at must include timezone"
            )
        if self.determination_authority_state not in ALLOWED_DETERMINATION_STATES:
            raise UnresolvedLegalState(
                "new determination must be OPERATIVE or FINAL"
            )
        if self.legal_authority is None:
            raise UnresolvedLegalState(
                "distinct legal authority is required for determination"
            )
        for name, value in (
            ("legal authority id", self.legal_authority.authority_id),
            ("legal authority type", self.legal_authority.authority_type),
            ("legal authority citation", self.legal_authority.citation),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if not self.bound_assertions:
            raise UnresolvedLegalState(
                "at least one bound source assertion is required"
            )
        ids: set[str] = set()
        for bound in self.bound_assertions:
            bound.validate()
            if bound.event_id in ids:
                raise UnresolvedLegalState("duplicate bound assertion event_id")
            ids.add(bound.event_id)
        payload_keys: set[str] = set()
        for key, value in self.determination_payload:
            if not isinstance(key, str) or not key.strip():
                raise UnresolvedLegalState(
                    "determination payload key is required"
                )
            if not isinstance(value, str):
                raise UnresolvedLegalState(
                    "determination payload values must be strings"
                )
            if key in payload_keys:
                raise UnresolvedLegalState(
                    "determination payload keys must be unique"
                )
            payload_keys.add(key)

    def canonical_dict(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "decision": self.decision.value,
            "reviewer": self.reviewer,
            "rationale": self.rationale,
            "issued_at": self.issued_at.isoformat(),
            "determination_event_type": self.determination_event_type,
            "determination_effective_at": (
                self.determination_effective_at.isoformat()
            ),
            "determination_authority_state": (
                self.determination_authority_state.value
            ),
            "legal_authority": {
                "authority_id": self.legal_authority.authority_id,
                "authority_type": self.legal_authority.authority_type,
                "citation": self.legal_authority.citation,
                "jurisdiction": self.legal_authority.jurisdiction,
                "effective_date": (
                    self.legal_authority.effective_date.isoformat()
                    if self.legal_authority.effective_date else None
                ),
            },
            "bound_assertions": [
                {
                    "event_id": b.event_id,
                    "expected_sha256": b.expected_sha256,
                }
                for b in self.bound_assertions
            ],
            "determination_payload": list(self.determination_payload),
        }

    @property
    def sha256(self) -> str:
        raw = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class DeterminationResult:
    authorization_sha256: str
    source_event_ids: Tuple[str, ...]
    source_event_hashes: Tuple[str, ...]
    event: CanonicalEvent
    persisted_event_id: str
    replay_idempotent: bool


def _payload_dict(event: CanonicalEvent) -> dict[str, str]:
    return dict(event.payload)


def _validate_assertion_family(
    *, source_events: Sequence[CanonicalEvent], determination_event_type: str
) -> None:
    families = {event.event_type for event in source_events}
    compatible = set()
    for family in families:
        allowed = ASSERTION_TO_DETERMINATION.get(family)
        if allowed is None:
            raise UnresolvedLegalState(
                f"source event {family!r} is not an allowed assertion family"
            )
        compatible.update(allowed)
    if determination_event_type not in compatible:
        raise UnresolvedLegalState(
            "requested determination type is incompatible with bound assertions"
        )

    # Prevent cross-family laundering. If multiple assertion families are bound,
    # each family must independently permit the same determination type.
    for family in families:
        if determination_event_type not in ASSERTION_TO_DETERMINATION[family]:
            raise UnresolvedLegalState(
                "all bound assertion families must support the same determination"
            )


class SecuredClaimDeterminationGate:
    """Create one canonical legal determination from exact bound assertions."""

    def __init__(self, *, store: SecuredClaimStore) -> None:
        self.store = store

    def authorize(
        self,
        authorization: HumanDeterminationAuthorization,
    ) -> DeterminationResult:
        authorization.validate()

        source_events: list[CanonicalEvent] = []
        source_hashes: list[str] = []
        for bound in authorization.bound_assertions:
            try:
                event = self.store.get_event(bound.event_id)
            except KeyError as exc:
                raise UnresolvedLegalState(
                    f"bound assertion does not exist: {bound.event_id}"
                ) from exc
            if event.sha256 != bound.expected_sha256:
                raise UnresolvedLegalState(
                    f"bound assertion hash mismatch: {bound.event_id}"
                )
            if event.authority_state is not EventAuthorityState.NONFINAL:
                raise UnresolvedLegalState(
                    "source assertions must remain NONFINAL"
                )
            if event.event_type not in ASSERTION_TO_DETERMINATION:
                raise UnresolvedLegalState(
                    "source event is not an allowed assertion"
                )
            source_events.append(event)
            source_hashes.append(event.sha256)

        _validate_assertion_family(
            source_events=source_events,
            determination_event_type=authorization.determination_event_type,
        )

        blocker_codes: set[str] = set()
        for event in source_events:
            payload = _payload_dict(event)
            raw = payload.get("blocker_codes_json", "[]")
            try:
                codes = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise UnresolvedLegalState(
                    "source assertion blocker_codes_json is invalid"
                ) from exc
            if not isinstance(codes, list):
                raise UnresolvedLegalState(
                    "source assertion blocker_codes_json must be an array"
                )
            blocker_codes.update(str(code) for code in codes)
        if blocker_codes:
            raise UnresolvedLegalState(
                "bound assertions retain unresolved promotion/evidence blockers: "
                + ",".join(sorted(blocker_codes))
            )

        auth_hash = authorization.sha256
        event_id = (
            f"legal-determination:{authorization.authorization_id}:{auth_hash}"
        )
        lineage_payload = (
            ("human_authorization_id", authorization.authorization_id),
            ("human_authorization_sha256", auth_hash),
            ("human_reviewer", authorization.reviewer),
            ("source_event_ids_json", json.dumps(
                [e.event_id for e in source_events],
                separators=(",", ":"),
            )),
            ("source_event_hashes_json", json.dumps(
                source_hashes,
                separators=(",", ":"),
            )),
        )
        event = CanonicalEvent(
            event_id=event_id,
            event_type=authorization.determination_event_type,
            event_effective_at=authorization.determination_effective_at,
            event_recorded_at=authorization.issued_at,
            authority=authorization.legal_authority,
            payload=lineage_payload + authorization.determination_payload,
            authority_state=authorization.determination_authority_state,
        )

        before = self.store.health()["event_count"]
        self.store.append_event(event)
        after = self.store.health()["event_count"]

        return DeterminationResult(
            authorization_sha256=auth_hash,
            source_event_ids=tuple(e.event_id for e in source_events),
            source_event_hashes=tuple(source_hashes),
            event=event,
            persisted_event_id=event.event_id,
            replay_idempotent=(before == after),
        )
