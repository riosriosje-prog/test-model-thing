"""§506(a) secured-status compiler candidate c5.

The compiler consumes only already-operative legal determinations created
through the c4 human-gated determination surface:

- CLAIM_ALLOWANCE_EVENT
- VALUATION_EVENT
- LIEN_PRIORITY_EVENT

It produces a new SECURED_STATUS_EVENT whose arithmetic is reproducible from
the exact bound input hashes. It does not consume raw assertions and does not
treat the arithmetic itself as a substitute for legal authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from typing import Tuple

from .secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    EventAuthorityState,
    UnresolvedLegalState,
    classify_secured_claim,
)
from .secured_claim_store import SecuredClaimStore


COMPILER_VERSION = "secured-status-506a-v1"
INPUT_STATES = {EventAuthorityState.OPERATIVE, EventAuthorityState.FINAL}
INPUT_TYPES = {
    "allowance": "CLAIM_ALLOWANCE_EVENT",
    "valuation": "VALUATION_EVENT",
    "priority": "LIEN_PRIORITY_EVENT",
}


@dataclass(frozen=True, slots=True)
class BoundDetermination:
    event_id: str
    expected_sha256: str

    def validate(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise UnresolvedLegalState("bound determination event_id is required")
        if not isinstance(self.expected_sha256, str) or len(self.expected_sha256) != 64:
            raise UnresolvedLegalState(
                "bound determination expected_sha256 must be 64 hex characters"
            )
        try:
            int(self.expected_sha256, 16)
        except ValueError as exc:
            raise UnresolvedLegalState(
                "bound determination expected_sha256 must be hexadecimal"
            ) from exc


@dataclass(frozen=True, slots=True)
class SecuredStatusCompileRequest:
    request_id: str
    compiled_at: datetime
    allowance: BoundDetermination
    valuation: BoundDetermination
    priority: BoundDetermination
    section_506a_authority: AuthorityReference
    result_authority_state: EventAuthorityState = EventAuthorityState.OPERATIVE

    def validate(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise UnresolvedLegalState("request_id is required")
        if self.compiled_at.tzinfo is None:
            raise UnresolvedLegalState("compiled_at must include timezone")
        self.allowance.validate()
        self.valuation.validate()
        self.priority.validate()
        ids = {
            self.allowance.event_id,
            self.valuation.event_id,
            self.priority.event_id,
        }
        if len(ids) != 3:
            raise UnresolvedLegalState(
                "allowance, valuation and priority must be distinct events"
            )
        if self.section_506a_authority is None:
            raise UnresolvedLegalState("§506(a) authority is required")
        for name, value in (
            ("§506(a) authority id", self.section_506a_authority.authority_id),
            ("§506(a) authority type", self.section_506a_authority.authority_type),
            ("§506(a) authority citation", self.section_506a_authority.citation),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if self.section_506a_authority.authority_type == "HUMAN_PROMOTION":
            raise UnresolvedLegalState(
                "human promotion cannot substitute for §506(a) legal authority"
            )
        if self.result_authority_state not in {
            EventAuthorityState.OPERATIVE,
            EventAuthorityState.FINAL,
        }:
            raise UnresolvedLegalState(
                "secured-status result must be OPERATIVE or FINAL"
            )


@dataclass(frozen=True, slots=True)
class SecuredStatusCompileResult:
    event: CanonicalEvent
    persisted_event_id: str
    input_event_ids: Tuple[str, str, str]
    input_event_hashes: Tuple[str, str, str]
    replay_idempotent: bool


def _payload(event: CanonicalEvent) -> dict[str, str]:
    payload = dict(event.payload)
    if len(payload) != len(event.payload):
        raise UnresolvedLegalState(
            f"event {event.event_id} has duplicate payload keys"
        )
    return payload


def _required(payload: dict[str, str], key: str, event: CanonicalEvent) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise UnresolvedLegalState(
            f"{event.event_type} missing required payload field {key}"
        )
    return value.strip()


def _money(payload: dict[str, str], key: str, event: CanonicalEvent) -> Decimal:
    raw = _required(payload, key, event)
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise UnresolvedLegalState(
            f"{event.event_type} payload field {key} is not a decimal"
        ) from exc
    if not value.is_finite() or value < 0:
        raise UnresolvedLegalState(
            f"{event.event_type} payload field {key} must be finite and non-negative"
        )
    return value


def _valid_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_c4_lineage(event: CanonicalEvent) -> None:
    payload = _payload(event)
    auth_id = _required(payload, "human_authorization_id", event)
    auth_hash = _required(payload, "human_authorization_sha256", event)
    reviewer = _required(payload, "human_reviewer", event)
    ids_raw = _required(payload, "source_event_ids_json", event)
    hashes_raw = _required(payload, "source_event_hashes_json", event)

    if not auth_id or not reviewer or not _valid_sha256(auth_hash):
        raise UnresolvedLegalState(
            f"{event.event_id} lacks valid c4 human-authorization lineage"
        )
    try:
        ids = json.loads(ids_raw)
        hashes = json.loads(hashes_raw)
    except json.JSONDecodeError as exc:
        raise UnresolvedLegalState(
            f"{event.event_id} has invalid c4 source-lineage JSON"
        ) from exc
    if (
        not isinstance(ids, list)
        or not isinstance(hashes, list)
        or not ids
        or len(ids) != len(hashes)
    ):
        raise UnresolvedLegalState(
            f"{event.event_id} has incomplete c4 source lineage"
        )
    if not all(isinstance(x, str) and x.strip() for x in ids):
        raise UnresolvedLegalState(
            f"{event.event_id} has invalid source event ids"
        )
    if not all(isinstance(x, str) and _valid_sha256(x) for x in hashes):
        raise UnresolvedLegalState(
            f"{event.event_id} has invalid source event hashes"
        )
    if event.authority.authority_type == "HUMAN_PROMOTION":
        raise UnresolvedLegalState(
            f"{event.event_id} uses human promotion as legal authority"
        )


def _load_bound(
    store: SecuredClaimStore,
    bound: BoundDetermination,
    expected_type: str,
) -> CanonicalEvent:
    try:
        event = store.get_event(bound.event_id)
    except KeyError as exc:
        raise UnresolvedLegalState(
            f"bound determination does not exist: {bound.event_id}"
        ) from exc
    if event.sha256 != bound.expected_sha256:
        raise UnresolvedLegalState(
            f"bound determination hash mismatch: {bound.event_id}"
        )
    if event.event_type != expected_type:
        raise UnresolvedLegalState(
            f"{bound.event_id} must be {expected_type}"
        )
    if event.authority_state not in INPUT_STATES:
        raise UnresolvedLegalState(
            f"{bound.event_id} must be OPERATIVE or FINAL"
        )
    _validate_c4_lineage(event)
    return event


def _request_hash(request: SecuredStatusCompileRequest) -> str:
    doc = {
        "request_id": request.request_id,
        "compiled_at": request.compiled_at.isoformat(),
        "allowance": {
            "event_id": request.allowance.event_id,
            "sha256": request.allowance.expected_sha256,
        },
        "valuation": {
            "event_id": request.valuation.event_id,
            "sha256": request.valuation.expected_sha256,
        },
        "priority": {
            "event_id": request.priority.event_id,
            "sha256": request.priority.expected_sha256,
        },
        "section_506a_authority": {
            "authority_id": request.section_506a_authority.authority_id,
            "authority_type": request.section_506a_authority.authority_type,
            "citation": request.section_506a_authority.citation,
            "jurisdiction": request.section_506a_authority.jurisdiction,
            "effective_date": (
                request.section_506a_authority.effective_date.isoformat()
                if request.section_506a_authority.effective_date else None
            ),
        },
        "result_authority_state": request.result_authority_state.value,
        "compiler_version": COMPILER_VERSION,
    }
    raw = json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class SecuredStatusCompiler:
    """Compile §506(a) classification from exact operative determinations."""

    def __init__(self, *, store: SecuredClaimStore) -> None:
        self.store = store

    def compile(
        self,
        request: SecuredStatusCompileRequest,
    ) -> SecuredStatusCompileResult:
        request.validate()

        allowance = _load_bound(
            self.store, request.allowance, INPUT_TYPES["allowance"]
        )
        valuation = _load_bound(
            self.store, request.valuation, INPUT_TYPES["valuation"]
        )
        priority = _load_bound(
            self.store, request.priority, INPUT_TYPES["priority"]
        )

        allowance_payload = _payload(allowance)
        valuation_payload = _payload(valuation)
        priority_payload = _payload(priority)

        allowance_claim_id = _required(
            allowance_payload, "claim_id", allowance
        )
        valuation_claim_id = _required(
            valuation_payload, "claim_id", valuation
        )
        priority_claim_id = _required(
            priority_payload, "claim_id", priority
        )
        if len({allowance_claim_id, valuation_claim_id, priority_claim_id}) != 1:
            raise UnresolvedLegalState(
                "allowance, valuation and priority claim_id must match"
            )

        valuation_package = _required(
            valuation_payload, "collateral_package_id", valuation
        )
        priority_package = _required(
            priority_payload, "collateral_package_id", priority
        )
        if valuation_package != priority_package:
            raise UnresolvedLegalState(
                "valuation and priority collateral_package_id must match"
            )

        valuation_context_id = _required(
            valuation_payload, "valuation_context_id", valuation
        )
        valuation_priority_snapshot = _required(
            valuation_payload, "priority_snapshot_id", valuation
        )
        priority_snapshot = _required(
            priority_payload, "priority_snapshot_id", priority
        )
        if valuation_priority_snapshot != priority_snapshot:
            raise UnresolvedLegalState(
                "valuation and priority snapshot ids must match"
            )

        allowed_amount = _money(
            allowance_payload, "allowed_amount", allowance
        )
        estate_interest_value = _money(
            valuation_payload, "estate_interest_value", valuation
        )
        value_available = _money(
            priority_payload, "value_available_to_creditor", priority
        )
        if value_available > estate_interest_value:
            raise UnresolvedLegalState(
                "priority value available to creditor cannot exceed estate interest value"
            )

        if (
            request.result_authority_state is EventAuthorityState.FINAL
            and not all(
                event.authority_state is EventAuthorityState.FINAL
                for event in (allowance, valuation, priority)
            )
        ):
            raise UnresolvedLegalState(
                "FINAL secured-status result requires all inputs FINAL"
            )

        classification = classify_secured_claim(
            allowed_claim_amount=allowed_amount,
            creditor_interest_value=value_available,
        )

        input_events = (allowance, valuation, priority)
        input_ids = tuple(event.event_id for event in input_events)
        input_hashes = tuple(event.sha256 for event in input_events)
        req_hash = _request_hash(request)

        event = CanonicalEvent(
            event_id=f"secured-status:{request.request_id}:{req_hash}",
            event_type="SECURED_STATUS_EVENT",
            event_effective_at=valuation.event_effective_at,
            event_recorded_at=request.compiled_at,
            authority=request.section_506a_authority,
            payload=(
                ("compiler_version", COMPILER_VERSION),
                ("compile_request_sha256", req_hash),
                ("claim_id", allowance_claim_id),
                ("collateral_package_id", valuation_package),
                ("valuation_context_id", valuation_context_id),
                ("priority_snapshot_id", priority_snapshot),
                ("allowed_claim_amount", str(classification.allowed_claim_amount)),
                ("estate_interest_value", str(estate_interest_value)),
                ("value_available_to_creditor", str(value_available)),
                ("secured_portion", str(classification.secured_portion)),
                ("unsecured_deficiency", str(classification.unsecured_deficiency)),
                ("input_event_ids_json", json.dumps(input_ids, separators=(",", ":"))),
                ("input_event_hashes_json", json.dumps(input_hashes, separators=(",", ":"))),
                ("derivation_kind", "ARITHMETIC_FROM_OPERATIVE_LEGAL_DETERMINATIONS"),
            ),
            authority_state=request.result_authority_state,
        )

        before = self.store.health()["event_count"]
        self.store.append_event(event)
        after = self.store.health()["event_count"]

        return SecuredStatusCompileResult(
            event=event,
            persisted_event_id=event.event_id,
            input_event_ids=input_ids,
            input_event_hashes=input_hashes,
            replay_idempotent=(before == after),
        )
