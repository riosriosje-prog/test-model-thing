"""§506(d) lien-consequence compiler candidate c8.

The compiler separates:
- whether a lien/property interest exists under applicable nonbankruptcy law;
- whether a claim is allowed/disallowed/not allowed solely for no proof of claim;
- §506(a) secured classification;
- the chapter-specific consequence of §506(d).

It never treats §506(a) arithmetic as an automatic lien strip.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from typing import Tuple

from .authority_lifecycle import resolve_effective_authority_state
from .secured_claim_store import SecuredClaimStore
from .secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    EventAuthorityState,
    UnresolvedLegalState,
)
from .secured_status_compiler import BoundDetermination


COMPILER_VERSION = "section-506d-v1"
ACTIVE_STATES = {EventAuthorityState.OPERATIVE, EventAuthorityState.FINAL}
SUPPORTED_CHAPTERS = {7, 11, 13}

LIEN_PROPERTY_STATES = {"EXISTS", "DOES_NOT_EXIST"}
PERFECTION_STATES = {"PERFECTED", "UNPERFECTED", "NOT_APPLICABLE"}

CLAIM_ALLOWANCE_STATES = {
    "ALLOWED",
    "DISALLOWED",
    "NOT_ALLOWED_DUE_ONLY_TO_NO_PROOF",
}
DISALLOWANCE_BASIS_CODES = {"502B5", "502E", "OTHER"}

RULE_NONBANKRUPTCY_NO_LIEN = "NONBANKRUPTCY_LIEN_EXISTENCE"
RULE_506D_VOID = "SECTION_506D_STATUTORY_VOIDING"
RULE_506D_EXCEPTION_1 = "SECTION_506D_EXCEPTION_1"
RULE_506D_EXCEPTION_2 = "SECTION_506D_EXCEPTION_2"
RULE_DEWSNUP = "DEWSNUP_CH7_NO_STRIP_DOWN"
RULE_CAULKETT = "CAULKETT_CH7_NO_STRIP_OFF"
RULE_ALLOWED_LIEN = "ALLOWED_LIEN_UNAFFECTED_506D"
RULE_CHAPTER_SPECIFIC = "CHAPTER_SPECIFIC_TREATMENT_REQUIRED"


@dataclass(frozen=True, slots=True)
class Section506DCompileRequest:
    request_id: str
    compiled_at: datetime
    chapter: int
    lien_existence: BoundDetermination
    claim_status: BoundDetermination
    secured_status: BoundDetermination | None
    section_506d_authority: AuthorityReference
    rule_basis_code: str
    rule_authority: AuthorityReference
    result_authority_state: EventAuthorityState = EventAuthorityState.OPERATIVE

    def validate(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise UnresolvedLegalState("request_id is required")
        if self.compiled_at.tzinfo is None:
            raise UnresolvedLegalState("compiled_at must include timezone")
        if self.chapter not in SUPPORTED_CHAPTERS:
            raise UnresolvedLegalState(
                "c8 supports Chapter 7, 11, and 13 only"
            )
        self.lien_existence.validate()
        self.claim_status.validate()
        if self.secured_status is not None:
            self.secured_status.validate()
        ids = [self.lien_existence.event_id, self.claim_status.event_id]
        if self.secured_status is not None:
            ids.append(self.secured_status.event_id)
        if len(ids) != len(set(ids)):
            raise UnresolvedLegalState("all bound input event ids must be unique")

        if not isinstance(self.rule_basis_code, str) or not self.rule_basis_code.strip():
            raise UnresolvedLegalState("rule_basis_code is required")

        for label, authority in (
            ("§506(d)", self.section_506d_authority),
            ("rule", self.rule_authority),
        ):
            if authority is None:
                raise UnresolvedLegalState(f"{label} authority is required")
            for name, value in (
                ("authority id", authority.authority_id),
                ("authority type", authority.authority_type),
                ("authority citation", authority.citation),
            ):
                if not isinstance(value, str) or not value.strip():
                    raise UnresolvedLegalState(
                        f"{label} {name} is required"
                    )
            if authority.authority_type == "HUMAN_PROMOTION":
                raise UnresolvedLegalState(
                    f"human promotion cannot substitute for {label} legal authority"
                )

        if self.result_authority_state not in ACTIVE_STATES:
            raise UnresolvedLegalState(
                "lien consequence result must be OPERATIVE or FINAL"
            )


@dataclass(frozen=True, slots=True)
class Section506DCompileResult:
    event: CanonicalEvent
    persisted_event_id: str
    consequence_code: str
    input_event_ids: Tuple[str, ...]
    input_event_hashes: Tuple[str, ...]
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


def _valid_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_c4_lineage(event: CanonicalEvent) -> None:
    payload = _payload(event)
    _required(payload, "human_authorization_id", event)
    auth_hash = _required(payload, "human_authorization_sha256", event)
    _required(payload, "human_reviewer", event)
    ids_raw = _required(payload, "source_event_ids_json", event)
    hashes_raw = _required(payload, "source_event_hashes_json", event)
    if not _valid_sha256(auth_hash):
        raise UnresolvedLegalState(
            f"{event.event_id} lacks valid c4 authorization hash"
        )
    try:
        ids = json.loads(ids_raw)
        hashes = json.loads(hashes_raw)
    except json.JSONDecodeError as exc:
        raise UnresolvedLegalState(
            f"{event.event_id} has invalid c4 lineage JSON"
        ) from exc
    if (
        not isinstance(ids, list)
        or not isinstance(hashes, list)
        or not ids
        or len(ids) != len(hashes)
        or not all(isinstance(x, str) and x.strip() for x in ids)
        or not all(_valid_sha256(x) for x in hashes)
    ):
        raise UnresolvedLegalState(
            f"{event.event_id} has incomplete c4 lineage"
        )
    if event.authority.authority_type == "HUMAN_PROMOTION":
        raise UnresolvedLegalState(
            f"{event.event_id} uses human promotion as legal authority"
        )


def _validate_c5_status(event: CanonicalEvent) -> None:
    payload = _payload(event)
    if _required(payload, "compiler_version", event) != "secured-status-506a-v1":
        raise UnresolvedLegalState(
            "secured_status input lacks c5 compiler provenance"
        )
    if _required(payload, "derivation_kind", event) != (
        "ARITHMETIC_FROM_OPERATIVE_LEGAL_DETERMINATIONS"
    ):
        raise UnresolvedLegalState(
            "secured_status input has invalid derivation provenance"
        )
    hashes_raw = _required(payload, "input_event_hashes_json", event)
    lifecycle_raw = _required(
        payload, "input_lifecycle_bindings_json", event
    )
    try:
        hashes = json.loads(hashes_raw)
        lifecycle = json.loads(lifecycle_raw)
    except json.JSONDecodeError as exc:
        raise UnresolvedLegalState(
            "secured_status input provenance JSON is invalid"
        ) from exc
    if not isinstance(hashes, list) or len(hashes) != 3 or not all(
        _valid_sha256(x) for x in hashes
    ):
        raise UnresolvedLegalState(
            "secured_status input lacks exact c5 input hashes"
        )
    if not isinstance(lifecycle, list) or len(lifecycle) != 3:
        raise UnresolvedLegalState(
            "secured_status input lacks c7 lifecycle bindings"
        )


def _load_bound(
    store: SecuredClaimStore,
    bound: BoundDetermination,
    expected_type: str,
    *,
    require_c4: bool,
) -> tuple[CanonicalEvent, object]:
    try:
        event = store.get_event(bound.event_id)
    except KeyError as exc:
        raise UnresolvedLegalState(
            f"bound event does not exist: {bound.event_id}"
        ) from exc
    if event.sha256 != bound.expected_sha256:
        raise UnresolvedLegalState(
            f"bound event hash mismatch: {bound.event_id}"
        )
    if event.event_type != expected_type:
        raise UnresolvedLegalState(
            f"{bound.event_id} must be {expected_type}"
        )
    state = resolve_effective_authority_state(store, event.event_id)
    if state.effective_state not in ACTIVE_STATES:
        raise UnresolvedLegalState(
            f"{bound.event_id} is not effectively OPERATIVE or FINAL: "
            f"{state.effective_state.value}"
        )
    if require_c4:
        _validate_c4_lineage(event)
    return event, state


def _authority_doc(authority: AuthorityReference) -> dict[str, object]:
    return {
        "authority_id": authority.authority_id,
        "authority_type": authority.authority_type,
        "citation": authority.citation,
        "jurisdiction": authority.jurisdiction,
        "effective_date": (
            authority.effective_date.isoformat()
            if authority.effective_date else None
        ),
    }


def _request_hash(
    request: Section506DCompileRequest,
    lifecycle_bindings: tuple[tuple[str, str, str, str], ...],
) -> str:
    def bound(value: BoundDetermination | None) -> dict[str, str] | None:
        if value is None:
            return None
        return {
            "event_id": value.event_id,
            "expected_sha256": value.expected_sha256,
        }

    doc = {
        "request_id": request.request_id,
        "compiled_at": request.compiled_at.isoformat(),
        "chapter": request.chapter,
        "lien_existence": bound(request.lien_existence),
        "claim_status": bound(request.claim_status),
        "secured_status": bound(request.secured_status),
        "section_506d_authority": _authority_doc(
            request.section_506d_authority
        ),
        "rule_basis_code": request.rule_basis_code,
        "rule_authority": _authority_doc(request.rule_authority),
        "result_authority_state": request.result_authority_state.value,
        "lifecycle_bindings": list(lifecycle_bindings),
        "compiler_version": COMPILER_VERSION,
    }
    raw = json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _expected_rule_and_consequence(
    *,
    chapter: int,
    lien_state: str,
    allowance_state: str,
    disallowance_basis: str | None,
    allowed_amount: Decimal | None,
    secured_portion: Decimal | None,
) -> tuple[str, str, str]:
    if lien_state == "DOES_NOT_EXIST":
        return (
            RULE_NONBANKRUPTCY_NO_LIEN,
            "NO_LIEN_PROPERTY_INTEREST",
            "NOT_REACHED",
        )

    if allowance_state == "DISALLOWED":
        if disallowance_basis in {"502B5", "502E"}:
            return (
                RULE_506D_EXCEPTION_1,
                "LIEN_NOT_VOIDED_506D_EXCEPTION_1",
                "EXCEPTION",
            )
        return (
            RULE_506D_VOID,
            "LIEN_VOID_TO_EXTENT_CLAIM_DISALLOWED",
            "VOID",
        )

    if allowance_state == "NOT_ALLOWED_DUE_ONLY_TO_NO_PROOF":
        return (
            RULE_506D_EXCEPTION_2,
            "LIEN_NOT_VOIDED_506D_EXCEPTION_2",
            "EXCEPTION",
        )

    if allowed_amount is None or secured_portion is None:
        raise UnresolvedLegalState(
            "ALLOWED claim requires c5 secured-status classification"
        )

    if chapter == 7:
        if secured_portion == 0 and allowed_amount > 0:
            return (
                RULE_CAULKETT,
                "NO_506D_STRIP_OFF_CH7_ALLOWED_CLAIM",
                "NO_STRIP",
            )
        if secured_portion < allowed_amount:
            return (
                RULE_DEWSNUP,
                "NO_506D_STRIP_DOWN_CH7_ALLOWED_CLAIM",
                "NO_STRIP",
            )
        return (
            RULE_ALLOWED_LIEN,
            "LIEN_UNAFFECTED_BY_506D_ALLOWED_FULLY_SECURED",
            "UNAFFECTED",
        )

    return (
        RULE_CHAPTER_SPECIFIC,
        f"NO_AUTOMATIC_506D_CONSEQUENCE_CHAPTER_{chapter}",
        "CHAPTER_SPECIFIC_PATH_REQUIRED",
    )


class Section506DCompiler:
    """Compile lien consequence without collapsing §506(a) into lien avoidance."""

    def __init__(self, *, store: SecuredClaimStore) -> None:
        self.store = store

    def compile(
        self,
        request: Section506DCompileRequest,
    ) -> Section506DCompileResult:
        request.validate()

        lien, lien_state_record = _load_bound(
            self.store,
            request.lien_existence,
            "LIEN_EXISTENCE_EVENT",
            require_c4=True,
        )
        claim, claim_state_record = _load_bound(
            self.store,
            request.claim_status,
            "CLAIM_STATUS_EVENT",
            require_c4=True,
        )

        lien_payload = _payload(lien)
        claim_payload = _payload(claim)

        lien_id = _required(lien_payload, "lien_id", lien)
        lien_claim_id = _required(lien_payload, "claim_id", lien)
        claim_id = _required(claim_payload, "claim_id", claim)
        if lien_claim_id != claim_id:
            raise UnresolvedLegalState(
                "lien existence and claim status claim_id must match"
            )

        lien_state = _required(
            lien_payload, "lien_property_interest_state", lien
        )
        if lien_state not in LIEN_PROPERTY_STATES:
            raise UnresolvedLegalState(
                "lien_property_interest_state must be EXISTS or DOES_NOT_EXIST"
            )
        perfection_state = _required(
            lien_payload, "perfection_state", lien
        )
        if perfection_state not in PERFECTION_STATES:
            raise UnresolvedLegalState(
                "perfection_state must be PERFECTED, UNPERFECTED, or NOT_APPLICABLE"
            )
        applicable_law = _required(
            lien_payload, "applicable_nonbankruptcy_law", lien
        )
        property_interest_basis = _required(
            lien_payload, "property_interest_basis", lien
        )
        collateral_package_id = _required(
            lien_payload, "collateral_package_id", lien
        )

        allowance_state = _required(
            claim_payload, "allowance_state", claim
        )
        if allowance_state not in CLAIM_ALLOWANCE_STATES:
            raise UnresolvedLegalState(
                "unsupported claim allowance_state"
            )

        disallowance_basis = None
        if allowance_state == "DISALLOWED":
            disallowance_basis = _required(
                claim_payload, "disallowance_basis_code", claim
            )
            if disallowance_basis not in DISALLOWANCE_BASIS_CODES:
                raise UnresolvedLegalState(
                    "unsupported disallowance_basis_code"
                )
        elif claim_payload.get("disallowance_basis_code"):
            raise UnresolvedLegalState(
                "disallowance_basis_code is permitted only when DISALLOWED"
            )

        status = None
        status_state_record = None
        allowed_amount = None
        secured_portion = None

        if allowance_state == "ALLOWED" and lien_state == "EXISTS":
            if request.secured_status is None:
                raise UnresolvedLegalState(
                    "ALLOWED claim with existing lien requires bound SECURED_STATUS_EVENT"
                )
            status, status_state_record = _load_bound(
                self.store,
                request.secured_status,
                "SECURED_STATUS_EVENT",
                require_c4=False,
            )
            _validate_c5_status(status)
            status_payload = _payload(status)
            if _required(status_payload, "claim_id", status) != claim_id:
                raise UnresolvedLegalState(
                    "secured status claim_id must match claim status"
                )
            if _required(
                status_payload, "collateral_package_id", status
            ) != collateral_package_id:
                raise UnresolvedLegalState(
                    "secured status collateral package must match lien existence"
                )
            allowed_amount = _money(
                status_payload, "allowed_claim_amount", status
            )
            secured_portion = _money(
                status_payload, "secured_portion", status
            )
            if secured_portion > allowed_amount:
                raise UnresolvedLegalState(
                    "secured_portion cannot exceed allowed_claim_amount"
                )
        elif lien_state == "DOES_NOT_EXIST":
            if request.secured_status is not None:
                raise UnresolvedLegalState(
                    "secured_status must be absent when no lien property interest exists"
                )
        elif request.secured_status is not None:
            raise UnresolvedLegalState(
                "secured_status is permitted only for ALLOWED claim with existing lien"
            )

        expected_rule, consequence_code, section_effect = (
            _expected_rule_and_consequence(
                chapter=request.chapter,
                lien_state=lien_state,
                allowance_state=allowance_state,
                disallowance_basis=disallowance_basis,
                allowed_amount=allowed_amount,
                secured_portion=secured_portion,
            )
        )
        if request.rule_basis_code != expected_rule:
            raise UnresolvedLegalState(
                f"rule_basis_code mismatch: expected {expected_rule}"
            )

        input_events = [lien, claim]
        state_records = [lien_state_record, claim_state_record]
        if status is not None and status_state_record is not None:
            input_events.append(status)
            state_records.append(status_state_record)

        if (
            request.result_authority_state is EventAuthorityState.FINAL
            and not all(
                state.effective_state is EventAuthorityState.FINAL
                for state in state_records
            )
        ):
            raise UnresolvedLegalState(
                "FINAL lien consequence requires all bound inputs FINAL in reconstructed effective state"
            )

        input_ids = tuple(event.event_id for event in input_events)
        input_hashes = tuple(event.sha256 for event in input_events)
        lifecycle_bindings = tuple(
            (
                state.target_event_id,
                state.effective_state.value,
                state.tail_transition_event_id or "",
                state.tail_transition_sha256 or "",
            )
            for state in state_records
        )
        req_hash = _request_hash(request, lifecycle_bindings)

        payload = [
            ("compiler_version", COMPILER_VERSION),
            ("compile_request_sha256", req_hash),
            ("chapter", str(request.chapter)),
            ("claim_id", claim_id),
            ("lien_id", lien_id),
            ("collateral_package_id", collateral_package_id),
            ("lien_property_interest_state", lien_state),
            ("perfection_state", perfection_state),
            ("applicable_nonbankruptcy_law", applicable_law),
            ("property_interest_basis", property_interest_basis),
            ("claim_allowance_state", allowance_state),
            ("disallowance_basis_code", disallowance_basis or ""),
            ("rule_basis_code", expected_rule),
            ("consequence_code", consequence_code),
            ("section_506d_effect", section_effect),
            (
                "section_506d_authority_json",
                json.dumps(
                    _authority_doc(request.section_506d_authority),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
            ("input_event_ids_json", json.dumps(input_ids, separators=(",", ":"))),
            ("input_event_hashes_json", json.dumps(input_hashes, separators=(",", ":"))),
            (
                "input_lifecycle_bindings_json",
                json.dumps(lifecycle_bindings, separators=(",", ":")),
            ),
        ]
        if allowed_amount is not None and secured_portion is not None:
            payload.extend(
                [
                    ("allowed_claim_amount", str(allowed_amount)),
                    ("secured_portion_506a", str(secured_portion)),
                    (
                        "unsecured_deficiency_506a",
                        str(allowed_amount - secured_portion),
                    ),
                ]
            )

        event = CanonicalEvent(
            event_id=f"lien-consequence:{request.request_id}:{req_hash}",
            event_type="LIEN_CONSEQUENCE_EVENT",
            event_effective_at=max(
                event.event_effective_at for event in input_events
            ),
            event_recorded_at=request.compiled_at,
            authority=request.rule_authority,
            payload=tuple(payload),
            authority_state=request.result_authority_state,
        )

        before = self.store.health()["event_count"]
        self.store.append_event(event)
        after = self.store.health()["event_count"]

        return Section506DCompileResult(
            event=event,
            persisted_event_id=event.event_id,
            consequence_code=consequence_code,
            input_event_ids=input_ids,
            input_event_hashes=input_hashes,
            replay_idempotent=(before == after),
        )
