"""§506(b) oversecurity and component-ceiling compiler candidate c6.

Inputs are already-governed legal determinations. The compiler calculates:
- net collateral after allowed §506(c) recoveries;
- non-circular §506(b) cushion using the pre-§506(b) allowed claim base;
- secured portions of already-eligible §506(b) components.

It never decides component entitlement from raw assertions. When the cushion is
insufficient but positive, it refuses to invent a priority among interest,
fees, costs, and charges: an authority-backed substantive allocation directive
is required.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from typing import Tuple

from .secured_claims import (
    AllocationRuleType,
    AuthorityReference,
    CanonicalEvent,
    ClaimComponent,
    ComponentType,
    EventAuthorityState,
    UnresolvedLegalState,
    allocate_506b_components,
    section_506b_cushion,
)
from .secured_claim_store import SecuredClaimStore
from .secured_status_compiler import BoundDetermination


COMPILER_VERSION = "section-506b-v1"
INPUT_STATES = {EventAuthorityState.OPERATIVE, EventAuthorityState.FINAL}
NONINTEREST_ENTITLEMENT_SOURCES = {"AGREEMENT", "STATE_STATUTE"}
ALLOCATION_SEMANTICS = {"SUBSTANTIVE_PRIORITY"}


@dataclass(frozen=True, slots=True)
class CushionAllocationDirective:
    rule_type: AllocationRuleType
    allocation_sequence: Tuple[str, ...]
    allocation_semantics: str
    legal_authority: AuthorityReference

    def validate(self) -> None:
        if self.allocation_semantics not in ALLOCATION_SEMANTICS:
            raise UnresolvedLegalState(
                "cushion allocation must establish SUBSTANTIVE_PRIORITY"
            )
        if not self.allocation_sequence:
            raise UnresolvedLegalState("allocation_sequence is required")
        if len(set(self.allocation_sequence)) != len(self.allocation_sequence):
            raise UnresolvedLegalState(
                "allocation_sequence component ids must be unique"
            )
        if self.legal_authority is None:
            raise UnresolvedLegalState(
                "allocation legal authority is required"
            )
        for name, value in (
            ("allocation authority id", self.legal_authority.authority_id),
            ("allocation authority type", self.legal_authority.authority_type),
            ("allocation authority citation", self.legal_authority.citation),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if self.legal_authority.authority_type == "HUMAN_PROMOTION":
            raise UnresolvedLegalState(
                "human promotion cannot establish §506(b) allocation priority"
            )


@dataclass(frozen=True, slots=True)
class Section506BCompileRequest:
    request_id: str
    compiled_at: datetime
    secured_status: BoundDetermination
    valuation: BoundDetermination
    recoveries_506c: Tuple[BoundDetermination, ...]
    components: Tuple[BoundDetermination, ...]
    section_506b_authority: AuthorityReference
    allocation_directive: CushionAllocationDirective | None = None
    result_authority_state: EventAuthorityState = EventAuthorityState.OPERATIVE

    def validate(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise UnresolvedLegalState("request_id is required")
        if self.compiled_at.tzinfo is None:
            raise UnresolvedLegalState("compiled_at must include timezone")
        self.secured_status.validate()
        self.valuation.validate()
        for bound in self.recoveries_506c:
            bound.validate()
        for bound in self.components:
            bound.validate()
        if not self.components:
            raise UnresolvedLegalState(
                "at least one §506(b) component determination is required"
            )
        ids = [
            self.secured_status.event_id,
            self.valuation.event_id,
            *(x.event_id for x in self.recoveries_506c),
            *(x.event_id for x in self.components),
        ]
        if len(ids) != len(set(ids)):
            raise UnresolvedLegalState("all bound input event ids must be unique")
        if self.section_506b_authority is None:
            raise UnresolvedLegalState("§506(b) authority is required")
        for name, value in (
            ("§506(b) authority id", self.section_506b_authority.authority_id),
            ("§506(b) authority type", self.section_506b_authority.authority_type),
            ("§506(b) authority citation", self.section_506b_authority.citation),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if self.section_506b_authority.authority_type == "HUMAN_PROMOTION":
            raise UnresolvedLegalState(
                "human promotion cannot substitute for §506(b) legal authority"
            )
        if self.allocation_directive is not None:
            self.allocation_directive.validate()
        if self.result_authority_state not in {
            EventAuthorityState.OPERATIVE,
            EventAuthorityState.FINAL,
        }:
            raise UnresolvedLegalState(
                "§506(b) result must be OPERATIVE or FINAL"
            )


@dataclass(frozen=True, slots=True)
class Section506BCompileResult:
    oversecurity_event: CanonicalEvent
    allocation_event: CanonicalEvent | None
    accrual_event: CanonicalEvent
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


def _valid_sha256(value: str) -> bool:
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


def _validate_c5_secured_status(event: CanonicalEvent) -> None:
    payload = _payload(event)
    if event.event_type != "SECURED_STATUS_EVENT":
        raise UnresolvedLegalState(
            "secured_status input must be SECURED_STATUS_EVENT"
        )
    if event.authority_state not in INPUT_STATES:
        raise UnresolvedLegalState(
            "secured_status input must be OPERATIVE or FINAL"
        )
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
    try:
        hashes = json.loads(hashes_raw)
    except json.JSONDecodeError as exc:
        raise UnresolvedLegalState(
            "secured_status input hashes are invalid JSON"
        ) from exc
    if not isinstance(hashes, list) or len(hashes) != 3 or not all(
        _valid_sha256(x) for x in hashes
    ):
        raise UnresolvedLegalState(
            "secured_status input lacks exact c5 input hashes"
        )


def _load_bound(
    store: SecuredClaimStore,
    bound: BoundDetermination,
    expected_type: str,
    *,
    require_c4: bool = True,
) -> CanonicalEvent:
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
    if event.authority_state not in INPUT_STATES:
        raise UnresolvedLegalState(
            f"{bound.event_id} must be OPERATIVE or FINAL"
        )
    if require_c4:
        _validate_c4_lineage(event)
    return event


def _request_hash(request: Section506BCompileRequest) -> str:
    doc = {
        "request_id": request.request_id,
        "compiled_at": request.compiled_at.isoformat(),
        "secured_status": request.secured_status.__dict__,
        "valuation": request.valuation.__dict__,
        "recoveries_506c": [x.__dict__ for x in request.recoveries_506c],
        "components": [x.__dict__ for x in request.components],
        "section_506b_authority": {
            "authority_id": request.section_506b_authority.authority_id,
            "authority_type": request.section_506b_authority.authority_type,
            "citation": request.section_506b_authority.citation,
            "jurisdiction": request.section_506b_authority.jurisdiction,
            "effective_date": (
                request.section_506b_authority.effective_date.isoformat()
                if request.section_506b_authority.effective_date else None
            ),
        },
        "allocation_directive": (
            None
            if request.allocation_directive is None
            else {
                "rule_type": request.allocation_directive.rule_type.value,
                "allocation_sequence": list(
                    request.allocation_directive.allocation_sequence
                ),
                "allocation_semantics": (
                    request.allocation_directive.allocation_semantics
                ),
                "authority": {
                    "authority_id": (
                        request.allocation_directive.legal_authority.authority_id
                    ),
                    "authority_type": (
                        request.allocation_directive.legal_authority.authority_type
                    ),
                    "citation": (
                        request.allocation_directive.legal_authority.citation
                    ),
                },
            }
        ),
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


class Section506BCompiler:
    """Compile §506(b) cushion and component secured amounts."""

    def __init__(self, *, store: SecuredClaimStore) -> None:
        self.store = store

    def compile(
        self,
        request: Section506BCompileRequest,
    ) -> Section506BCompileResult:
        request.validate()

        secured_status = _load_bound(
            self.store,
            request.secured_status,
            "SECURED_STATUS_EVENT",
            require_c4=False,
        )
        _validate_c5_secured_status(secured_status)

        valuation = _load_bound(
            self.store, request.valuation, "VALUATION_EVENT"
        )
        recoveries = tuple(
            _load_bound(
                self.store, bound, "SECTION_506C_RECOVERY_EVENT"
            )
            for bound in request.recoveries_506c
        )
        component_events = tuple(
            _load_bound(
                self.store, bound, "SECTION_506B_COMPONENT_EVENT"
            )
            for bound in request.components
        )

        status_payload = _payload(secured_status)
        valuation_payload = _payload(valuation)

        claim_id = _required(status_payload, "claim_id", secured_status)
        package_id = _required(
            status_payload, "collateral_package_id", secured_status
        )
        pre_506b_claim_base = _money(
            status_payload, "allowed_claim_amount", secured_status
        )

        if _required(valuation_payload, "claim_id", valuation) != claim_id:
            raise UnresolvedLegalState(
                "§506(b) valuation claim_id must match secured status"
            )
        if _required(
            valuation_payload, "collateral_package_id", valuation
        ) != package_id:
            raise UnresolvedLegalState(
                "§506(b) valuation collateral package must match secured status"
            )
        valuation_context_id = _required(
            valuation_payload, "valuation_context_id", valuation
        )
        valuation_purpose = _required(
            valuation_payload, "valuation_purpose", valuation
        )
        if valuation_purpose != "SECTION_506B":
            raise UnresolvedLegalState(
                "valuation purpose must be SECTION_506B"
            )
        collateral_value = _money(
            valuation_payload, "collateral_value_for_506b", valuation
        )

        total_506c = Decimal("0")
        for recovery in recoveries:
            payload = _payload(recovery)
            if _required(payload, "claim_id", recovery) != claim_id:
                raise UnresolvedLegalState(
                    "§506(c) recovery claim_id must match"
                )
            if _required(
                payload, "collateral_package_id", recovery
            ) != package_id:
                raise UnresolvedLegalState(
                    "§506(c) recovery collateral package must match"
                )
            if _required(payload, "recovery_state", recovery) != "ALLOWED":
                raise UnresolvedLegalState(
                    "§506(c) recovery must be legally ALLOWED"
                )
            total_506c += _money(
                payload, "allowed_recovery_amount", recovery
            )
        if total_506c > collateral_value:
            raise UnresolvedLegalState(
                "aggregate §506(c) recovery cannot exceed §506(b) collateral value"
            )

        net_collateral = collateral_value - total_506c
        cushion = section_506b_cushion(
            net_collateral_for_506b=net_collateral,
            pre_506b_claim_base=pre_506b_claim_base,
        )

        components: list[ClaimComponent] = []
        component_payloads: dict[str, dict[str, str]] = {}
        for event in component_events:
            payload = _payload(event)
            if _required(payload, "claim_id", event) != claim_id:
                raise UnresolvedLegalState(
                    "§506(b) component claim_id must match"
                )
            component_id = _required(payload, "component_id", event)
            if component_id in component_payloads:
                raise UnresolvedLegalState(
                    "duplicate §506(b) component_id"
                )
            raw_type = _required(payload, "component_type", event)
            try:
                component_type = ComponentType(raw_type)
            except ValueError as exc:
                raise UnresolvedLegalState(
                    f"unsupported §506(b) component_type: {raw_type}"
                ) from exc
            if _required(payload, "eligibility_state", event) != "ELIGIBLE":
                raise UnresolvedLegalState(
                    "§506(b) component must be legally ELIGIBLE"
                )
            eligible_amount = _money(payload, "eligible_amount", event)
            _required(payload, "accrual_start", event)
            _required(payload, "accrual_end", event)
            if component_type is ComponentType.INTEREST:
                _required(payload, "rate_source", event)
            else:
                entitlement_source = _required(
                    payload, "entitlement_source", event
                )
                if entitlement_source not in NONINTEREST_ENTITLEMENT_SOURCES:
                    raise UnresolvedLegalState(
                        "fee/cost/charge entitlement_source must be "
                        "AGREEMENT or STATE_STATUTE"
                    )
                if _required(
                    payload, "reasonableness_state", event
                ) != "REASONABLE":
                    raise UnresolvedLegalState(
                        "fee/cost/charge must be legally REASONABLE"
                    )
            components.append(
                ClaimComponent(
                    component_id=component_id,
                    component_type=component_type,
                    eligible_amount=eligible_amount,
                )
            )
            component_payloads[component_id] = payload

        total_eligible = sum(
            (component.eligible_amount for component in components),
            Decimal("0"),
        )

        allocation_event = None
        if cushion == 0:
            allocations = tuple(
                (
                    component.component_id,
                    component.component_type,
                    component.eligible_amount,
                    Decimal("0"),
                )
                for component in components
            )
        elif total_eligible <= cushion:
            allocated = allocate_506b_components(
                components=tuple(components),
                cushion=cushion,
            )
            allocations = tuple(
                (
                    x.component_id,
                    x.component_type,
                    x.eligible_amount,
                    x.secured_amount,
                )
                for x in allocated
            )
        else:
            directive = request.allocation_directive
            if directive is None:
                raise UnresolvedLegalState(
                    "positive insufficient cushion requires authority-backed "
                    "substantive allocation rule"
                )
            expected_ids = {x.component_id for x in components}
            if (
                set(directive.allocation_sequence) != expected_ids
                or len(directive.allocation_sequence) != len(expected_ids)
            ):
                raise UnresolvedLegalState(
                    "allocation_sequence must contain every component exactly once"
                )
            allocated = allocate_506b_components(
                components=tuple(components),
                cushion=cushion,
                rule_type=directive.rule_type,
                allocation_sequence=directive.allocation_sequence,
            )
            allocations = tuple(
                (
                    x.component_id,
                    x.component_type,
                    x.eligible_amount,
                    x.secured_amount,
                )
                for x in allocated
            )

        if (
            request.result_authority_state is EventAuthorityState.FINAL
            and not all(
                event.authority_state is EventAuthorityState.FINAL
                for event in (
                    secured_status,
                    valuation,
                    *recoveries,
                    *component_events,
                )
            )
        ):
            raise UnresolvedLegalState(
                "FINAL §506(b) result requires all bound inputs FINAL"
            )

        input_events = (
            secured_status,
            valuation,
            *recoveries,
            *component_events,
        )
        input_ids = tuple(event.event_id for event in input_events)
        input_hashes = tuple(event.sha256 for event in input_events)
        req_hash = _request_hash(request)

        oversecurity_event = CanonicalEvent(
            event_id=f"oversecurity:{request.request_id}:{req_hash}",
            event_type="OVERSECURITY_DETERMINATION",
            event_effective_at=valuation.event_effective_at,
            event_recorded_at=request.compiled_at,
            authority=request.section_506b_authority,
            payload=(
                ("compiler_version", COMPILER_VERSION),
                ("compile_request_sha256", req_hash),
                ("claim_id", claim_id),
                ("collateral_package_id", package_id),
                ("valuation_context_id", valuation_context_id),
                ("collateral_value_for_506b", str(collateral_value)),
                ("section_506c_recovery_total", str(total_506c)),
                ("net_collateral_base", str(net_collateral)),
                ("pre_506b_claim_base", str(pre_506b_claim_base)),
                ("available_506b_cushion", str(cushion)),
                ("oversecured_state", "OVERSECURED" if cushion > 0 else "NOT_OVERSECURED"),
                ("input_event_ids_json", json.dumps(input_ids, separators=(",", ":"))),
                ("input_event_hashes_json", json.dumps(input_hashes, separators=(",", ":"))),
            ),
            authority_state=request.result_authority_state,
        )

        if total_eligible > cushion and cushion > 0:
            directive = request.allocation_directive
            assert directive is not None
            allocation_event = CanonicalEvent(
                event_id=f"cushion-allocation:{request.request_id}:{req_hash}",
                event_type="CUSHION_ALLOCATION_EVENT",
                event_effective_at=valuation.event_effective_at,
                event_recorded_at=request.compiled_at,
                authority=directive.legal_authority,
                payload=(
                    ("compiler_version", COMPILER_VERSION),
                    ("compile_request_sha256", req_hash),
                    ("claim_id", claim_id),
                    ("available_before", str(cushion)),
                    ("rule_type", directive.rule_type.value),
                    ("allocation_semantics", directive.allocation_semantics),
                    ("allocation_sequence_json", json.dumps(
                        directive.allocation_sequence, separators=(",", ":")
                    )),
                    ("allocations_json", json.dumps(
                        [
                            {
                                "component_id": cid,
                                "component_type": ctype.value,
                                "eligible_amount": str(eligible),
                                "secured_amount": str(secured),
                            }
                            for cid, ctype, eligible, secured in allocations
                        ],
                        separators=(",", ":"),
                    )),
                ),
                authority_state=request.result_authority_state,
            )

        total_secured = sum(
            (secured for _, _, _, secured in allocations),
            Decimal("0"),
        )
        if total_secured > cushion:
            raise UnresolvedLegalState(
                "total §506(b) secured allowance cannot exceed cushion"
            )

        accrual_event = CanonicalEvent(
            event_id=f"section-506b-accrual:{request.request_id}:{req_hash}",
            event_type="SECTION_506B_ACCRUAL_EVENT",
            event_effective_at=valuation.event_effective_at,
            event_recorded_at=request.compiled_at,
            authority=request.section_506b_authority,
            payload=(
                ("compiler_version", COMPILER_VERSION),
                ("compile_request_sha256", req_hash),
                ("claim_id", claim_id),
                ("collateral_package_id", package_id),
                ("valuation_context_id", valuation_context_id),
                ("available_506b_cushion", str(cushion)),
                ("total_eligible_components", str(total_eligible)),
                ("total_506b_secured_allowance", str(total_secured)),
                ("cushion_remaining", str(cushion - total_secured)),
                ("allocations_json", json.dumps(
                    [
                        {
                            "component_id": cid,
                            "component_type": ctype.value,
                            "eligible_amount": str(eligible),
                            "secured_amount": str(secured),
                        }
                        for cid, ctype, eligible, secured in allocations
                    ],
                    separators=(",", ":"),
                )),
                ("oversecurity_event_id", oversecurity_event.event_id),
                ("allocation_event_id", allocation_event.event_id if allocation_event else ""),
                ("input_event_ids_json", json.dumps(input_ids, separators=(",", ":"))),
                ("input_event_hashes_json", json.dumps(input_hashes, separators=(",", ":"))),
            ),
            authority_state=request.result_authority_state,
        )

        before = self.store.health()["event_count"]
        self.store.append_event(oversecurity_event)
        if allocation_event is not None:
            self.store.append_event(allocation_event)
        self.store.append_event(accrual_event)
        after = self.store.health()["event_count"]
        created_count = 2 + (1 if allocation_event is not None else 0)

        return Section506BCompileResult(
            oversecurity_event=oversecurity_event,
            allocation_event=allocation_event,
            accrual_event=accrual_event,
            input_event_ids=input_ids,
            input_event_hashes=input_hashes,
            replay_idempotent=(after - before == 0),
        )
