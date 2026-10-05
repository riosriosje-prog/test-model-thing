"""GALIA 2.0 secured-claim kernel implementation candidate c1.

This module implements a deliberately small, in-memory vertical slice of the
promoted architecture baseline:
GALIA-SECURED-CLAIM-KERNEL-ARCH-CANDIDATE-v1.0-rc1.

Boundaries:
- canonical events are immutable;
- derived snapshots are reproducible and carry source-event lineage;
- valuation is context-sensitive;
- §506(b) uses a non-circular cushion ceiling;
- lien waterfalls fail closed when priority/allocation is unresolved;
- no persistence, promotion, or legacy/model-runtime mutation is provided.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
import hashlib
import json
from typing import Iterable, Mapping, Sequence, Tuple


Money = Decimal


class UnresolvedLegalState(ValueError):
    """A material legal input is missing or disputed; calculation must stop."""


class DuplicateEventConflict(ValueError):
    """The same canonical event id was reused for different content."""


class EventAuthorityState(str, Enum):
    OPERATIVE = "OPERATIVE"
    SUPERSEDED = "SUPERSEDED"
    VACATED = "VACATED"
    REVERSED = "REVERSED"
    STAYED = "STAYED"
    APPEAL_PENDING = "APPEAL_PENDING"
    FINAL = "FINAL"
    NONFINAL = "NONFINAL"


class PriorityState(str, Enum):
    SENIOR = "SENIOR"
    PARI_PASSU = "PARI_PASSU"
    JUNIOR = "JUNIOR"
    PRIMED = "PRIMED"
    SUBORDINATED = "SUBORDINATED"
    DISPUTED = "DISPUTED"
    UNDETERMINED = "UNDETERMINED"


class ComponentType(str, Enum):
    INTEREST = "INTEREST"
    FEE = "FEE"
    COST = "COST"
    CHARGE = "CHARGE"


class AllocationRuleType(str, Enum):
    COURT_ORDERED = "COURT_ORDERED"
    CONTRACTUAL = "CONTRACTUAL"
    STIPULATED = "STIPULATED"
    PLAN_DEFINED = "PLAN_DEFINED"
    STATUTORY = "STATUTORY"
    JURISDICTIONAL_PRECEDENT = "JURISDICTIONAL_PRECEDENT"
    CASE_SPECIFIC_EQUITABLE = "CASE_SPECIFIC_EQUITABLE"


@dataclass(frozen=True, slots=True)
class AuthorityReference:
    authority_id: str
    authority_type: str
    citation: str
    jurisdiction: str | None = None
    effective_date: datetime | None = None


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    event_id: str
    event_type: str
    event_effective_at: datetime
    event_recorded_at: datetime
    authority: AuthorityReference
    payload: Tuple[Tuple[str, str], ...] = ()
    supersedes_event_id: str | None = None
    authority_state: EventAuthorityState = EventAuthorityState.OPERATIVE

    def canonical_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_effective_at": self.event_effective_at.isoformat(),
            "event_recorded_at": self.event_recorded_at.isoformat(),
            "authority": {
                "authority_id": self.authority.authority_id,
                "authority_type": self.authority.authority_type,
                "citation": self.authority.citation,
                "jurisdiction": self.authority.jurisdiction,
                "effective_date": (
                    self.authority.effective_date.isoformat()
                    if self.authority.effective_date else None
                ),
            },
            "payload": list(self.payload),
            "supersedes_event_id": self.supersedes_event_id,
            "authority_state": self.authority_state.value,
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


class CanonicalEventStore:
    """Append-only, deterministic event store for candidate validation."""

    def __init__(self) -> None:
        self._events: dict[str, CanonicalEvent] = {}
        self._order: list[str] = []

    def append(self, event: CanonicalEvent) -> None:
        _require_text("event_id", event.event_id)
        _require_text("event_type", event.event_type)
        if event.authority is None:
            raise UnresolvedLegalState("authority is required")
        existing = self._events.get(event.event_id)
        if existing is not None:
            if existing.sha256 == event.sha256:
                return
            raise DuplicateEventConflict(
                f"event_id {event.event_id!r} already exists with different content"
            )
        if event.supersedes_event_id and event.supersedes_event_id not in self._events:
            raise UnresolvedLegalState("superseded event must already exist")
        self._events[event.event_id] = event
        self._order.append(event.event_id)

    def get(self, event_id: str) -> CanonicalEvent:
        return self._events[event_id]

    def events(self) -> tuple[CanonicalEvent, ...]:
        return tuple(self._events[eid] for eid in self._order)


@dataclass(frozen=True, slots=True)
class ValuationContext:
    statutory_basis: str
    chapter: int
    valuation_purpose: str
    legal_effective_date: datetime
    determination_date: datetime
    evidence_observation_date: datetime
    proposed_disposition: str
    proposed_use: str
    collateral_scope: str
    creditor_interest_scope: str
    priority_snapshot_id: str
    valuation_standard: str

    def validate(self) -> None:
        for name in (
            "statutory_basis",
            "valuation_purpose",
            "proposed_disposition",
            "proposed_use",
            "collateral_scope",
            "creditor_interest_scope",
            "priority_snapshot_id",
            "valuation_standard",
        ):
            _require_text(name, getattr(self, name))
        if self.chapter <= 0:
            raise UnresolvedLegalState("chapter is required")


@dataclass(frozen=True, slots=True)
class ValuationEvent:
    event_id: str
    collateral_id: str
    creditor_id: str
    context: ValuationContext
    property_gross_value: Money
    estate_interest_value: Money
    creditor_interest_value: Money
    authority: AuthorityReference

    def validate(self) -> None:
        _require_text("event_id", self.event_id)
        _require_text("collateral_id", self.collateral_id)
        _require_text("creditor_id", self.creditor_id)
        self.context.validate()
        for name in (
            "property_gross_value",
            "estate_interest_value",
            "creditor_interest_value",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.estate_interest_value > self.property_gross_value:
            raise ValueError("estate interest cannot exceed gross property value")
        if self.creditor_interest_value > self.estate_interest_value:
            raise ValueError("creditor interest cannot exceed estate interest")


@dataclass(frozen=True, slots=True)
class SecuredClassification:
    allowed_claim_amount: Money
    creditor_interest_value: Money
    secured_portion: Money
    unsecured_deficiency: Money


@dataclass(frozen=True, slots=True)
class ClaimComponent:
    component_id: str
    component_type: ComponentType
    eligible_amount: Money

    def validate(self) -> None:
        _require_text("component_id", self.component_id)
        if self.eligible_amount < 0:
            raise ValueError("eligible_amount must be non-negative")


@dataclass(frozen=True, slots=True)
class CushionAllocation:
    component_id: str
    component_type: ComponentType
    eligible_amount: Money
    secured_amount: Money


@dataclass(frozen=True, slots=True)
class LienPosition:
    lien_id: str
    claim_id: str
    allowed_claim_amount: Money
    tier: int
    priority_state: PriorityState
    pari_passu_rule: str | None = None

    def validate(self) -> None:
        _require_text("lien_id", self.lien_id)
        _require_text("claim_id", self.claim_id)
        if self.allowed_claim_amount < 0:
            raise ValueError("allowed_claim_amount must be non-negative")
        if self.tier < 0:
            raise ValueError("tier must be non-negative")
        if self.priority_state in {PriorityState.DISPUTED, PriorityState.UNDETERMINED}:
            raise UnresolvedLegalState(
                f"priority for lien {self.lien_id} is {self.priority_state.value}"
            )


@dataclass(frozen=True, slots=True)
class LienDistribution:
    lien_id: str
    claim_id: str
    secured_amount: Money
    unsecured_deficiency: Money


@dataclass(frozen=True, slots=True)
class DerivedSnapshot:
    snapshot_type: str
    as_of: datetime
    purpose: str
    source_event_ids: Tuple[str, ...]
    calculation_version: str
    values: Tuple[Tuple[str, str], ...]

    def validate(self) -> None:
        _require_text("snapshot_type", self.snapshot_type)
        _require_text("purpose", self.purpose)
        _require_text("calculation_version", self.calculation_version)
        if not self.source_event_ids:
            raise UnresolvedLegalState("derived snapshot requires source event lineage")


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UnresolvedLegalState(f"{name} is required")
    return value


def money(value: str | int | Decimal) -> Money:
    return Decimal(value)


def valuation_context_equivalent(a: ValuationContext, b: ValuationContext) -> bool:
    a.validate()
    b.validate()
    keys = (
        "statutory_basis",
        "chapter",
        "valuation_purpose",
        "legal_effective_date",
        "proposed_disposition",
        "proposed_use",
        "collateral_scope",
        "creditor_interest_scope",
        "priority_snapshot_id",
        "valuation_standard",
    )
    return all(getattr(a, key) == getattr(b, key) for key in keys)


def classify_secured_claim(
    *, allowed_claim_amount: Money, creditor_interest_value: Money
) -> SecuredClassification:
    if allowed_claim_amount < 0 or creditor_interest_value < 0:
        raise ValueError("claim and collateral values must be non-negative")
    secured = min(allowed_claim_amount, creditor_interest_value)
    return SecuredClassification(
        allowed_claim_amount=allowed_claim_amount,
        creditor_interest_value=creditor_interest_value,
        secured_portion=secured,
        unsecured_deficiency=allowed_claim_amount - secured,
    )


def section_506b_cushion(
    *, net_collateral_for_506b: Money, pre_506b_claim_base: Money
) -> Money:
    if net_collateral_for_506b < 0 or pre_506b_claim_base < 0:
        raise ValueError("values must be non-negative")
    return max(Money("0"), net_collateral_for_506b - pre_506b_claim_base)


def allocate_506b_components(
    *,
    components: Sequence[ClaimComponent],
    cushion: Money,
    rule_type: AllocationRuleType | None = None,
    allocation_sequence: Sequence[str] | None = None,
) -> tuple[CushionAllocation, ...]:
    if cushion < 0:
        raise ValueError("cushion must be non-negative")
    seen: set[str] = set()
    by_id: dict[str, ClaimComponent] = {}
    for component in components:
        component.validate()
        if component.component_id in seen:
            raise ValueError("duplicate component_id")
        seen.add(component.component_id)
        by_id[component.component_id] = component

    total = sum((c.eligible_amount for c in components), Money("0"))
    if total <= cushion:
        return tuple(
            CushionAllocation(
                c.component_id, c.component_type, c.eligible_amount, c.eligible_amount
            )
            for c in components
        )

    if rule_type is None or allocation_sequence is None:
        raise UnresolvedLegalState(
            "insufficient cushion requires an authority-backed allocation rule"
        )
    if set(allocation_sequence) != set(by_id) or len(allocation_sequence) != len(by_id):
        raise ValueError("allocation_sequence must contain every component exactly once")

    remaining = cushion
    allocated: dict[str, Money] = {}
    for component_id in allocation_sequence:
        c = by_id[component_id]
        amount = min(c.eligible_amount, remaining)
        allocated[component_id] = amount
        remaining -= amount

    return tuple(
        CushionAllocation(
            c.component_id,
            c.component_type,
            c.eligible_amount,
            allocated[c.component_id],
        )
        for c in components
    )


def lien_waterfall(
    *, estate_interest_value: Money, liens: Sequence[LienPosition]
) -> tuple[LienDistribution, ...]:
    if estate_interest_value < 0:
        raise ValueError("estate_interest_value must be non-negative")
    for lien in liens:
        lien.validate()

    by_tier: dict[int, list[LienPosition]] = {}
    for lien in liens:
        by_tier.setdefault(lien.tier, []).append(lien)

    remaining = estate_interest_value
    secured_by_id: dict[str, Money] = {}

    for tier in sorted(by_tier):
        group = by_tier[tier]
        tier_claim = sum((l.allowed_claim_amount for l in group), Money("0"))
        if tier_claim <= remaining:
            for lien in group:
                secured_by_id[lien.lien_id] = lien.allowed_claim_amount
            remaining -= tier_claim
            continue

        if len(group) == 1:
            lien = group[0]
            secured_by_id[lien.lien_id] = remaining
            remaining = Money("0")
            continue

        rules = {l.pari_passu_rule for l in group}
        if None in rules or len(rules) != 1:
            raise UnresolvedLegalState(
                f"tier {tier} is insufficient and has no single pari-passu rule"
            )
        rule = next(iter(rules))
        if rule != "PRO_RATA_BY_ALLOWED_AMOUNT":
            raise UnresolvedLegalState(f"unsupported pari-passu rule: {rule}")

        if tier_claim == 0:
            for lien in group:
                secured_by_id[lien.lien_id] = Money("0")
        else:
            distributed = Money("0")
            for lien in group[:-1]:
                share = remaining * lien.allowed_claim_amount / tier_claim
                secured_by_id[lien.lien_id] = share
                distributed += share
            secured_by_id[group[-1].lien_id] = remaining - distributed
        remaining = Money("0")

    return tuple(
        LienDistribution(
            lien_id=l.lien_id,
            claim_id=l.claim_id,
            secured_amount=secured_by_id.get(l.lien_id, Money("0")),
            unsecured_deficiency=l.allowed_claim_amount
            - secured_by_id.get(l.lien_id, Money("0")),
        )
        for l in liens
    )


def make_snapshot(
    *,
    snapshot_type: str,
    as_of: datetime,
    purpose: str,
    source_events: Iterable[CanonicalEvent],
    calculation_version: str,
    values: Mapping[str, str | int | Decimal],
) -> DerivedSnapshot:
    events = tuple(source_events)
    snap = DerivedSnapshot(
        snapshot_type=snapshot_type,
        as_of=as_of,
        purpose=purpose,
        source_event_ids=tuple(e.event_id for e in events),
        calculation_version=calculation_version,
        values=tuple(sorted((k, str(v)) for k, v in values.items())),
    )
    snap.validate()
    return snap
