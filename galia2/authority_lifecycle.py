"""Authority lifecycle / vacatur / reversal kernel candidate c7.

Canonical legal events remain immutable. Legal effect changes are represented by
append-only AUTHORITY_STATE_TRANSITION_EVENT records that bind:

- the exact target event id and SHA-256;
- the exact prior lifecycle transition (if any);
- an explicit human GALIA authorization;
- a distinct legal authority supporting the change;
- the expected current state and requested next state.

CURRENT_STATE is reconstructed by replay. No target event row is updated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Tuple

from .secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    EventAuthorityState,
    UnresolvedLegalState,
)
from .secured_claim_store import SecuredClaimStore


TRANSITION_EVENT_TYPE = "AUTHORITY_STATE_TRANSITION_EVENT"

ACTIVE_STATES = {
    EventAuthorityState.OPERATIVE,
    EventAuthorityState.FINAL,
}

LIFECYCLE_INPUT_STATES = {
    EventAuthorityState.OPERATIVE,
    EventAuthorityState.APPEAL_PENDING,
    EventAuthorityState.STAYED,
    EventAuthorityState.FINAL,
    EventAuthorityState.SUPERSEDED,
}

TERMINAL_STATES = {
    EventAuthorityState.VACATED,
    EventAuthorityState.REVERSED,
}

ALLOWED_TRANSITIONS = {
    EventAuthorityState.OPERATIVE: {
        EventAuthorityState.APPEAL_PENDING,
        EventAuthorityState.STAYED,
        EventAuthorityState.FINAL,
        EventAuthorityState.SUPERSEDED,
        EventAuthorityState.VACATED,
        EventAuthorityState.REVERSED,
    },
    EventAuthorityState.APPEAL_PENDING: {
        EventAuthorityState.OPERATIVE,
        EventAuthorityState.STAYED,
        EventAuthorityState.FINAL,
        EventAuthorityState.SUPERSEDED,
        EventAuthorityState.VACATED,
        EventAuthorityState.REVERSED,
    },
    EventAuthorityState.STAYED: {
        EventAuthorityState.OPERATIVE,
        EventAuthorityState.APPEAL_PENDING,
        EventAuthorityState.FINAL,
        EventAuthorityState.SUPERSEDED,
        EventAuthorityState.VACATED,
        EventAuthorityState.REVERSED,
    },
    EventAuthorityState.FINAL: {
        EventAuthorityState.APPEAL_PENDING,
        EventAuthorityState.STAYED,
        EventAuthorityState.SUPERSEDED,
        EventAuthorityState.VACATED,
        EventAuthorityState.REVERSED,
    },
    EventAuthorityState.SUPERSEDED: {
        EventAuthorityState.VACATED,
        EventAuthorityState.REVERSED,
    },
}


class LifecycleDecision(str, Enum):
    AUTHORIZE_STATE_TRANSITION = "AUTHORIZE_STATE_TRANSITION"


@dataclass(frozen=True, slots=True)
class BoundEvent:
    event_id: str
    expected_sha256: str

    def validate(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise UnresolvedLegalState("bound event_id is required")
        if not isinstance(self.expected_sha256, str) or len(self.expected_sha256) != 64:
            raise UnresolvedLegalState(
                "bound expected_sha256 must be 64 hex characters"
            )
        try:
            int(self.expected_sha256, 16)
        except ValueError as exc:
            raise UnresolvedLegalState(
                "bound expected_sha256 must be hexadecimal"
            ) from exc


@dataclass(frozen=True, slots=True)
class EffectiveAuthorityState:
    target_event_id: str
    target_event_sha256: str
    initial_state: EventAuthorityState
    effective_state: EventAuthorityState
    transition_event_ids: Tuple[str, ...]
    transition_event_hashes: Tuple[str, ...]
    tail_transition_event_id: str | None
    tail_transition_sha256: str | None

    @property
    def is_active(self) -> bool:
        return self.effective_state in ACTIVE_STATES


@dataclass(frozen=True, slots=True)
class HumanLifecycleAuthorization:
    authorization_id: str
    decision: LifecycleDecision
    reviewer: str
    rationale: str
    issued_at: datetime
    transition_effective_at: datetime
    target: BoundEvent
    expected_current_state: EventAuthorityState
    to_state: EventAuthorityState
    legal_authority: AuthorityReference
    prior_transition: BoundEvent | None = None
    replacement_event: BoundEvent | None = None

    def validate(self) -> None:
        for name, value in (
            ("authorization_id", self.authorization_id),
            ("reviewer", self.reviewer),
            ("rationale", self.rationale),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if self.decision is not LifecycleDecision.AUTHORIZE_STATE_TRANSITION:
            raise UnresolvedLegalState(
                "human decision must be AUTHORIZE_STATE_TRANSITION"
            )
        if self.issued_at.tzinfo is None:
            raise UnresolvedLegalState("issued_at must include timezone")
        if self.transition_effective_at.tzinfo is None:
            raise UnresolvedLegalState(
                "transition_effective_at must include timezone"
            )
        self.target.validate()
        if self.prior_transition is not None:
            self.prior_transition.validate()
        if self.replacement_event is not None:
            self.replacement_event.validate()

        if self.expected_current_state in TERMINAL_STATES:
            raise UnresolvedLegalState(
                "VACATED and REVERSED are terminal lifecycle states"
            )
        if self.expected_current_state is EventAuthorityState.NONFINAL:
            raise UnresolvedLegalState(
                "NONFINAL assertion/source events are not lifecycle targets"
            )
        if self.expected_current_state not in LIFECYCLE_INPUT_STATES:
            raise UnresolvedLegalState(
                "expected_current_state is not lifecycle-eligible"
            )
        allowed = ALLOWED_TRANSITIONS.get(self.expected_current_state, set())
        if self.to_state not in allowed:
            raise UnresolvedLegalState(
                f"transition {self.expected_current_state.value} -> "
                f"{self.to_state.value} is not allowed"
            )
        if self.to_state is self.expected_current_state:
            raise UnresolvedLegalState("no-op lifecycle transition is forbidden")

        if self.legal_authority is None:
            raise UnresolvedLegalState(
                "distinct legal authority is required for lifecycle transition"
            )
        for name, value in (
            ("legal authority id", self.legal_authority.authority_id),
            ("legal authority type", self.legal_authority.authority_type),
            ("legal authority citation", self.legal_authority.citation),
        ):
            if not isinstance(value, str) or not value.strip():
                raise UnresolvedLegalState(f"{name} is required")
        if self.legal_authority.authority_type == "HUMAN_PROMOTION":
            raise UnresolvedLegalState(
                "human promotion cannot substitute for lifecycle legal authority"
            )

        if self.to_state is EventAuthorityState.SUPERSEDED:
            if self.replacement_event is None:
                raise UnresolvedLegalState(
                    "SUPERSEDED transition requires exact replacement_event"
                )
        elif self.replacement_event is not None:
            raise UnresolvedLegalState(
                "replacement_event is permitted only for SUPERSEDED transition"
            )

    def canonical_dict(self) -> dict[str, object]:
        def bound(value: BoundEvent | None) -> dict[str, str] | None:
            if value is None:
                return None
            return {
                "event_id": value.event_id,
                "expected_sha256": value.expected_sha256,
            }

        return {
            "authorization_id": self.authorization_id,
            "decision": self.decision.value,
            "reviewer": self.reviewer,
            "rationale": self.rationale,
            "issued_at": self.issued_at.isoformat(),
            "transition_effective_at": self.transition_effective_at.isoformat(),
            "target": bound(self.target),
            "expected_current_state": self.expected_current_state.value,
            "to_state": self.to_state.value,
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
            "prior_transition": bound(self.prior_transition),
            "replacement_event": bound(self.replacement_event),
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
class LifecycleTransitionResult:
    authorization_sha256: str
    before_state: EventAuthorityState
    after_state: EventAuthorityState
    event: CanonicalEvent
    persisted_event_id: str
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


def _valid_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _load_exact(store: SecuredClaimStore, bound: BoundEvent) -> CanonicalEvent:
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
    return event


def _transition_rows_for_target(
    store: SecuredClaimStore,
    target: CanonicalEvent,
) -> tuple[CanonicalEvent, ...]:
    rows: list[CanonicalEvent] = []
    for event in store.list_events():
        if event.event_type != TRANSITION_EVENT_TYPE:
            continue
        payload = _payload(event)
        if payload.get("target_event_id") != target.event_id:
            continue
        if payload.get("target_event_sha256") != target.sha256:
            raise UnresolvedLegalState(
                f"lifecycle transition for {target.event_id} binds wrong target hash"
            )
        rows.append(event)
    return tuple(rows)


def resolve_effective_authority_state(
    store: SecuredClaimStore,
    target_event_id: str,
) -> EffectiveAuthorityState:
    try:
        target = store.get_event(target_event_id)
    except KeyError as exc:
        raise UnresolvedLegalState(
            f"target event does not exist: {target_event_id}"
        ) from exc

    if target.event_type == TRANSITION_EVENT_TYPE:
        raise UnresolvedLegalState(
            "lifecycle transition events cannot themselves be lifecycle targets"
        )

    transitions = _transition_rows_for_target(store, target)
    if not transitions:
        return EffectiveAuthorityState(
            target_event_id=target.event_id,
            target_event_sha256=target.sha256,
            initial_state=target.authority_state,
            effective_state=target.authority_state,
            transition_event_ids=(),
            transition_event_hashes=(),
            tail_transition_event_id=None,
            tail_transition_sha256=None,
        )

    by_prior: dict[str, list[CanonicalEvent]] = {}
    for event in transitions:
        payload = _payload(event)
        prior_id = payload.get("prior_transition_event_id", "")
        by_prior.setdefault(prior_id, []).append(event)

    roots = by_prior.get("", [])
    if len(roots) != 1:
        raise UnresolvedLegalState(
            f"lifecycle chain for {target.event_id} must have exactly one root"
        )

    current_state = target.authority_state
    current = roots[0]
    ordered: list[CanonicalEvent] = []
    seen: set[str] = set()

    while True:
        if current.event_id in seen:
            raise UnresolvedLegalState("lifecycle transition cycle detected")
        seen.add(current.event_id)
        payload = _payload(current)

        human_authorization_id = _required(
            payload, "human_authorization_id", current
        )
        human_authorization_sha256 = _required(
            payload, "human_authorization_sha256", current
        )
        human_reviewer = _required(
            payload, "human_reviewer", current
        )
        if (
            not human_authorization_id
            or not human_reviewer
            or not _valid_sha256(human_authorization_sha256)
        ):
            raise UnresolvedLegalState(
                f"lifecycle transition {current.event_id} lacks valid human authorization provenance"
            )
        if current.authority.authority_type == "HUMAN_PROMOTION":
            raise UnresolvedLegalState(
                f"lifecycle transition {current.event_id} uses human promotion as legal authority"
            )
        if current.authority_state not in ACTIVE_STATES:
            raise UnresolvedLegalState(
                f"lifecycle transition {current.event_id} is not itself operative/final"
            )

        from_state = EventAuthorityState(
            _required(payload, "from_state", current)
        )
        to_state = EventAuthorityState(
            _required(payload, "to_state", current)
        )
        if from_state is not current_state:
            raise UnresolvedLegalState(
                f"lifecycle chain state mismatch at {current.event_id}"
            )
        if to_state not in ALLOWED_TRANSITIONS.get(from_state, set()):
            raise UnresolvedLegalState(
                f"stored lifecycle transition {from_state.value} -> "
                f"{to_state.value} is not allowed"
            )

        replacement_event_id = payload.get("replacement_event_id", "")
        replacement_event_sha256 = payload.get("replacement_event_sha256", "")
        if to_state is EventAuthorityState.SUPERSEDED:
            if (
                not replacement_event_id
                or not _valid_sha256(replacement_event_sha256)
            ):
                raise UnresolvedLegalState(
                    f"stored SUPERSEDED transition {current.event_id} lacks replacement binding"
                )
            if replacement_event_id == target.event_id:
                raise UnresolvedLegalState(
                    "stored replacement_event must differ from target"
                )
            try:
                replacement_event = store.get_event(replacement_event_id)
            except KeyError as exc:
                raise UnresolvedLegalState(
                    f"stored replacement_event does not exist: {replacement_event_id}"
                ) from exc
            if replacement_event.sha256 != replacement_event_sha256:
                raise UnresolvedLegalState(
                    "stored replacement_event hash mismatch"
                )
            if replacement_event.event_type == TRANSITION_EVENT_TYPE:
                raise UnresolvedLegalState(
                    "stored replacement_event cannot be lifecycle transition"
                )
        elif replacement_event_id or replacement_event_sha256:
            raise UnresolvedLegalState(
                "stored replacement binding is permitted only for SUPERSEDED transition"
            )

        if ordered:
            previous = ordered[-1]
            prior_id = _required(
                payload, "prior_transition_event_id", current
            )
            prior_hash = _required(
                payload, "prior_transition_sha256", current
            )
            if prior_id != previous.event_id or prior_hash != previous.sha256:
                raise UnresolvedLegalState(
                    f"lifecycle predecessor binding mismatch at {current.event_id}"
                )
        else:
            if payload.get("prior_transition_event_id", "") != "":
                raise UnresolvedLegalState(
                    "root lifecycle transition must not name a predecessor"
                )
            if payload.get("prior_transition_sha256", "") != "":
                raise UnresolvedLegalState(
                    "root lifecycle transition must not bind predecessor hash"
                )

        ordered.append(current)
        current_state = to_state

        children = by_prior.get(current.event_id, [])
        if not children:
            break
        if len(children) != 1:
            raise UnresolvedLegalState(
                f"lifecycle chain forks after {current.event_id}"
            )
        current = children[0]

    if len(ordered) != len(transitions):
        raise UnresolvedLegalState(
            f"orphan lifecycle transitions exist for {target.event_id}"
        )

    tail = ordered[-1]
    return EffectiveAuthorityState(
        target_event_id=target.event_id,
        target_event_sha256=target.sha256,
        initial_state=target.authority_state,
        effective_state=current_state,
        transition_event_ids=tuple(x.event_id for x in ordered),
        transition_event_hashes=tuple(x.sha256 for x in ordered),
        tail_transition_event_id=tail.event_id,
        tail_transition_sha256=tail.sha256,
    )


def require_effectively_active(
    store: SecuredClaimStore,
    event: CanonicalEvent,
) -> EffectiveAuthorityState:
    state = resolve_effective_authority_state(store, event.event_id)
    if state.effective_state not in ACTIVE_STATES:
        raise UnresolvedLegalState(
            f"{event.event_id} is not effectively active: "
            f"{state.effective_state.value}"
        )
    return state


class AuthorityLifecycleGate:
    """Append one exact lifecycle transition without mutating its target."""

    def __init__(self, *, store: SecuredClaimStore) -> None:
        self.store = store

    def authorize(
        self,
        authorization: HumanLifecycleAuthorization,
    ) -> LifecycleTransitionResult:
        authorization.validate()

        target = _load_exact(self.store, authorization.target)
        auth_hash = authorization.sha256
        transition_event_id = (
            f"authority-transition:{authorization.authorization_id}:{auth_hash}"
        )
        try:
            existing = self.store.get_event(transition_event_id)
        except KeyError:
            existing = None
        if existing is not None:
            payload = _payload(existing)
            if (
                existing.event_type != TRANSITION_EVENT_TYPE
                or payload.get("human_authorization_sha256") != auth_hash
                or payload.get("target_event_id") != target.event_id
                or payload.get("target_event_sha256") != target.sha256
            ):
                raise UnresolvedLegalState(
                    "existing lifecycle event conflicts with exact authorization replay"
                )
            return LifecycleTransitionResult(
                authorization_sha256=auth_hash,
                before_state=EventAuthorityState(
                    _required(payload, "from_state", existing)
                ),
                after_state=EventAuthorityState(
                    _required(payload, "to_state", existing)
                ),
                event=existing,
                persisted_event_id=existing.event_id,
                replay_idempotent=True,
            )

        if target.event_type == TRANSITION_EVENT_TYPE:
            raise UnresolvedLegalState(
                "lifecycle transition events cannot themselves be lifecycle targets"
            )
        if target.authority_state is EventAuthorityState.NONFINAL:
            raise UnresolvedLegalState(
                "NONFINAL assertion/source events are not lifecycle targets"
            )

        current = resolve_effective_authority_state(
            self.store, target.event_id
        )
        if current.effective_state is not authorization.expected_current_state:
            raise UnresolvedLegalState(
                "expected_current_state does not match reconstructed CURRENT_STATE"
            )

        if current.tail_transition_event_id is None:
            if authorization.prior_transition is not None:
                raise UnresolvedLegalState(
                    "first lifecycle transition must not bind prior_transition"
                )
        else:
            if authorization.prior_transition is None:
                raise UnresolvedLegalState(
                    "subsequent lifecycle transition must bind exact prior_transition"
                )
            prior = _load_exact(self.store, authorization.prior_transition)
            if prior.event_type != TRANSITION_EVENT_TYPE:
                raise UnresolvedLegalState(
                    "prior_transition must be AUTHORITY_STATE_TRANSITION_EVENT"
                )
            if (
                prior.event_id != current.tail_transition_event_id
                or prior.sha256 != current.tail_transition_sha256
            ):
                raise UnresolvedLegalState(
                    "prior_transition is stale or does not match lifecycle tail"
                )

        replacement = None
        if authorization.replacement_event is not None:
            replacement = _load_exact(
                self.store, authorization.replacement_event
            )
            if replacement.event_id == target.event_id:
                raise UnresolvedLegalState(
                    "replacement_event must differ from target event"
                )
            if replacement.event_type == TRANSITION_EVENT_TYPE:
                raise UnresolvedLegalState(
                    "replacement_event cannot be a lifecycle transition"
                )
            replacement_state = resolve_effective_authority_state(
                self.store, replacement.event_id
            )
            if replacement_state.effective_state not in {
                EventAuthorityState.OPERATIVE,
                EventAuthorityState.FINAL,
                EventAuthorityState.APPEAL_PENDING,
                EventAuthorityState.STAYED,
            }:
                raise UnresolvedLegalState(
                    "replacement_event is not legally live"
                )

        event = CanonicalEvent(
            event_id=transition_event_id,
            event_type=TRANSITION_EVENT_TYPE,
            event_effective_at=authorization.transition_effective_at,
            event_recorded_at=authorization.issued_at,
            authority=authorization.legal_authority,
            payload=(
                ("human_authorization_id", authorization.authorization_id),
                ("human_authorization_sha256", auth_hash),
                ("human_reviewer", authorization.reviewer),
                ("target_event_id", target.event_id),
                ("target_event_sha256", target.sha256),
                ("prior_transition_event_id", current.tail_transition_event_id or ""),
                ("prior_transition_sha256", current.tail_transition_sha256 or ""),
                ("from_state", current.effective_state.value),
                ("to_state", authorization.to_state.value),
                ("replacement_event_id", replacement.event_id if replacement else ""),
                ("replacement_event_sha256", replacement.sha256 if replacement else ""),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )

        before = self.store.health()["event_count"]
        self.store.append_event(event)
        after = self.store.health()["event_count"]

        reconstructed = resolve_effective_authority_state(
            self.store, target.event_id
        )
        if reconstructed.effective_state is not authorization.to_state:
            raise UnresolvedLegalState(
                "persisted lifecycle transition did not reconstruct requested state"
            )

        return LifecycleTransitionResult(
            authorization_sha256=auth_hash,
            before_state=current.effective_state,
            after_state=reconstructed.effective_state,
            event=event,
            persisted_event_id=event.event_id,
            replay_idempotent=(before == after),
        )
