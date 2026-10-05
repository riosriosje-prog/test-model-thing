import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

from galia2.authority_lifecycle import (
    AuthorityLifecycleGate,
    BoundEvent,
    HumanLifecycleAuthorization,
    LifecycleDecision,
    TRANSITION_EVENT_TYPE,
    resolve_effective_authority_state,
)
from galia2.secured_claim_determination import (
    BoundAssertion,
    DeterminationDecision,
    HumanDeterminationAuthorization,
    SecuredClaimDeterminationGate,
)
from galia2.secured_claim_store import SecuredClaimStore
from galia2.secured_claims import (
    AuthorityReference,
    CanonicalEvent,
    EventAuthorityState,
    UnresolvedLegalState,
)
from galia2.secured_status_compiler import (
    BoundDetermination,
    SecuredStatusCompileRequest,
    SecuredStatusCompiler,
)
from galia2.section_506b_compiler import (
    Section506BCompileRequest,
    Section506BCompiler,
)

UTC = timezone.utc
T1 = datetime(2026, 1, 15, tzinfo=UTC)
T2 = datetime(2026, 1, 20, tzinfo=UTC)
T3 = datetime(2026, 1, 21, tzinfo=UTC)
T4 = datetime(2026, 1, 22, tzinfo=UTC)
T5 = datetime(2026, 1, 23, tzinfo=UTC)

SOURCE_AUTH = AuthorityReference(
    authority_id="source",
    authority_type="DOCUMENT",
    citation="Synthetic source",
    jurisdiction="D.P.R.",
    effective_date=T1,
)
ORDER_AUTH = AuthorityReference(
    authority_id="order",
    authority_type="COURT_ORDER",
    citation="Synthetic operative order",
    jurisdiction="D.P.R.",
    effective_date=T1,
)
LIFECYCLE_AUTH = AuthorityReference(
    authority_id="lifecycle-order",
    authority_type="COURT_ORDER",
    citation="Synthetic stay/vacatur order",
    jurisdiction="D.P.R.",
    effective_date=T4,
)
SECTION_506A = AuthorityReference(
    authority_id="statute-506a",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506(a)",
    jurisdiction="US",
    effective_date=T1,
)
SECTION_506B = AuthorityReference(
    authority_id="statute-506b",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506(b)",
    jurisdiction="US",
    effective_date=T1,
)


class AuthorityLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.store = SecuredClaimStore(self.path)
        self.det_gate = SecuredClaimDeterminationGate(store=self.store)
        self.lifecycle = AuthorityLifecycleGate(store=self.store)
        self.status_compiler = SecuredStatusCompiler(store=self.store)
        self.b_compiler = Section506BCompiler(store=self.store)
        self.counter = 0

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _source(self, event_type):
        self.counter += 1
        event = CanonicalEvent(
            event_id=f"src-{self.counter}",
            event_type=event_type,
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=SOURCE_AUTH,
            payload=(("blocker_codes_json", "[]"),),
            authority_state=EventAuthorityState.NONFINAL,
        )
        self.store.append_event(event)
        return event

    def _det(
        self,
        source_type,
        det_type,
        payload,
        *,
        state=EventAuthorityState.OPERATIVE,
        legal_authority=ORDER_AUTH,
    ):
        source = self._source(source_type)
        self.counter += 1
        auth = HumanDeterminationAuthorization(
            authorization_id=f"human-det-{self.counter}",
            decision=DeterminationDecision.AUTHORIZE_DETERMINATION,
            reviewer="human-reviewer",
            rationale="fixture determination",
            issued_at=T2,
            determination_event_type=det_type,
            determination_effective_at=T1,
            determination_authority_state=state,
            legal_authority=legal_authority,
            bound_assertions=(BoundAssertion(source.event_id, source.sha256),),
            determination_payload=tuple(payload),
        )
        return self.det_gate.authorize(auth).event

    def _lifecycle_auth(
        self,
        target,
        to_state,
        *,
        expected_state=None,
        prior=None,
        replacement=None,
        authorization_id=None,
        authority=LIFECYCLE_AUTH,
        issued_at=T5,
        effective_at=T4,
    ):
        self.counter += 1
        return HumanLifecycleAuthorization(
            authorization_id=authorization_id or f"life-{self.counter}",
            decision=LifecycleDecision.AUTHORIZE_STATE_TRANSITION,
            reviewer="human-reviewer",
            rationale="fixture lifecycle transition",
            issued_at=issued_at,
            transition_effective_at=effective_at,
            target=BoundEvent(target.event_id, target.sha256),
            expected_current_state=expected_state or target.authority_state,
            to_state=to_state,
            legal_authority=authority,
            prior_transition=(
                BoundEvent(prior.event_id, prior.sha256)
                if prior is not None else None
            ),
            replacement_event=(
                BoundEvent(replacement.event_id, replacement.sha256)
                if replacement is not None else None
            ),
        )

    def _c5_trio(self, *, state=EventAuthorityState.OPERATIVE):
        allowance = self._det(
            "CLAIM_ASSERTION_EVENT",
            "CLAIM_ALLOWANCE_EVENT",
            (("claim_id", "claim-1"), ("allowed_amount", "100")),
            state=state,
        )
        valuation = self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("valuation_context_id", "ctx-506a"),
                ("priority_snapshot_id", "stack-1"),
                ("estate_interest_value", "90"),
            ),
            state=state,
        )
        priority = self._det(
            "PRIORITY_ASSERTION_EVENT",
            "LIEN_PRIORITY_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("priority_snapshot_id", "stack-1"),
                ("value_available_to_creditor", "80"),
            ),
            state=state,
        )
        return allowance, valuation, priority

    def _c5_request(
        self,
        trio,
        *,
        request_id="status-1",
        compiled_at=T3,
        state=EventAuthorityState.OPERATIVE,
    ):
        allowance, valuation, priority = trio
        return SecuredStatusCompileRequest(
            request_id=request_id,
            compiled_at=compiled_at,
            allowance=BoundDetermination(allowance.event_id, allowance.sha256),
            valuation=BoundDetermination(valuation.event_id, valuation.sha256),
            priority=BoundDetermination(priority.event_id, priority.sha256),
            section_506a_authority=SECTION_506A,
            result_authority_state=state,
        )

    def _status(self, *, state=EventAuthorityState.OPERATIVE):
        trio = self._c5_trio(state=state)
        return self.status_compiler.compile(
            self._c5_request(trio, request_id=f"status-{self.counter}", state=state)
        ).event

    def _valuation_506b(self, *, state=EventAuthorityState.OPERATIVE):
        return self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("valuation_context_id", "ctx-506b"),
                ("priority_snapshot_id", "stack-506b"),
                ("valuation_purpose", "SECTION_506B"),
                ("collateral_value_for_506b", "140"),
            ),
            state=state,
        )

    def _component(self, *, state=EventAuthorityState.OPERATIVE):
        return self._det(
            "SECTION_506B_COMPONENT_ASSERTION_EVENT",
            "SECTION_506B_COMPONENT_EVENT",
            (
                ("claim_id", "claim-1"),
                ("component_id", "interest"),
                ("component_type", "INTEREST"),
                ("eligible_amount", "10"),
                ("eligibility_state", "ELIGIBLE"),
                ("accrual_start", "2026-01-15T00:00:00+00:00"),
                ("accrual_end", "2026-01-20T00:00:00+00:00"),
                ("rate_source", "CONTRACT"),
            ),
            state=state,
        )

    def _c6_request(
        self,
        status,
        valuation,
        component,
        *,
        request_id="506b-1",
        compiled_at=T5,
        state=EventAuthorityState.OPERATIVE,
    ):
        return Section506BCompileRequest(
            request_id=request_id,
            compiled_at=compiled_at,
            secured_status=BoundDetermination(status.event_id, status.sha256),
            valuation=BoundDetermination(valuation.event_id, valuation.sha256),
            recoveries_506c=(),
            components=(BoundDetermination(component.event_id, component.sha256),),
            section_506b_authority=SECTION_506B,
            result_authority_state=state,
        )

    def _simple_target(self, *, state=EventAuthorityState.OPERATIVE):
        return self._det(
            "CLAIM_ASSERTION_EVENT",
            "CLAIM_ALLOWANCE_EVENT",
            (("claim_id", "claim-x"), ("allowed_amount", "50")),
            state=state,
        )

    def test_01_no_transition_returns_stored_state(self):
        target = self._simple_target()
        state = resolve_effective_authority_state(self.store, target.event_id)
        self.assertEqual(state.initial_state, EventAuthorityState.OPERATIVE)
        self.assertEqual(state.effective_state, EventAuthorityState.OPERATIVE)
        self.assertEqual(state.transition_event_ids, ())

    def test_02_operative_to_stayed(self):
        target = self._simple_target()
        result = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        )
        self.assertEqual(result.before_state, EventAuthorityState.OPERATIVE)
        self.assertEqual(result.after_state, EventAuthorityState.STAYED)

    def test_03_target_event_is_never_mutated(self):
        target = self._simple_target()
        digest = target.sha256
        self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        )
        loaded = self.store.get_event(target.event_id)
        self.assertEqual(loaded.sha256, digest)
        self.assertEqual(loaded.authority_state, EventAuthorityState.OPERATIVE)

    def test_04_transition_is_new_canonical_event(self):
        target = self._simple_target()
        result = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        )
        self.assertEqual(result.event.event_type, TRANSITION_EVENT_TYPE)
        self.assertNotEqual(result.event.event_id, target.event_id)

    def test_05_human_authorization_and_legal_authority_are_separate(self):
        target = self._simple_target()
        result = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        )
        payload = dict(result.event.payload)
        self.assertIn("human_authorization_sha256", payload)
        self.assertEqual(result.event.authority, LIFECYCLE_AUTH)

    def test_06_human_promotion_cannot_be_lifecycle_legal_authority(self):
        target = self._simple_target()
        human = AuthorityReference(
            authority_id="human",
            authority_type="HUMAN_PROMOTION",
            citation="Prom",
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot substitute"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target, EventAuthorityState.STAYED, authority=human
                )
            )

    def test_07_nonfinal_assertion_cannot_be_lifecycle_target(self):
        source = self._source("CLAIM_ASSERTION_EVENT")
        with self.assertRaisesRegex(UnresolvedLegalState, "NONFINAL"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    source,
                    EventAuthorityState.STAYED,
                    expected_state=EventAuthorityState.NONFINAL,
                )
            )

    def test_08_transition_event_cannot_be_transition_target(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        ).event
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot themselves"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    first,
                    EventAuthorityState.STAYED,
                    expected_state=EventAuthorityState.OPERATIVE,
                )
            )

    def test_09_operative_to_appeal_pending(self):
        target = self._simple_target()
        result = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.APPEAL_PENDING)
        )
        self.assertEqual(result.after_state, EventAuthorityState.APPEAL_PENDING)

    def test_10_appeal_pending_to_final_requires_prior_binding(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.APPEAL_PENDING)
        ).event
        result = self.lifecycle.authorize(
            self._lifecycle_auth(
                target,
                EventAuthorityState.FINAL,
                expected_state=EventAuthorityState.APPEAL_PENDING,
                prior=first,
            )
        )
        self.assertEqual(result.after_state, EventAuthorityState.FINAL)

    def test_11_stayed_can_return_to_operative(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        ).event
        second = self.lifecycle.authorize(
            self._lifecycle_auth(
                target,
                EventAuthorityState.OPERATIVE,
                expected_state=EventAuthorityState.STAYED,
                prior=first,
            )
        )
        self.assertEqual(second.after_state, EventAuthorityState.OPERATIVE)

    def test_12_final_can_be_stayed_by_new_authority(self):
        target = self._simple_target(state=EventAuthorityState.FINAL)
        result = self.lifecycle.authorize(
            self._lifecycle_auth(
                target,
                EventAuthorityState.STAYED,
                expected_state=EventAuthorityState.FINAL,
            )
        )
        self.assertEqual(result.after_state, EventAuthorityState.STAYED)

    def test_13_vacated_is_terminal(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.VACATED)
        ).event
        with self.assertRaisesRegex(UnresolvedLegalState, "terminal"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.OPERATIVE,
                    expected_state=EventAuthorityState.VACATED,
                    prior=first,
                )
            )

    def test_14_reversed_is_terminal(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.REVERSED)
        ).event
        with self.assertRaisesRegex(UnresolvedLegalState, "terminal"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.OPERATIVE,
                    expected_state=EventAuthorityState.REVERSED,
                    prior=first,
                )
            )

    def test_15_superseded_requires_replacement(self):
        target = self._simple_target()
        with self.assertRaisesRegex(UnresolvedLegalState, "replacement_event"):
            self.lifecycle.authorize(
                self._lifecycle_auth(target, EventAuthorityState.SUPERSEDED)
            )

    def test_16_superseded_binds_exact_replacement(self):
        target = self._simple_target()
        replacement = self._simple_target()
        result = self.lifecycle.authorize(
            self._lifecycle_auth(
                target,
                EventAuthorityState.SUPERSEDED,
                replacement=replacement,
            )
        )
        payload = dict(result.event.payload)
        self.assertEqual(payload["replacement_event_id"], replacement.event_id)
        self.assertEqual(payload["replacement_event_sha256"], replacement.sha256)

    def test_17_replacement_not_permitted_for_stay(self):
        target = self._simple_target()
        replacement = self._simple_target()
        with self.assertRaisesRegex(UnresolvedLegalState, "only for SUPERSEDED"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.STAYED,
                    replacement=replacement,
                )
            )

    def test_18_replacement_hash_must_match(self):
        target = self._simple_target()
        replacement = self._simple_target()
        auth = self._lifecycle_auth(
            target,
            EventAuthorityState.SUPERSEDED,
            replacement=replacement,
        )
        bad = HumanLifecycleAuthorization(
            authorization_id=auth.authorization_id,
            decision=auth.decision,
            reviewer=auth.reviewer,
            rationale=auth.rationale,
            issued_at=auth.issued_at,
            transition_effective_at=auth.transition_effective_at,
            target=auth.target,
            expected_current_state=auth.expected_current_state,
            to_state=auth.to_state,
            legal_authority=auth.legal_authority,
            prior_transition=auth.prior_transition,
            replacement_event=BoundEvent(replacement.event_id, "0" * 64),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "hash mismatch"):
            self.lifecycle.authorize(bad)

    def test_19_replacement_must_differ_from_target(self):
        target = self._simple_target()
        with self.assertRaisesRegex(UnresolvedLegalState, "must differ"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.SUPERSEDED,
                    replacement=target,
                )
            )

    def test_20_first_transition_cannot_bind_prior(self):
        target = self._simple_target()
        other_target = self._simple_target()
        other_transition = self.lifecycle.authorize(
            self._lifecycle_auth(other_target, EventAuthorityState.STAYED)
        ).event
        with self.assertRaisesRegex(UnresolvedLegalState, "must not bind"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.STAYED,
                    prior=other_transition,
                )
            )

    def test_21_subsequent_transition_requires_prior(self):
        target = self._simple_target()
        self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "must bind exact"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.OPERATIVE,
                    expected_state=EventAuthorityState.STAYED,
                )
            )

    def test_22_stale_prior_is_rejected(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        ).event
        second = self.lifecycle.authorize(
            self._lifecycle_auth(
                target,
                EventAuthorityState.OPERATIVE,
                expected_state=EventAuthorityState.STAYED,
                prior=first,
            )
        ).event
        with self.assertRaisesRegex(UnresolvedLegalState, "stale"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.APPEAL_PENDING,
                    expected_state=EventAuthorityState.OPERATIVE,
                    prior=first,
                )
            )
        self.assertEqual(
            resolve_effective_authority_state(
                self.store, target.event_id
            ).tail_transition_event_id,
            second.event_id,
        )

    def test_23_expected_current_state_must_match_replay(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        ).event
        with self.assertRaisesRegex(UnresolvedLegalState, "CURRENT_STATE"):
            self.lifecycle.authorize(
                self._lifecycle_auth(
                    target,
                    EventAuthorityState.FINAL,
                    expected_state=EventAuthorityState.OPERATIVE,
                    prior=first,
                )
            )

    def test_24_target_hash_must_match(self):
        target = self._simple_target()
        auth = self._lifecycle_auth(target, EventAuthorityState.STAYED)
        bad = HumanLifecycleAuthorization(
            authorization_id=auth.authorization_id,
            decision=auth.decision,
            reviewer=auth.reviewer,
            rationale=auth.rationale,
            issued_at=auth.issued_at,
            transition_effective_at=auth.transition_effective_at,
            target=BoundEvent(target.event_id, "0" * 64),
            expected_current_state=auth.expected_current_state,
            to_state=auth.to_state,
            legal_authority=auth.legal_authority,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "hash mismatch"):
            self.lifecycle.authorize(bad)

    def test_25_exact_authorization_replay_is_idempotent(self):
        target = self._simple_target()
        auth = self._lifecycle_auth(
            target,
            EventAuthorityState.STAYED,
            authorization_id="exact-replay",
        )
        first = self.lifecycle.authorize(auth)
        second = self.lifecycle.authorize(auth)
        self.assertFalse(first.replay_idempotent)
        self.assertTrue(second.replay_idempotent)
        self.assertEqual(first.event.event_id, second.event.event_id)

    def test_26_chain_reconstructs_exact_ids_and_hashes(self):
        target = self._simple_target()
        first = self.lifecycle.authorize(
            self._lifecycle_auth(target, EventAuthorityState.STAYED)
        ).event
        second = self.lifecycle.authorize(
            self._lifecycle_auth(
                target,
                EventAuthorityState.OPERATIVE,
                expected_state=EventAuthorityState.STAYED,
                prior=first,
            )
        ).event
        state = resolve_effective_authority_state(self.store, target.event_id)
        self.assertEqual(state.transition_event_ids, (first.event_id, second.event_id))
        self.assertEqual(state.transition_event_hashes, (first.sha256, second.sha256))
        self.assertEqual(state.effective_state, EventAuthorityState.OPERATIVE)

    def test_27_forged_lifecycle_fork_fails_closed(self):
        target = self._simple_target()
        for suffix, to_state in (
            ("a", EventAuthorityState.STAYED),
            ("b", EventAuthorityState.APPEAL_PENDING),
        ):
            event = CanonicalEvent(
                event_id=f"forged-root-{suffix}",
                event_type=TRANSITION_EVENT_TYPE,
                event_effective_at=T4,
                event_recorded_at=T5,
                authority=LIFECYCLE_AUTH,
                payload=(
                    ("target_event_id", target.event_id),
                    ("target_event_sha256", target.sha256),
                    ("prior_transition_event_id", ""),
                    ("prior_transition_sha256", ""),
                    ("from_state", "OPERATIVE"),
                    ("to_state", to_state.value),
                ),
                authority_state=EventAuthorityState.OPERATIVE,
            )
            self.store.append_event(event)
        with self.assertRaisesRegex(UnresolvedLegalState, "exactly one root"):
            resolve_effective_authority_state(self.store, target.event_id)

    def test_28_forged_orphan_transition_fails_closed(self):
        target = self._simple_target()
        root = CanonicalEvent(
            event_id="root",
            event_type=TRANSITION_EVENT_TYPE,
            event_effective_at=T4,
            event_recorded_at=T5,
            authority=LIFECYCLE_AUTH,
            payload=(
                ("target_event_id", target.event_id),
                ("target_event_sha256", target.sha256),
                ("human_authorization_id", "forged-human"),
                ("human_authorization_sha256", "a" * 64),
                ("human_reviewer", "forged-reviewer"),
                ("replacement_event_id", ""),
                ("replacement_event_sha256", ""),
                ("prior_transition_event_id", ""),
                ("prior_transition_sha256", ""),
                ("from_state", "OPERATIVE"),
                ("to_state", "STAYED"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        orphan = CanonicalEvent(
            event_id="orphan",
            event_type=TRANSITION_EVENT_TYPE,
            event_effective_at=T4,
            event_recorded_at=T5,
            authority=LIFECYCLE_AUTH,
            payload=(
                ("target_event_id", target.event_id),
                ("target_event_sha256", target.sha256),
                ("human_authorization_id", "forged-human"),
                ("human_authorization_sha256", "a" * 64),
                ("human_reviewer", "forged-reviewer"),
                ("replacement_event_id", ""),
                ("replacement_event_sha256", ""),
                ("prior_transition_event_id", "missing"),
                ("prior_transition_sha256", "0" * 64),
                ("from_state", "STAYED"),
                ("to_state", "OPERATIVE"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(root)
        self.store.append_event(orphan)
        with self.assertRaisesRegex(UnresolvedLegalState, "orphan"):
            resolve_effective_authority_state(self.store, target.event_id)

    def test_29_forged_predecessor_hash_mismatch_fails_closed(self):
        target = self._simple_target()
        root = CanonicalEvent(
            event_id="root-hash",
            event_type=TRANSITION_EVENT_TYPE,
            event_effective_at=T4,
            event_recorded_at=T5,
            authority=LIFECYCLE_AUTH,
            payload=(
                ("target_event_id", target.event_id),
                ("target_event_sha256", target.sha256),
                ("human_authorization_id", "forged-human"),
                ("human_authorization_sha256", "a" * 64),
                ("human_reviewer", "forged-reviewer"),
                ("replacement_event_id", ""),
                ("replacement_event_sha256", ""),
                ("prior_transition_event_id", ""),
                ("prior_transition_sha256", ""),
                ("from_state", "OPERATIVE"),
                ("to_state", "STAYED"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(root)
        child = CanonicalEvent(
            event_id="child-hash",
            event_type=TRANSITION_EVENT_TYPE,
            event_effective_at=T4,
            event_recorded_at=T5,
            authority=LIFECYCLE_AUTH,
            payload=(
                ("target_event_id", target.event_id),
                ("target_event_sha256", target.sha256),
                ("human_authorization_id", "forged-human"),
                ("human_authorization_sha256", "a" * 64),
                ("human_reviewer", "forged-reviewer"),
                ("replacement_event_id", ""),
                ("replacement_event_sha256", ""),
                ("prior_transition_event_id", root.event_id),
                ("prior_transition_sha256", "0" * 64),
                ("from_state", "STAYED"),
                ("to_state", "OPERATIVE"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(child)
        with self.assertRaisesRegex(UnresolvedLegalState, "predecessor binding"):
            resolve_effective_authority_state(self.store, target.event_id)

    def test_30_c5_rejects_effectively_stayed_allowance(self):
        trio = self._c5_trio()
        allowance = trio[0]
        self.lifecycle.authorize(
            self._lifecycle_auth(allowance, EventAuthorityState.STAYED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "effectively"):
            self.status_compiler.compile(self._c5_request(trio))

    def test_31_c5_rejects_effectively_vacated_valuation(self):
        trio = self._c5_trio()
        valuation = trio[1]
        self.lifecycle.authorize(
            self._lifecycle_auth(valuation, EventAuthorityState.VACATED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "VACATED"):
            self.status_compiler.compile(self._c5_request(trio))

    def test_32_c5_rejects_effectively_reversed_priority(self):
        trio = self._c5_trio()
        priority = trio[2]
        self.lifecycle.authorize(
            self._lifecycle_auth(priority, EventAuthorityState.REVERSED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "REVERSED"):
            self.status_compiler.compile(self._c5_request(trio))

    def test_33_c5_compile_hash_binds_lifecycle_tail(self):
        trio = self._c5_trio()
        first = self.status_compiler.compile(
            self._c5_request(trio, request_id="same", compiled_at=T3)
        ).event
        valuation = trio[1]
        stay = self.lifecycle.authorize(
            self._lifecycle_auth(valuation, EventAuthorityState.STAYED)
        ).event
        self.lifecycle.authorize(
            self._lifecycle_auth(
                valuation,
                EventAuthorityState.OPERATIVE,
                expected_state=EventAuthorityState.STAYED,
                prior=stay,
            )
        )
        second = self.status_compiler.compile(
            self._c5_request(trio, request_id="same", compiled_at=T3)
        ).event
        self.assertNotEqual(first.event_id, second.event_id)
        self.assertIn(
            "input_lifecycle_bindings_json",
            dict(second.payload),
        )

    def test_34_c5_final_requires_effectively_final_inputs(self):
        trio = self._c5_trio(state=EventAuthorityState.FINAL)
        allowance = trio[0]
        self.lifecycle.authorize(
            self._lifecycle_auth(
                allowance,
                EventAuthorityState.STAYED,
                expected_state=EventAuthorityState.FINAL,
            )
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "effectively"):
            self.status_compiler.compile(
                self._c5_request(trio, state=EventAuthorityState.FINAL)
            )

    def test_35_c6_rejects_effectively_stayed_secured_status(self):
        status = self._status()
        valuation = self._valuation_506b()
        component = self._component()
        self.lifecycle.authorize(
            self._lifecycle_auth(status, EventAuthorityState.STAYED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "effectively"):
            self.b_compiler.compile(
                self._c6_request(status, valuation, component)
            )

    def test_36_c6_rejects_effectively_vacated_valuation(self):
        status = self._status()
        valuation = self._valuation_506b()
        component = self._component()
        self.lifecycle.authorize(
            self._lifecycle_auth(valuation, EventAuthorityState.VACATED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "VACATED"):
            self.b_compiler.compile(
                self._c6_request(status, valuation, component)
            )

    def test_37_c6_rejects_effectively_stayed_component(self):
        status = self._status()
        valuation = self._valuation_506b()
        component = self._component()
        self.lifecycle.authorize(
            self._lifecycle_auth(component, EventAuthorityState.STAYED)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "STAYED"):
            self.b_compiler.compile(
                self._c6_request(status, valuation, component)
            )

    def test_38_c6_compile_hash_binds_lifecycle_tail(self):
        status = self._status()
        valuation = self._valuation_506b()
        component = self._component()
        first = self.b_compiler.compile(
            self._c6_request(
                status, valuation, component, request_id="same-506b"
            )
        ).accrual_event
        stay = self.lifecycle.authorize(
            self._lifecycle_auth(component, EventAuthorityState.STAYED)
        ).event
        self.lifecycle.authorize(
            self._lifecycle_auth(
                component,
                EventAuthorityState.OPERATIVE,
                expected_state=EventAuthorityState.STAYED,
                prior=stay,
            )
        )
        second = self.b_compiler.compile(
            self._c6_request(
                status, valuation, component, request_id="same-506b"
            )
        ).accrual_event
        self.assertNotEqual(first.event_id, second.event_id)
        self.assertIn(
            "input_lifecycle_bindings_json",
            dict(second.payload),
        )


if __name__ == "__main__":
    unittest.main()
