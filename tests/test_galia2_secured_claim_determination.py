import ast
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

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

UTC = timezone.utc
T1 = datetime(2026, 1, 15, tzinfo=UTC)
T2 = datetime(2026, 1, 20, tzinfo=UTC)
LEGAL = AuthorityReference(
    authority_id="order-allowance-1",
    authority_type="COURT_ORDER",
    citation="Order Allowing Claim ¶ 4",
    jurisdiction="D.P.R.",
    effective_date=T1,
)
SOURCE_AUTH = AuthorityReference(
    authority_id="source-doc-1",
    authority_type="DOCUMENT",
    citation="Proof of Claim No. 7",
    jurisdiction="D.P.R.",
    effective_date=T1,
)


class SecuredClaimDeterminationGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.store = SecuredClaimStore(self.path)
        self.gate = SecuredClaimDeterminationGate(store=self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _assertion(
        self,
        event_id="a1",
        event_type="CLAIM_ASSERTION_EVENT",
        *,
        state=EventAuthorityState.NONFINAL,
        blockers="[]",
    ):
        e = CanonicalEvent(
            event_id=event_id,
            event_type=event_type,
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=SOURCE_AUTH,
            payload=(
                ("source_claim_id", "clm-1"),
                ("blocker_codes_json", blockers),
            ),
            authority_state=state,
        )
        self.store.append_event(e)
        return e

    def _auth(
        self,
        source_events,
        *,
        authorization_id="human-auth-1",
        event_type="CLAIM_ALLOWANCE_EVENT",
        state=EventAuthorityState.OPERATIVE,
        legal_authority=LEGAL,
        issued_at=T2,
        effective_at=T1,
        payload=(("allowed_amount", "100000"),),
    ):
        return HumanDeterminationAuthorization(
            authorization_id=authorization_id,
            decision=DeterminationDecision.AUTHORIZE_DETERMINATION,
            reviewer="human-reviewer",
            rationale="Reviewed exact source assertions and underlying order.",
            issued_at=issued_at,
            determination_event_type=event_type,
            determination_effective_at=effective_at,
            determination_authority_state=state,
            legal_authority=legal_authority,
            bound_assertions=tuple(
                BoundAssertion(e.event_id, e.sha256) for e in source_events
            ),
            determination_payload=payload,
        )

    def test_01_claim_assertion_can_authorize_allowance(self):
        source = self._assertion()
        result = self.gate.authorize(self._auth((source,)))
        self.assertEqual(result.event.event_type, "CLAIM_ALLOWANCE_EVENT")
        self.assertEqual(result.event.authority_state, EventAuthorityState.OPERATIVE)

    def test_02_valuation_assertion_can_authorize_valuation(self):
        source = self._assertion(event_type="VALUATION_ASSERTION_EVENT")
        auth = self._auth(
            (source,),
            event_type="VALUATION_EVENT",
            payload=(("creditor_interest_value", "80000"),),
        )
        result = self.gate.authorize(auth)
        self.assertEqual(result.event.event_type, "VALUATION_EVENT")

    def test_03_priority_assertion_can_authorize_priority(self):
        source = self._assertion(event_type="PRIORITY_ASSERTION_EVENT")
        auth = self._auth(
            (source,),
            event_type="LIEN_PRIORITY_EVENT",
            payload=(("priority", "SENIOR"),),
        )
        self.assertEqual(
            self.gate.authorize(auth).event.event_type,
            "LIEN_PRIORITY_EVENT",
        )

    def test_04_lien_assertion_can_authorize_priority(self):
        source = self._assertion(event_type="LIEN_ASSERTION_EVENT")
        auth = self._auth(
            (source,),
            event_type="LIEN_PRIORITY_EVENT",
            payload=(("priority", "SENIOR"),),
        )
        self.assertEqual(
            self.gate.authorize(auth).event.event_type,
            "LIEN_PRIORITY_EVENT",
        )

    def test_05_payment_assertion_can_authorize_payment(self):
        source = self._assertion(event_type="PAYMENT_ASSERTION_EVENT")
        auth = self._auth(
            (source,),
            event_type="PAYMENT_EVENT",
            payload=(("amount", "5000"),),
        )
        self.assertEqual(self.gate.authorize(auth).event.event_type, "PAYMENT_EVENT")

    def test_06_plan_assertion_can_authorize_plan_treatment(self):
        source = self._assertion(event_type="PLAN_TREATMENT_ASSERTION_EVENT")
        auth = self._auth(
            (source,),
            event_type="PLAN_TREATMENT_EVENT",
            payload=(("treatment", "RETAIN_AND_PAY"),),
        )
        self.assertEqual(
            self.gate.authorize(auth).event.event_type,
            "PLAN_TREATMENT_EVENT",
        )

    def test_07_missing_bound_assertion_fails_closed(self):
        missing = CanonicalEvent(
            "missing", "CLAIM_ASSERTION_EVENT", T1, T2, SOURCE_AUTH,
            authority_state=EventAuthorityState.NONFINAL,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "does not exist"):
            self.gate.authorize(self._auth((missing,)))

    def test_08_hash_mismatch_fails_closed(self):
        source = self._assertion()
        auth = self._auth((source,))
        bad = HumanDeterminationAuthorization(
            authorization_id=auth.authorization_id,
            decision=auth.decision,
            reviewer=auth.reviewer,
            rationale=auth.rationale,
            issued_at=auth.issued_at,
            determination_event_type=auth.determination_event_type,
            determination_effective_at=auth.determination_effective_at,
            determination_authority_state=auth.determination_authority_state,
            legal_authority=auth.legal_authority,
            bound_assertions=(BoundAssertion(source.event_id, "0" * 64),),
            determination_payload=auth.determination_payload,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "hash mismatch"):
            self.gate.authorize(bad)

    def test_09_source_must_remain_nonfinal(self):
        source = self._assertion(state=EventAuthorityState.OPERATIVE)
        with self.assertRaisesRegex(UnresolvedLegalState, "remain NONFINAL"):
            self.gate.authorize(self._auth((source,)))

    def test_10_non_assertion_source_is_rejected(self):
        source = self._assertion(event_type="CLAIM_ALLOWANCE_EVENT")
        with self.assertRaisesRegex(UnresolvedLegalState, "allowed assertion"):
            self.gate.authorize(self._auth((source,)))

    def test_11_incompatible_determination_family_is_rejected(self):
        source = self._assertion()
        auth = self._auth((source,), event_type="VALUATION_EVENT")
        with self.assertRaisesRegex(UnresolvedLegalState, "incompatible"):
            self.gate.authorize(auth)

    def test_12_cross_family_laundering_is_rejected(self):
        claim = self._assertion("a1", "CLAIM_ASSERTION_EVENT")
        value = self._assertion("a2", "VALUATION_ASSERTION_EVENT")
        auth = self._auth((claim, value), event_type="CLAIM_ALLOWANCE_EVENT")
        with self.assertRaisesRegex(UnresolvedLegalState, "all bound assertion"):
            self.gate.authorize(auth)

    def test_13_at_least_one_bound_assertion_required(self):
        auth = self._auth(())
        with self.assertRaisesRegex(UnresolvedLegalState, "at least one"):
            self.gate.authorize(auth)

    def test_14_duplicate_bound_assertion_rejected(self):
        source = self._assertion()
        auth = self._auth((source, source))
        with self.assertRaisesRegex(UnresolvedLegalState, "duplicate"):
            self.gate.authorize(auth)

    def test_15_bad_hash_format_rejected(self):
        source = self._assertion()
        auth = self._auth((source,))
        bad = HumanDeterminationAuthorization(
            authorization_id=auth.authorization_id,
            decision=auth.decision,
            reviewer=auth.reviewer,
            rationale=auth.rationale,
            issued_at=auth.issued_at,
            determination_event_type=auth.determination_event_type,
            determination_effective_at=auth.determination_effective_at,
            determination_authority_state=auth.determination_authority_state,
            legal_authority=auth.legal_authority,
            bound_assertions=(BoundAssertion(source.event_id, "xyz"),),
            determination_payload=auth.determination_payload,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "64"):
            self.gate.authorize(bad)

    def test_16_distinct_legal_authority_required(self):
        source = self._assertion()
        auth = self._auth((source,), legal_authority=None)
        with self.assertRaisesRegex(UnresolvedLegalState, "legal authority"):
            self.gate.authorize(auth)

    def test_17_legal_authority_citation_required(self):
        source = self._assertion()
        bad_authority = AuthorityReference(
            authority_id="x",
            authority_type="COURT_ORDER",
            citation="",
        )
        auth = self._auth((source,), legal_authority=bad_authority)
        with self.assertRaisesRegex(UnresolvedLegalState, "citation"):
            self.gate.authorize(auth)

    def test_18_new_determination_cannot_be_nonfinal(self):
        source = self._assertion()
        auth = self._auth((source,), state=EventAuthorityState.NONFINAL)
        with self.assertRaisesRegex(UnresolvedLegalState, "OPERATIVE or FINAL"):
            self.gate.authorize(auth)

    def test_19_new_determination_cannot_be_stayed(self):
        source = self._assertion()
        auth = self._auth((source,), state=EventAuthorityState.STAYED)
        with self.assertRaisesRegex(UnresolvedLegalState, "OPERATIVE or FINAL"):
            self.gate.authorize(auth)

    def test_20_issued_at_must_have_timezone(self):
        source = self._assertion()
        auth = self._auth(
            (source,), issued_at=datetime(2026, 1, 20, 0, 0, 0)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "issued_at"):
            self.gate.authorize(auth)

    def test_21_effective_at_must_have_timezone(self):
        source = self._assertion()
        auth = self._auth(
            (source,), effective_at=datetime(2026, 1, 15, 0, 0, 0)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "effective"):
            self.gate.authorize(auth)

    def test_22_source_blockers_prevent_determination(self):
        source = self._assertion(blockers='["RAW_CAPTURE_REQUIRED"]')
        with self.assertRaisesRegex(UnresolvedLegalState, "blockers"):
            self.gate.authorize(self._auth((source,)))

    def test_23_invalid_blocker_json_fails_closed(self):
        source = self._assertion(blockers="not-json")
        with self.assertRaisesRegex(UnresolvedLegalState, "invalid"):
            self.gate.authorize(self._auth((source,)))

    def test_24_replay_is_idempotent(self):
        source = self._assertion()
        auth = self._auth((source,))
        first = self.gate.authorize(auth)
        second = self.gate.authorize(auth)
        self.assertFalse(first.replay_idempotent)
        self.assertTrue(second.replay_idempotent)
        self.assertEqual(first.event.event_id, second.event.event_id)

    def test_25_changed_human_authorization_creates_new_event(self):
        source = self._assertion()
        first = self.gate.authorize(self._auth((source,), authorization_id="h1"))
        second = self.gate.authorize(self._auth(
            (source,),
            authorization_id="h2",
            payload=(("allowed_amount", "90000"),),
        ))
        self.assertNotEqual(first.event.event_id, second.event.event_id)
        self.assertEqual(self.store.health()["event_count"], 3)

    def test_26_authorization_hash_is_deterministic(self):
        source = self._assertion()
        a = self._auth((source,))
        b = self._auth((source,))
        self.assertEqual(a.sha256, b.sha256)

    def test_27_source_assertion_is_not_mutated(self):
        source = self._assertion()
        original_hash = source.sha256
        self.gate.authorize(self._auth((source,)))
        loaded = self.store.get_event(source.event_id)
        self.assertEqual(loaded.sha256, original_hash)
        self.assertEqual(loaded.authority_state, EventAuthorityState.NONFINAL)

    def test_28_result_binds_source_and_human_authorization_hashes(self):
        source = self._assertion()
        auth = self._auth((source,))
        result = self.gate.authorize(auth)
        payload = dict(result.event.payload)
        self.assertEqual(payload["human_authorization_sha256"], auth.sha256)
        self.assertIn(source.event_id, payload["source_event_ids_json"])
        self.assertIn(source.sha256, payload["source_event_hashes_json"])

    def test_29_legal_authority_is_not_source_assertion_authority(self):
        source = self._assertion()
        result = self.gate.authorize(self._auth((source,)))
        self.assertEqual(result.event.authority, LEGAL)
        self.assertNotEqual(result.event.authority, source.authority)

    def test_30_final_state_is_allowed_when_explicitly_authorized(self):
        source = self._assertion()
        auth = self._auth((source,), state=EventAuthorityState.FINAL)
        result = self.gate.authorize(auth)
        self.assertEqual(result.event.authority_state, EventAuthorityState.FINAL)

    def test_31_payload_duplicate_keys_fail_closed(self):
        source = self._assertion()
        auth = self._auth(
            (source,),
            payload=(("allowed_amount", "100"), ("allowed_amount", "90")),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "unique"):
            self.gate.authorize(auth)

    def test_32_gate_module_has_no_shadow_or_historical_writeback_calls(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "galia2"
            / "secured_claim_determination.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden = {
            "review_claim",
            "propose_claim",
            "add_evidence",
            "mirror_claim",
            "record_human_selection",
            "issue_promotion_authorization",
            "publish_generation",
        }
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertTrue(forbidden.isdisjoint(used))


if __name__ == "__main__":
    unittest.main()
