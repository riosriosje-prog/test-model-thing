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
from galia2.secured_status_compiler import (
    BoundDetermination,
    SecuredStatusCompileRequest,
    SecuredStatusCompiler,
)

UTC = timezone.utc
T1 = datetime(2026, 1, 15, tzinfo=UTC)
T2 = datetime(2026, 1, 20, tzinfo=UTC)
T3 = datetime(2026, 1, 21, tzinfo=UTC)

SOURCE_AUTH = AuthorityReference(
    authority_id="source-fixture",
    authority_type="DOCUMENT",
    citation="Synthetic Source",
    jurisdiction="D.P.R.",
    effective_date=T1,
)
ORDER_AUTH = AuthorityReference(
    authority_id="order-fixture",
    authority_type="COURT_ORDER",
    citation="Synthetic Order",
    jurisdiction="D.P.R.",
    effective_date=T1,
)
SECTION_506A = AuthorityReference(
    authority_id="statute-506a",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506(a)",
    jurisdiction="US",
    effective_date=T1,
)


class SecuredStatusCompilerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.store = SecuredClaimStore(self.path)
        self.gate = SecuredClaimDeterminationGate(store=self.store)
        self.compiler = SecuredStatusCompiler(store=self.store)
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

    def _det(self, source_type, det_type, payload, *, state=EventAuthorityState.OPERATIVE):
        source = self._source(source_type)
        self.counter += 1
        auth = HumanDeterminationAuthorization(
            authorization_id=f"human-{self.counter}",
            decision=DeterminationDecision.AUTHORIZE_DETERMINATION,
            reviewer="human-fixture",
            rationale="fixture determination",
            issued_at=T2,
            determination_event_type=det_type,
            determination_effective_at=T1,
            determination_authority_state=state,
            legal_authority=ORDER_AUTH,
            bound_assertions=(BoundAssertion(source.event_id, source.sha256),),
            determination_payload=tuple(payload),
        )
        return self.gate.authorize(auth).event

    def _trio(
        self,
        *,
        claim_id="claim-1",
        package="pkg-1",
        context="ctx-1",
        snapshot="stack-1",
        allowed="100",
        estate="80",
        available="60",
        allowance_state=EventAuthorityState.OPERATIVE,
        valuation_state=EventAuthorityState.OPERATIVE,
        priority_state=EventAuthorityState.OPERATIVE,
    ):
        allowance = self._det(
            "CLAIM_ASSERTION_EVENT",
            "CLAIM_ALLOWANCE_EVENT",
            (("claim_id", claim_id), ("allowed_amount", allowed)),
            state=allowance_state,
        )
        valuation = self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", claim_id),
                ("collateral_package_id", package),
                ("valuation_context_id", context),
                ("priority_snapshot_id", snapshot),
                ("estate_interest_value", estate),
            ),
            state=valuation_state,
        )
        priority = self._det(
            "PRIORITY_ASSERTION_EVENT",
            "LIEN_PRIORITY_EVENT",
            (
                ("claim_id", claim_id),
                ("collateral_package_id", package),
                ("priority_snapshot_id", snapshot),
                ("value_available_to_creditor", available),
            ),
            state=priority_state,
        )
        return allowance, valuation, priority

    def _request(
        self,
        trio,
        *,
        request_id="compile-1",
        authority=SECTION_506A,
        state=EventAuthorityState.OPERATIVE,
        compiled_at=T3,
    ):
        allowance, valuation, priority = trio
        return SecuredStatusCompileRequest(
            request_id=request_id,
            compiled_at=compiled_at,
            allowance=BoundDetermination(allowance.event_id, allowance.sha256),
            valuation=BoundDetermination(valuation.event_id, valuation.sha256),
            priority=BoundDetermination(priority.event_id, priority.sha256),
            section_506a_authority=authority,
            result_authority_state=state,
        )

    def test_01_undersecured_classification(self):
        result = self.compiler.compile(self._request(self._trio()))
        payload = dict(result.event.payload)
        self.assertEqual(payload["secured_portion"], "60")
        self.assertEqual(payload["unsecured_deficiency"], "40")

    def test_02_fully_secured_classification(self):
        result = self.compiler.compile(
            self._request(self._trio(allowed="50", available="60"))
        )
        payload = dict(result.event.payload)
        self.assertEqual(payload["secured_portion"], "50")
        self.assertEqual(payload["unsecured_deficiency"], "0")

    def test_03_zero_available_value_is_fully_unsecured_by_value(self):
        result = self.compiler.compile(
            self._request(self._trio(allowed="50", estate="80", available="0"))
        )
        payload = dict(result.event.payload)
        self.assertEqual(payload["secured_portion"], "0")
        self.assertEqual(payload["unsecured_deficiency"], "50")

    def test_04_output_is_secured_status_event(self):
        result = self.compiler.compile(self._request(self._trio()))
        self.assertEqual(result.event.event_type, "SECURED_STATUS_EVENT")

    def test_05_effective_date_comes_from_valuation(self):
        trio = self._trio()
        result = self.compiler.compile(self._request(trio))
        self.assertEqual(result.event.event_effective_at, trio[1].event_effective_at)

    def test_06_recorded_date_is_compile_time(self):
        result = self.compiler.compile(self._request(self._trio()))
        self.assertEqual(result.event.event_recorded_at, T3)

    def test_07_claim_ids_must_match(self):
        a, v, p = self._trio()
        bad_p = self._det(
            "PRIORITY_ASSERTION_EVENT",
            "LIEN_PRIORITY_EVENT",
            (
                ("claim_id", "other"),
                ("collateral_package_id", "pkg-1"),
                ("priority_snapshot_id", "stack-1"),
                ("value_available_to_creditor", "60"),
            ),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "claim_id"):
            self.compiler.compile(self._request((a, v, bad_p)))

    def test_08_collateral_package_must_match(self):
        a, v, p = self._trio()
        bad_p = self._det(
            "PRIORITY_ASSERTION_EVENT",
            "LIEN_PRIORITY_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-2"),
                ("priority_snapshot_id", "stack-1"),
                ("value_available_to_creditor", "60"),
            ),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "collateral_package"):
            self.compiler.compile(self._request((a, v, bad_p)))

    def test_09_priority_snapshot_must_match(self):
        a, v, p = self._trio()
        bad_p = self._det(
            "PRIORITY_ASSERTION_EVENT",
            "LIEN_PRIORITY_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("priority_snapshot_id", "stack-2"),
                ("value_available_to_creditor", "60"),
            ),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "snapshot"):
            self.compiler.compile(self._request((a, v, bad_p)))

    def test_10_available_value_cannot_exceed_estate_interest(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot exceed"):
            self.compiler.compile(
                self._request(self._trio(estate="50", available="60"))
            )

    def test_11_missing_claim_id_fails_closed(self):
        a = self._det(
            "CLAIM_ASSERTION_EVENT",
            "CLAIM_ALLOWANCE_EVENT",
            (("allowed_amount", "100"),),
        )
        _, v, p = self._trio()
        with self.assertRaisesRegex(UnresolvedLegalState, "claim_id"):
            self.compiler.compile(self._request((a, v, p)))

    def test_12_invalid_allowed_amount_fails_closed(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "not a decimal"):
            self.compiler.compile(
                self._request(self._trio(allowed="not-money"))
            )

    def test_13_negative_allowed_amount_fails_closed(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "non-negative"):
            self.compiler.compile(self._request(self._trio(allowed="-1")))

    def test_14_missing_estate_interest_fails_closed(self):
        a, _, p = self._trio()
        v = self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("valuation_context_id", "ctx-1"),
                ("priority_snapshot_id", "stack-1"),
            ),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "estate_interest_value"):
            self.compiler.compile(self._request((a, v, p)))

    def test_15_invalid_available_value_fails_closed(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "not a decimal"):
            self.compiler.compile(
                self._request(self._trio(available="abc"))
            )

    def test_16_wrong_allowance_event_type_rejected(self):
        a, v, p = self._trio()
        with self.assertRaisesRegex(UnresolvedLegalState, "CLAIM_ALLOWANCE_EVENT"):
            self.compiler.compile(
                SecuredStatusCompileRequest(
                    request_id="x",
                    compiled_at=T3,
                    allowance=BoundDetermination(v.event_id, v.sha256),
                    valuation=BoundDetermination(a.event_id, a.sha256),
                    priority=BoundDetermination(p.event_id, p.sha256),
                    section_506a_authority=SECTION_506A,
                )
            )

    def test_17_wrong_valuation_event_type_rejected(self):
        a, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination(a.event_id, a.sha256),
            valuation=BoundDetermination(p.event_id, p.sha256),
            priority=BoundDetermination(v.event_id, v.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "VALUATION_EVENT"):
            self.compiler.compile(req)

    def test_18_hash_mismatch_fails_closed(self):
        a, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination(a.event_id, "0" * 64),
            valuation=BoundDetermination(v.event_id, v.sha256),
            priority=BoundDetermination(p.event_id, p.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "hash mismatch"):
            self.compiler.compile(req)

    def test_19_missing_event_fails_closed(self):
        a, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination("missing", "0" * 64),
            valuation=BoundDetermination(v.event_id, v.sha256),
            priority=BoundDetermination(p.event_id, p.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "does not exist"):
            self.compiler.compile(req)

    def test_20_nonfinal_input_rejected(self):
        raw = CanonicalEvent(
            event_id="raw-nonfinal",
            event_type="CLAIM_ALLOWANCE_EVENT",
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=ORDER_AUTH,
            payload=(("human_authorization_id", "x"),),
            authority_state=EventAuthorityState.NONFINAL,
        )
        self.store.append_event(raw)
        _, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination(raw.event_id, raw.sha256),
            valuation=BoundDetermination(v.event_id, v.sha256),
            priority=BoundDetermination(p.event_id, p.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "OPERATIVE or FINAL"):
            self.compiler.compile(req)

    def test_21_input_without_c4_lineage_rejected(self):
        raw = CanonicalEvent(
            event_id="manual-operative",
            event_type="CLAIM_ALLOWANCE_EVENT",
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=ORDER_AUTH,
            payload=(("claim_id", "claim-1"), ("allowed_amount", "100")),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(raw)
        _, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination(raw.event_id, raw.sha256),
            valuation=BoundDetermination(v.event_id, v.sha256),
            priority=BoundDetermination(p.event_id, p.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "human_authorization"):
            self.compiler.compile(req)

    def test_22_human_promotion_cannot_be_input_legal_authority(self):
        human = AuthorityReference(
            authority_id="h",
            authority_type="HUMAN_PROMOTION",
            citation="Human decision",
        )
        source = self._source("CLAIM_ASSERTION_EVENT")
        auth = HumanDeterminationAuthorization(
            authorization_id="human-x",
            decision=DeterminationDecision.AUTHORIZE_DETERMINATION,
            reviewer="human",
            rationale="fixture",
            issued_at=T2,
            determination_event_type="CLAIM_ALLOWANCE_EVENT",
            determination_effective_at=T1,
            determination_authority_state=EventAuthorityState.OPERATIVE,
            legal_authority=human,
            bound_assertions=(BoundAssertion(source.event_id, source.sha256),),
            determination_payload=(("claim_id", "claim-1"), ("allowed_amount", "100")),
        )
        allowance = self.gate.authorize(auth).event
        _, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination(allowance.event_id, allowance.sha256),
            valuation=BoundDetermination(v.event_id, v.sha256),
            priority=BoundDetermination(p.event_id, p.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "human promotion"):
            self.compiler.compile(req)

    def test_23_result_authority_cannot_be_human_promotion(self):
        human = AuthorityReference(
            authority_id="h",
            authority_type="HUMAN_PROMOTION",
            citation="Human decision",
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot substitute"):
            self.compiler.compile(
                self._request(self._trio(), authority=human)
            )

    def test_24_final_result_requires_all_inputs_final(self):
        trio = self._trio(
            allowance_state=EventAuthorityState.FINAL,
            valuation_state=EventAuthorityState.FINAL,
            priority_state=EventAuthorityState.OPERATIVE,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "all inputs FINAL"):
            self.compiler.compile(
                self._request(trio, state=EventAuthorityState.FINAL)
            )

    def test_25_final_result_allowed_when_all_inputs_final(self):
        trio = self._trio(
            allowance_state=EventAuthorityState.FINAL,
            valuation_state=EventAuthorityState.FINAL,
            priority_state=EventAuthorityState.FINAL,
        )
        result = self.compiler.compile(
            self._request(trio, state=EventAuthorityState.FINAL)
        )
        self.assertEqual(result.event.authority_state, EventAuthorityState.FINAL)

    def test_26_operative_result_accepts_final_inputs(self):
        trio = self._trio(
            allowance_state=EventAuthorityState.FINAL,
            valuation_state=EventAuthorityState.FINAL,
            priority_state=EventAuthorityState.FINAL,
        )
        result = self.compiler.compile(self._request(trio))
        self.assertEqual(result.event.authority_state, EventAuthorityState.OPERATIVE)

    def test_27_replay_is_idempotent(self):
        trio = self._trio()
        req = self._request(trio)
        first = self.compiler.compile(req)
        second = self.compiler.compile(req)
        self.assertFalse(first.replay_idempotent)
        self.assertTrue(second.replay_idempotent)
        self.assertEqual(first.event.event_id, second.event.event_id)

    def test_28_changed_request_id_creates_new_event(self):
        trio = self._trio()
        first = self.compiler.compile(self._request(trio, request_id="r1"))
        second = self.compiler.compile(self._request(trio, request_id="r2"))
        self.assertNotEqual(first.event.event_id, second.event.event_id)

    def test_29_input_events_are_not_mutated(self):
        trio = self._trio()
        before = tuple(e.sha256 for e in trio)
        self.compiler.compile(self._request(trio))
        after = tuple(self.store.get_event(e.event_id).sha256 for e in trio)
        self.assertEqual(before, after)

    def test_30_output_binds_exact_input_ids_and_hashes(self):
        trio = self._trio()
        result = self.compiler.compile(self._request(trio))
        payload = dict(result.event.payload)
        for e in trio:
            self.assertIn(e.event_id, payload["input_event_ids_json"])
            self.assertIn(e.sha256, payload["input_event_hashes_json"])

    def test_31_output_preserves_context_and_priority_snapshot(self):
        result = self.compiler.compile(
            self._request(self._trio(context="ctx-x", snapshot="stack-x"))
        )
        payload = dict(result.event.payload)
        self.assertEqual(payload["valuation_context_id"], "ctx-x")
        self.assertEqual(payload["priority_snapshot_id"], "stack-x")

    def test_32_output_marks_derivation_as_arithmetic(self):
        result = self.compiler.compile(self._request(self._trio()))
        self.assertEqual(
            dict(result.event.payload)["derivation_kind"],
            "ARITHMETIC_FROM_OPERATIVE_LEGAL_DETERMINATIONS",
        )

    def test_33_distinct_bound_inputs_required(self):
        a, v, p = self._trio()
        req = SecuredStatusCompileRequest(
            request_id="x",
            compiled_at=T3,
            allowance=BoundDetermination(a.event_id, a.sha256),
            valuation=BoundDetermination(a.event_id, a.sha256),
            priority=BoundDetermination(p.event_id, p.sha256),
            section_506a_authority=SECTION_506A,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "distinct events"):
            self.compiler.compile(req)

    def test_34_compile_time_requires_timezone(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "timezone"):
            self.compiler.compile(
                self._request(
                    self._trio(),
                    compiled_at=datetime(2026, 1, 21, 0, 0, 0),
                )
            )

    def test_35_compiler_does_not_call_historical_or_shadow_surfaces(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "galia2"
            / "secured_status_compiler.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden = {
            "claim_bundle",
            "mirror_claim",
            "review_claim",
            "propose_claim",
            "add_evidence",
            "authorize",
        }
        used = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertTrue(forbidden.isdisjoint(used))

    def test_36_result_authority_is_506a_authority_not_input_authority(self):
        result = self.compiler.compile(self._request(self._trio()))
        self.assertEqual(result.event.authority, SECTION_506A)
        self.assertNotEqual(result.event.authority, ORDER_AUTH)


if __name__ == "__main__":
    unittest.main()
