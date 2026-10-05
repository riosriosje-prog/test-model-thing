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
    AllocationRuleType,
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
    CushionAllocationDirective,
    Section506BCompileRequest,
    Section506BCompiler,
)

UTC = timezone.utc
T1 = datetime(2026, 1, 15, tzinfo=UTC)
T2 = datetime(2026, 1, 20, tzinfo=UTC)
T3 = datetime(2026, 1, 21, tzinfo=UTC)
T4 = datetime(2026, 1, 22, tzinfo=UTC)

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
    citation="Synthetic order",
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
SECTION_506B = AuthorityReference(
    authority_id="statute-506b",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506(b)",
    jurisdiction="US",
    effective_date=T1,
)
ALLOC_AUTH = AuthorityReference(
    authority_id="allocation-order",
    authority_type="COURT_ORDER",
    citation="Allocation Order ¶ 9",
    jurisdiction="D.P.R.",
    effective_date=T1,
)


class Section506BCompilerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.store = SecuredClaimStore(self.path)
        self.gate = SecuredClaimDeterminationGate(store=self.store)
        self.status_compiler = SecuredStatusCompiler(store=self.store)
        self.compiler = Section506BCompiler(store=self.store)
        self.counter = 0

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _source(self, event_type, *, blockers="[]"):
        self.counter += 1
        event = CanonicalEvent(
            event_id=f"src-{self.counter}",
            event_type=event_type,
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=SOURCE_AUTH,
            payload=(("blocker_codes_json", blockers),),
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
            authorization_id=f"human-{self.counter}",
            decision=DeterminationDecision.AUTHORIZE_DETERMINATION,
            reviewer="human-fixture",
            rationale="fixture legal determination",
            issued_at=T2,
            determination_event_type=det_type,
            determination_effective_at=T1,
            determination_authority_state=state,
            legal_authority=legal_authority,
            bound_assertions=(BoundAssertion(source.event_id, source.sha256),),
            determination_payload=tuple(payload),
        )
        return self.gate.authorize(auth).event

    def _secured_status(
        self,
        *,
        claim_id="claim-1",
        package="pkg-1",
        allowed="100",
        available="80",
        estate="100",
        state=EventAuthorityState.OPERATIVE,
    ):
        allowance = self._det(
            "CLAIM_ASSERTION_EVENT",
            "CLAIM_ALLOWANCE_EVENT",
            (("claim_id", claim_id), ("allowed_amount", allowed)),
            state=state,
        )
        valuation = self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", claim_id),
                ("collateral_package_id", package),
                ("valuation_context_id", "ctx-506a"),
                ("priority_snapshot_id", "stack-1"),
                ("estate_interest_value", estate),
            ),
            state=state,
        )
        priority = self._det(
            "PRIORITY_ASSERTION_EVENT",
            "LIEN_PRIORITY_EVENT",
            (
                ("claim_id", claim_id),
                ("collateral_package_id", package),
                ("priority_snapshot_id", "stack-1"),
                ("value_available_to_creditor", available),
            ),
            state=state,
        )
        req = SecuredStatusCompileRequest(
            request_id=f"status-{self.counter}",
            compiled_at=T3,
            allowance=BoundDetermination(allowance.event_id, allowance.sha256),
            valuation=BoundDetermination(valuation.event_id, valuation.sha256),
            priority=BoundDetermination(priority.event_id, priority.sha256),
            section_506a_authority=SECTION_506A,
            result_authority_state=state,
        )
        return self.status_compiler.compile(req).event

    def _valuation_506b(
        self,
        *,
        claim_id="claim-1",
        package="pkg-1",
        value="140",
        context="ctx-506b",
        state=EventAuthorityState.OPERATIVE,
    ):
        return self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", claim_id),
                ("collateral_package_id", package),
                ("valuation_context_id", context),
                ("priority_snapshot_id", "stack-506b"),
                ("valuation_purpose", "SECTION_506B"),
                ("collateral_value_for_506b", value),
            ),
            state=state,
        )

    def _recovery(
        self,
        amount="10",
        *,
        claim_id="claim-1",
        package="pkg-1",
        recovery_state="ALLOWED",
        state=EventAuthorityState.OPERATIVE,
    ):
        return self._det(
            "SECTION_506C_ASSERTION_EVENT",
            "SECTION_506C_RECOVERY_EVENT",
            (
                ("claim_id", claim_id),
                ("collateral_package_id", package),
                ("recovery_state", recovery_state),
                ("allowed_recovery_amount", amount),
            ),
            state=state,
        )

    def _component(
        self,
        component_id,
        component_type,
        amount,
        *,
        claim_id="claim-1",
        entitlement_source="AGREEMENT",
        reasonableness_state="REASONABLE",
        rate_source="CONTRACT",
        eligibility_state="ELIGIBLE",
        state=EventAuthorityState.OPERATIVE,
        legal_authority=ORDER_AUTH,
    ):
        payload = [
            ("claim_id", claim_id),
            ("component_id", component_id),
            ("component_type", component_type),
            ("eligible_amount", amount),
            ("eligibility_state", eligibility_state),
            ("accrual_start", "2026-01-15T00:00:00+00:00"),
            ("accrual_end", "2026-01-20T00:00:00+00:00"),
        ]
        if component_type == "INTEREST":
            payload.append(("rate_source", rate_source))
        else:
            payload.extend(
                [
                    ("entitlement_source", entitlement_source),
                    ("reasonableness_state", reasonableness_state),
                ]
            )
        return self._det(
            "SECTION_506B_COMPONENT_ASSERTION_EVENT",
            "SECTION_506B_COMPONENT_EVENT",
            payload,
            state=state,
            legal_authority=legal_authority,
        )

    def _directive(self, sequence, *, authority=ALLOC_AUTH, semantics="SUBSTANTIVE_PRIORITY"):
        return CushionAllocationDirective(
            rule_type=AllocationRuleType.COURT_ORDERED,
            allocation_sequence=tuple(sequence),
            allocation_semantics=semantics,
            legal_authority=authority,
        )

    def _request(
        self,
        *,
        status=None,
        valuation=None,
        recoveries=(),
        components=None,
        directive=None,
        request_id="compile-506b-1",
        state=EventAuthorityState.OPERATIVE,
        authority=SECTION_506B,
        compiled_at=T4,
    ):
        status = status or self._secured_status()
        valuation = valuation or self._valuation_506b()
        components = components or (
            self._component("interest", "INTEREST", "20"),
            self._component("fee", "FEE", "5"),
        )
        return Section506BCompileRequest(
            request_id=request_id,
            compiled_at=compiled_at,
            secured_status=BoundDetermination(status.event_id, status.sha256),
            valuation=BoundDetermination(valuation.event_id, valuation.sha256),
            recoveries_506c=tuple(
                BoundDetermination(x.event_id, x.sha256) for x in recoveries
            ),
            components=tuple(
                BoundDetermination(x.event_id, x.sha256) for x in components
            ),
            section_506b_authority=authority,
            allocation_directive=directive,
            result_authority_state=state,
        )

    def test_01_basic_oversecurity_without_506c(self):
        result = self.compiler.compile(self._request())
        payload = dict(result.oversecurity_event.payload)
        self.assertEqual(payload["net_collateral_base"], "140")
        self.assertEqual(payload["pre_506b_claim_base"], "100")
        self.assertEqual(payload["available_506b_cushion"], "40")

    def test_02_506c_recovery_reduces_net_collateral_first(self):
        result = self.compiler.compile(
            self._request(recoveries=(self._recovery("10"),))
        )
        payload = dict(result.oversecurity_event.payload)
        self.assertEqual(payload["section_506c_recovery_total"], "10")
        self.assertEqual(payload["net_collateral_base"], "130")
        self.assertEqual(payload["available_506b_cushion"], "30")

    def test_03_multiple_506c_recoveries_sum(self):
        result = self.compiler.compile(
            self._request(
                recoveries=(self._recovery("10"), self._recovery("5"))
            )
        )
        self.assertEqual(
            dict(result.oversecurity_event.payload)["section_506c_recovery_total"],
            "15",
        )

    def test_04_506c_cannot_exceed_collateral_value(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot exceed"):
            self.compiler.compile(
                self._request(recoveries=(self._recovery("150"),))
            )

    def test_05_undersecured_has_zero_cushion(self):
        result = self.compiler.compile(
            self._request(valuation=self._valuation_506b(value="90"))
        )
        payload = dict(result.oversecurity_event.payload)
        self.assertEqual(payload["available_506b_cushion"], "0")
        self.assertEqual(payload["oversecured_state"], "NOT_OVERSECURED")

    def test_06_zero_cushion_needs_no_allocation_priority(self):
        components = (
            self._component("interest", "INTEREST", "20"),
            self._component("fee", "FEE", "10"),
        )
        result = self.compiler.compile(
            self._request(
                valuation=self._valuation_506b(value="90"),
                components=components,
            )
        )
        self.assertIsNone(result.allocation_event)
        self.assertEqual(
            dict(result.accrual_event.payload)["total_506b_secured_allowance"],
            "0",
        )

    def test_07_components_fit_without_allocation_rule(self):
        result = self.compiler.compile(self._request())
        self.assertIsNone(result.allocation_event)
        payload = dict(result.accrual_event.payload)
        self.assertEqual(payload["total_eligible_components"], "25")
        self.assertEqual(payload["total_506b_secured_allowance"], "25")
        self.assertEqual(payload["cushion_remaining"], "15")

    def test_08_positive_shortfall_requires_allocation_rule(self):
        components = (
            self._component("interest", "INTEREST", "30"),
            self._component("fee", "FEE", "20"),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "allocation rule"):
            self.compiler.compile(self._request(components=components))

    def test_09_shortfall_with_authority_allocates_to_cushion_ceiling(self):
        components = (
            self._component("interest", "INTEREST", "30"),
            self._component("fee", "FEE", "20"),
        )
        result = self.compiler.compile(
            self._request(
                components=components,
                directive=self._directive(("interest", "fee")),
            )
        )
        self.assertIsNotNone(result.allocation_event)
        payload = dict(result.accrual_event.payload)
        self.assertEqual(payload["total_506b_secured_allowance"], "40")
        self.assertEqual(payload["cushion_remaining"], "0")

    def test_10_allocation_sequence_is_substantive_not_silent(self):
        components = (
            self._component("interest", "INTEREST", "30"),
            self._component("fee", "FEE", "20"),
        )
        result = self.compiler.compile(
            self._request(
                components=components,
                directive=self._directive(("fee", "interest")),
            )
        )
        alloc = dict(result.allocation_event.payload)
        self.assertEqual(alloc["allocation_semantics"], "SUBSTANTIVE_PRIORITY")
        self.assertIn('"fee","interest"', alloc["allocation_sequence_json"])

    def test_11_non_substantive_allocation_semantics_rejected(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "SUBSTANTIVE_PRIORITY"):
            self.compiler.compile(
                self._request(
                    directive=self._directive(
                        ("interest", "fee"),
                        semantics="COMPUTATIONAL_SEQUENCE",
                    )
                )
            )

    def test_12_human_promotion_cannot_supply_allocation_priority(self):
        human = AuthorityReference(
            authority_id="h",
            authority_type="HUMAN_PROMOTION",
            citation="Human decision",
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot establish"):
            self.compiler.compile(
                self._request(
                    directive=self._directive(("interest", "fee"), authority=human)
                )
            )

    def test_13_human_promotion_cannot_be_506b_authority(self):
        human = AuthorityReference(
            authority_id="h",
            authority_type="HUMAN_PROMOTION",
            citation="Human decision",
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot substitute"):
            self.compiler.compile(self._request(authority=human))

    def test_14_valuation_must_be_for_section_506b(self):
        bad = self._det(
            "VALUATION_ASSERTION_EVENT",
            "VALUATION_EVENT",
            (
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("valuation_context_id", "ctx"),
                ("priority_snapshot_id", "stack"),
                ("valuation_purpose", "CRAMDOWN"),
                ("collateral_value_for_506b", "140"),
            ),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "SECTION_506B"):
            self.compiler.compile(self._request(valuation=bad))

    def test_15_506b_valuation_claim_must_match(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "claim_id"):
            self.compiler.compile(
                self._request(valuation=self._valuation_506b(claim_id="other"))
            )

    def test_16_506b_valuation_package_must_match(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "collateral package"):
            self.compiler.compile(
                self._request(valuation=self._valuation_506b(package="pkg-2"))
            )

    def test_17_recovery_claim_must_match(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "recovery claim_id"):
            self.compiler.compile(
                self._request(recoveries=(self._recovery(claim_id="other"),))
            )

    def test_18_recovery_package_must_match(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "recovery collateral"):
            self.compiler.compile(
                self._request(recoveries=(self._recovery(package="pkg-2"),))
            )

    def test_19_recovery_must_be_allowed(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "legally ALLOWED"):
            self.compiler.compile(
                self._request(
                    recoveries=(self._recovery(recovery_state="REQUESTED"),)
                )
            )

    def test_20_component_claim_must_match(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "component claim_id"):
            self.compiler.compile(
                self._request(
                    components=(
                        self._component("interest", "INTEREST", "10", claim_id="other"),
                    )
                )
            )

    def test_21_component_must_be_eligible(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "legally ELIGIBLE"):
            self.compiler.compile(
                self._request(
                    components=(
                        self._component(
                            "interest",
                            "INTEREST",
                            "10",
                            eligibility_state="REQUESTED",
                        ),
                    )
                )
            )

    def test_22_interest_requires_rate_source(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "rate_source"):
            self.compiler.compile(
                self._request(
                    components=(
                        self._component(
                            "interest", "INTEREST", "10", rate_source=""
                        ),
                    )
                )
            )

    def test_23_fee_requires_agreement_or_state_statute(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "AGREEMENT or STATE_STATUTE"):
            self.compiler.compile(
                self._request(
                    components=(
                        self._component(
                            "fee", "FEE", "10", entitlement_source="NONE"
                        ),
                    )
                )
            )

    def test_24_fee_requires_reasonableness(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "REASONABLE"):
            self.compiler.compile(
                self._request(
                    components=(
                        self._component(
                            "fee",
                            "FEE",
                            "10",
                            reasonableness_state="NOT_DETERMINED",
                        ),
                    )
                )
            )

    def test_25_state_statute_can_support_fee_component(self):
        result = self.compiler.compile(
            self._request(
                components=(
                    self._component(
                        "fee",
                        "FEE",
                        "10",
                        entitlement_source="STATE_STATUTE",
                    ),
                )
            )
        )
        self.assertEqual(
            dict(result.accrual_event.payload)["total_506b_secured_allowance"],
            "10",
        )

    def test_26_duplicate_component_ids_rejected(self):
        components = (
            self._component("dup", "INTEREST", "10"),
            self._component("dup", "FEE", "5"),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "duplicate"):
            self.compiler.compile(self._request(components=components))

    def test_27_at_least_one_component_required(self):
        req = self._request()
        bad = Section506BCompileRequest(
            request_id=req.request_id,
            compiled_at=req.compiled_at,
            secured_status=req.secured_status,
            valuation=req.valuation,
            recoveries_506c=req.recoveries_506c,
            components=(),
            section_506b_authority=req.section_506b_authority,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "at least one"):
            self.compiler.compile(bad)

    def test_28_hash_mismatch_fails_closed(self):
        req = self._request()
        bad = Section506BCompileRequest(
            request_id=req.request_id,
            compiled_at=req.compiled_at,
            secured_status=BoundDetermination(
                req.secured_status.event_id, "0" * 64
            ),
            valuation=req.valuation,
            recoveries_506c=req.recoveries_506c,
            components=req.components,
            section_506b_authority=req.section_506b_authority,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "hash mismatch"):
            self.compiler.compile(bad)

    def test_29_manual_component_without_c4_lineage_rejected(self):
        manual = CanonicalEvent(
            event_id="manual-component",
            event_type="SECTION_506B_COMPONENT_EVENT",
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=ORDER_AUTH,
            payload=(
                ("claim_id", "claim-1"),
                ("component_id", "x"),
                ("component_type", "INTEREST"),
                ("eligible_amount", "5"),
                ("eligibility_state", "ELIGIBLE"),
                ("accrual_start", "2026-01-15T00:00:00+00:00"),
                ("accrual_end", "2026-01-20T00:00:00+00:00"),
                ("rate_source", "CONTRACT"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(manual)
        req = self._request(
            components=(manual,)
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "human_authorization"):
            self.compiler.compile(req)

    def test_30_c5_secured_status_provenance_required(self):
        manual = CanonicalEvent(
            event_id="manual-status",
            event_type="SECURED_STATUS_EVENT",
            event_effective_at=T1,
            event_recorded_at=T3,
            authority=SECTION_506A,
            payload=(
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("allowed_claim_amount", "100"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(manual)
        with self.assertRaisesRegex(UnresolvedLegalState, "c5 compiler provenance"):
            self.compiler.compile(self._request(status=manual))

    def test_31_total_secured_never_exceeds_cushion(self):
        components = (
            self._component("interest", "INTEREST", "100"),
            self._component("fee", "FEE", "100"),
        )
        result = self.compiler.compile(
            self._request(
                components=components,
                directive=self._directive(("interest", "fee")),
            )
        )
        accrual = dict(result.accrual_event.payload)
        over = dict(result.oversecurity_event.payload)
        self.assertLessEqual(
            int(accrual["total_506b_secured_allowance"]),
            int(over["available_506b_cushion"]),
        )

    def test_32_oversecurity_and_accrual_are_separate_events(self):
        result = self.compiler.compile(self._request())
        self.assertEqual(
            result.oversecurity_event.event_type,
            "OVERSECURITY_DETERMINATION",
        )
        self.assertEqual(
            result.accrual_event.event_type,
            "SECTION_506B_ACCRUAL_EVENT",
        )
        self.assertNotEqual(
            result.oversecurity_event.event_id,
            result.accrual_event.event_id,
        )

    def test_33_allocation_event_exists_only_for_positive_shortfall(self):
        fit = self.compiler.compile(self._request())
        self.assertIsNone(fit.allocation_event)
        components = (
            self._component("i2", "INTEREST", "30"),
            self._component("f2", "FEE", "20"),
        )
        short = self.compiler.compile(
            self._request(
                components=components,
                directive=self._directive(("i2", "f2")),
                request_id="short",
            )
        )
        self.assertEqual(
            short.allocation_event.event_type,
            "CUSHION_ALLOCATION_EVENT",
        )

    def test_34_exact_input_ids_and_hashes_are_bound(self):
        req = self._request(recoveries=(self._recovery("5"),))
        result = self.compiler.compile(req)
        payload = dict(result.accrual_event.payload)
        for event_id in result.input_event_ids:
            self.assertIn(event_id, payload["input_event_ids_json"])
        for digest in result.input_event_hashes:
            self.assertIn(digest, payload["input_event_hashes_json"])

    def test_35_replay_is_idempotent(self):
        req = self._request()
        first = self.compiler.compile(req)
        second = self.compiler.compile(req)
        self.assertFalse(first.replay_idempotent)
        self.assertTrue(second.replay_idempotent)
        self.assertEqual(first.accrual_event.event_id, second.accrual_event.event_id)

    def test_36_changed_request_id_creates_new_events(self):
        status = self._secured_status()
        valuation = self._valuation_506b()
        components = (
            self._component("interest", "INTEREST", "10"),
        )
        first = self.compiler.compile(
            self._request(
                status=status,
                valuation=valuation,
                components=components,
                request_id="r1",
            )
        )
        second = self.compiler.compile(
            self._request(
                status=status,
                valuation=valuation,
                components=components,
                request_id="r2",
            )
        )
        self.assertNotEqual(first.accrual_event.event_id, second.accrual_event.event_id)

    def test_37_final_result_requires_all_inputs_final(self):
        status = self._secured_status(state=EventAuthorityState.FINAL)
        valuation = self._valuation_506b(state=EventAuthorityState.FINAL)
        components = (
            self._component(
                "interest",
                "INTEREST",
                "10",
                state=EventAuthorityState.OPERATIVE,
            ),
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "all bound inputs FINAL"):
            self.compiler.compile(
                self._request(
                    status=status,
                    valuation=valuation,
                    components=components,
                    state=EventAuthorityState.FINAL,
                )
            )

    def test_38_final_result_allowed_when_all_inputs_final(self):
        status = self._secured_status(state=EventAuthorityState.FINAL)
        valuation = self._valuation_506b(state=EventAuthorityState.FINAL)
        recovery = self._recovery("5", state=EventAuthorityState.FINAL)
        component = self._component(
            "interest", "INTEREST", "10", state=EventAuthorityState.FINAL
        )
        result = self.compiler.compile(
            self._request(
                status=status,
                valuation=valuation,
                recoveries=(recovery,),
                components=(component,),
                state=EventAuthorityState.FINAL,
            )
        )
        self.assertEqual(
            result.accrual_event.authority_state,
            EventAuthorityState.FINAL,
        )

    def test_39_compile_time_requires_timezone(self):
        with self.assertRaisesRegex(UnresolvedLegalState, "timezone"):
            self.compiler.compile(
                self._request(
                    compiled_at=datetime(2026, 1, 22, 0, 0, 0)
                )
            )

    def test_40_shadow_and_determination_families_support_506b_inputs(self):
        recovery = self._recovery("5")
        component = self._component("interest", "INTEREST", "5")
        self.assertEqual(recovery.event_type, "SECTION_506C_RECOVERY_EVENT")
        self.assertEqual(component.event_type, "SECTION_506B_COMPONENT_EVENT")

    def test_41_compiler_does_not_call_historical_or_shadow_surfaces(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "galia2"
            / "section_506b_compiler.py"
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


if __name__ == "__main__":
    unittest.main()
