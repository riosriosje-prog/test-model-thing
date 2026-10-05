import os
import tempfile
import unittest
from datetime import datetime, timezone

from galia2.authority_lifecycle import (
    AuthorityLifecycleGate,
    BoundEvent,
    HumanLifecycleAuthorization,
    LifecycleDecision,
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
from galia2.section_506d_compiler import (
    RULE_506D_EXCEPTION_1,
    RULE_506D_EXCEPTION_2,
    RULE_506D_VOID,
    RULE_ALLOWED_LIEN,
    RULE_CAULKETT,
    RULE_CHAPTER_SPECIFIC,
    RULE_DEWSNUP,
    RULE_NONBANKRUPTCY_NO_LIEN,
    Section506DCompileRequest,
    Section506DCompiler,
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
    citation="Synthetic determination order",
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
SECTION_506D = AuthorityReference(
    authority_id="statute-506d",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506(d)",
    jurisdiction="US",
    effective_date=T1,
)
DEWSNUP_AUTH = AuthorityReference(
    authority_id="dewsnup",
    authority_type="SUPREME_COURT_PRECEDENT",
    citation="Dewsnup v. Timm, 502 U.S. 410 (1992)",
    jurisdiction="US",
    effective_date=T1,
)
CAULKETT_AUTH = AuthorityReference(
    authority_id="caulkett",
    authority_type="SUPREME_COURT_PRECEDENT",
    citation="Bank of America v. Caulkett, 575 U.S. 790 (2015)",
    jurisdiction="US",
    effective_date=T1,
)
CHAPTER_AUTH = AuthorityReference(
    authority_id="chapter-specific",
    authority_type="STATUTE_PRECEDENT",
    citation="Chapter-specific treatment authority",
    jurisdiction="US",
    effective_date=T1,
)
PROPERTY_AUTH = AuthorityReference(
    authority_id="property-law",
    authority_type="STATE_LAW_DETERMINATION",
    citation="Applicable nonbankruptcy property law",
    jurisdiction="PR",
    effective_date=T1,
)
LIFECYCLE_AUTH = AuthorityReference(
    authority_id="stay-order",
    authority_type="COURT_ORDER",
    citation="Synthetic stay order",
    jurisdiction="D.P.R.",
    effective_date=T4,
)


class Section506DCompilerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.store = SecuredClaimStore(self.path)
        self.det_gate = SecuredClaimDeterminationGate(store=self.store)
        self.status_compiler = SecuredStatusCompiler(store=self.store)
        self.lifecycle = AuthorityLifecycleGate(store=self.store)
        self.compiler = Section506DCompiler(store=self.store)
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
        authority=ORDER_AUTH,
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
            legal_authority=authority,
            bound_assertions=(BoundAssertion(source.event_id, source.sha256),),
            determination_payload=tuple(payload),
        )
        return self.det_gate.authorize(auth).event

    def _lien(
        self,
        *,
        claim_id="claim-1",
        lien_id="lien-1",
        package="pkg-1",
        lien_state="EXISTS",
        perfection="PERFECTED",
        state=EventAuthorityState.OPERATIVE,
    ):
        return self._det(
            "LIEN_EXISTENCE_ASSERTION_EVENT",
            "LIEN_EXISTENCE_EVENT",
            (
                ("claim_id", claim_id),
                ("lien_id", lien_id),
                ("collateral_package_id", package),
                ("lien_property_interest_state", lien_state),
                ("perfection_state", perfection),
                ("applicable_nonbankruptcy_law", "Puerto Rico law"),
                ("property_interest_basis", "recorded mortgage / fixture basis"),
            ),
            state=state,
            authority=PROPERTY_AUTH,
        )

    def _claim_status(
        self,
        allowance_state,
        *,
        claim_id="claim-1",
        basis=None,
        state=EventAuthorityState.OPERATIVE,
    ):
        payload = [
            ("claim_id", claim_id),
            ("allowance_state", allowance_state),
        ]
        if basis is not None:
            payload.append(("disallowance_basis_code", basis))
        return self._det(
            "CLAIM_STATUS_ASSERTION_EVENT",
            "CLAIM_STATUS_EVENT",
            payload,
            state=state,
        )

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

    def _request(
        self,
        lien,
        claim,
        *,
        status=None,
        chapter=7,
        rule_code=RULE_DEWSNUP,
        rule_authority=DEWSNUP_AUTH,
        section_authority=SECTION_506D,
        request_id="506d-1",
        state=EventAuthorityState.OPERATIVE,
        compiled_at=T4,
    ):
        return Section506DCompileRequest(
            request_id=request_id,
            compiled_at=compiled_at,
            chapter=chapter,
            lien_existence=BoundDetermination(lien.event_id, lien.sha256),
            claim_status=BoundDetermination(claim.event_id, claim.sha256),
            secured_status=(
                BoundDetermination(status.event_id, status.sha256)
                if status is not None else None
            ),
            section_506d_authority=section_authority,
            rule_basis_code=rule_code,
            rule_authority=rule_authority,
            result_authority_state=state,
        )

    def _stay(self, event):
        self.counter += 1
        auth = HumanLifecycleAuthorization(
            authorization_id=f"life-{self.counter}",
            decision=LifecycleDecision.AUTHORIZE_STATE_TRANSITION,
            reviewer="human-fixture",
            rationale="fixture stay",
            issued_at=T5,
            transition_effective_at=T4,
            target=BoundEvent(event.event_id, event.sha256),
            expected_current_state=event.authority_state,
            to_state=EventAuthorityState.STAYED,
            legal_authority=LIFECYCLE_AUTH,
        )
        return self.lifecycle.authorize(auth).event

    def test_01_no_lien_property_interest_does_not_reach_506d(self):
        lien = self._lien(lien_state="DOES_NOT_EXIST", perfection="NOT_APPLICABLE")
        claim = self._claim_status("ALLOWED")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=None,
                rule_code=RULE_NONBANKRUPTCY_NO_LIEN,
                rule_authority=PROPERTY_AUTH,
            )
        )
        payload = dict(result.event.payload)
        self.assertEqual(result.consequence_code, "NO_LIEN_PROPERTY_INTEREST")
        self.assertEqual(payload["section_506d_effect"], "NOT_REACHED")

    def test_02_no_lien_path_rejects_secured_status(self):
        lien = self._lien(lien_state="DOES_NOT_EXIST", perfection="NOT_APPLICABLE")
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        with self.assertRaisesRegex(UnresolvedLegalState, "must be absent"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=status,
                    rule_code=RULE_NONBANKRUPTCY_NO_LIEN,
                    rule_authority=PROPERTY_AUTH,
                )
            )

    def test_03_ch7_partial_undersecurity_is_dewsnup_no_strip_down(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="80")
        result = self.compiler.compile(
            self._request(lien, claim, status=status)
        )
        self.assertEqual(
            result.consequence_code,
            "NO_506D_STRIP_DOWN_CH7_ALLOWED_CLAIM",
        )

    def test_04_ch7_zero_secured_portion_is_caulkett_no_strip_off(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="0")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                rule_code=RULE_CAULKETT,
                rule_authority=CAULKETT_AUTH,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "NO_506D_STRIP_OFF_CH7_ALLOWED_CLAIM",
        )
        self.assertEqual(dict(result.event.payload)["secured_portion_506a"], "0")

    def test_05_ch7_fully_secured_lien_is_unaffected(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="80", available="80")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                rule_code=RULE_ALLOWED_LIEN,
                rule_authority=SECTION_506D,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "LIEN_UNAFFECTED_BY_506D_ALLOWED_FULLY_SECURED",
        )

    def test_06_ch11_allowed_claim_requires_chapter_specific_path(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                chapter=11,
                rule_code=RULE_CHAPTER_SPECIFIC,
                rule_authority=CHAPTER_AUTH,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "NO_AUTOMATIC_506D_CONSEQUENCE_CHAPTER_11",
        )

    def test_07_ch13_allowed_claim_requires_chapter_specific_path(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                chapter=13,
                rule_code=RULE_CHAPTER_SPECIFIC,
                rule_authority=CHAPTER_AUTH,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "NO_AUTOMATIC_506D_CONSEQUENCE_CHAPTER_13",
        )

    def test_08_disallowed_other_basis_voids_lien_to_extent(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=None,
                rule_code=RULE_506D_VOID,
                rule_authority=SECTION_506D,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "LIEN_VOID_TO_EXTENT_CLAIM_DISALLOWED",
        )

    def test_09_502b5_disallowance_hits_exception_1(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="502B5")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=None,
                rule_code=RULE_506D_EXCEPTION_1,
                rule_authority=SECTION_506D,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "LIEN_NOT_VOIDED_506D_EXCEPTION_1",
        )

    def test_10_502e_disallowance_hits_exception_1(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="502E")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=None,
                rule_code=RULE_506D_EXCEPTION_1,
                rule_authority=SECTION_506D,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "LIEN_NOT_VOIDED_506D_EXCEPTION_1",
        )

    def test_11_no_proof_only_hits_exception_2(self):
        lien = self._lien()
        claim = self._claim_status("NOT_ALLOWED_DUE_ONLY_TO_NO_PROOF")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=None,
                rule_code=RULE_506D_EXCEPTION_2,
                rule_authority=SECTION_506D,
            )
        )
        self.assertEqual(
            result.consequence_code,
            "LIEN_NOT_VOIDED_506D_EXCEPTION_2",
        )

    def test_12_rule_basis_mismatch_fails_closed(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="0")
        with self.assertRaisesRegex(UnresolvedLegalState, "rule_basis_code mismatch"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=status,
                    rule_code=RULE_DEWSNUP,
                    rule_authority=DEWSNUP_AUTH,
                )
            )

    def test_13_human_promotion_cannot_be_506d_authority(self):
        human = AuthorityReference(
            authority_id="human",
            authority_type="HUMAN_PROMOTION",
            citation="Prom",
        )
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot substitute"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                    section_authority=human,
                )
            )

    def test_14_human_promotion_cannot_be_rule_authority(self):
        human = AuthorityReference(
            authority_id="human",
            authority_type="HUMAN_PROMOTION",
            citation="Prom",
        )
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot substitute"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=human,
                )
            )

    def test_15_lien_and_claim_status_claim_id_must_match(self):
        lien = self._lien(claim_id="claim-1")
        claim = self._claim_status("DISALLOWED", claim_id="claim-2", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "claim_id must match"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_16_secured_status_package_must_match_lien(self):
        lien = self._lien(package="pkg-1")
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(package="pkg-2")
        with self.assertRaisesRegex(UnresolvedLegalState, "collateral package"):
            self.compiler.compile(self._request(lien, claim, status=status))

    def test_17_invalid_lien_state_fails_closed(self):
        lien = self._lien(lien_state="DISPUTED")
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "EXISTS or DOES_NOT_EXIST"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_18_invalid_perfection_state_fails_closed(self):
        lien = self._lien(perfection="UNDETERMINED")
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "perfection_state"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_19_disallowed_claim_requires_basis(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED")
        with self.assertRaisesRegex(UnresolvedLegalState, "disallowance_basis_code"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_20_non_disallowed_claim_cannot_carry_disallowance_basis(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED", basis="OTHER")
        status = self._secured_status()
        with self.assertRaisesRegex(UnresolvedLegalState, "only when DISALLOWED"):
            self.compiler.compile(self._request(lien, claim, status=status))

    def test_21_allowed_existing_lien_requires_secured_status(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        with self.assertRaisesRegex(UnresolvedLegalState, "requires bound"):
            self.compiler.compile(
                self._request(lien, claim, status=None)
            )

    def test_22_disallowed_claim_rejects_secured_status(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        status = self._secured_status()
        with self.assertRaisesRegex(UnresolvedLegalState, "permitted only"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=status,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_23_manual_lien_event_without_c4_lineage_rejected(self):
        lien = CanonicalEvent(
            event_id="manual-lien",
            event_type="LIEN_EXISTENCE_EVENT",
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=PROPERTY_AUTH,
            payload=(
                ("claim_id", "claim-1"),
                ("lien_id", "lien-1"),
                ("collateral_package_id", "pkg-1"),
                ("lien_property_interest_state", "EXISTS"),
                ("perfection_state", "PERFECTED"),
                ("applicable_nonbankruptcy_law", "Puerto Rico law"),
                ("property_interest_basis", "manual"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(lien)
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "human_authorization"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_24_manual_claim_status_without_c4_lineage_rejected(self):
        lien = self._lien()
        claim = CanonicalEvent(
            event_id="manual-claim-status",
            event_type="CLAIM_STATUS_EVENT",
            event_effective_at=T1,
            event_recorded_at=T2,
            authority=ORDER_AUTH,
            payload=(
                ("claim_id", "claim-1"),
                ("allowance_state", "DISALLOWED"),
                ("disallowance_basis_code", "OTHER"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(claim)
        with self.assertRaisesRegex(UnresolvedLegalState, "human_authorization"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_25_manual_secured_status_without_c5_provenance_rejected(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = CanonicalEvent(
            event_id="manual-status",
            event_type="SECURED_STATUS_EVENT",
            event_effective_at=T1,
            event_recorded_at=T3,
            authority=SECTION_506A,
            payload=(
                ("claim_id", "claim-1"),
                ("collateral_package_id", "pkg-1"),
                ("allowed_claim_amount", "100"),
                ("secured_portion", "80"),
            ),
            authority_state=EventAuthorityState.OPERATIVE,
        )
        self.store.append_event(status)
        with self.assertRaisesRegex(UnresolvedLegalState, "compiler_version"):
            self.compiler.compile(self._request(lien, claim, status=status))

    def test_26_effectively_stayed_lien_is_rejected(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        self._stay(lien)
        with self.assertRaisesRegex(UnresolvedLegalState, "STAYED"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_27_effectively_stayed_claim_status_is_rejected(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        self._stay(claim)
        with self.assertRaisesRegex(UnresolvedLegalState, "STAYED"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_28_effectively_stayed_secured_status_is_rejected(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        self._stay(status)
        with self.assertRaisesRegex(UnresolvedLegalState, "STAYED"):
            self.compiler.compile(self._request(lien, claim, status=status))

    def test_29_compile_hash_binds_lifecycle_tail(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        first = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                request_id="same",
            )
        ).event
        stay = self._stay(claim)
        self.counter += 1
        lift = HumanLifecycleAuthorization(
            authorization_id=f"life-{self.counter}",
            decision=LifecycleDecision.AUTHORIZE_STATE_TRANSITION,
            reviewer="human-fixture",
            rationale="lift stay",
            issued_at=T5,
            transition_effective_at=T5,
            target=BoundEvent(claim.event_id, claim.sha256),
            expected_current_state=EventAuthorityState.STAYED,
            to_state=EventAuthorityState.OPERATIVE,
            legal_authority=LIFECYCLE_AUTH,
            prior_transition=BoundEvent(stay.event_id, stay.sha256),
        )
        self.lifecycle.authorize(lift)
        second = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                request_id="same",
            )
        ).event
        self.assertNotEqual(first.event_id, second.event_id)

    def test_30_final_result_requires_all_inputs_final(self):
        lien = self._lien(state=EventAuthorityState.FINAL)
        claim = self._claim_status("ALLOWED", state=EventAuthorityState.FINAL)
        status = self._secured_status(state=EventAuthorityState.OPERATIVE)
        with self.assertRaisesRegex(UnresolvedLegalState, "all bound inputs FINAL"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=status,
                    state=EventAuthorityState.FINAL,
                )
            )

    def test_31_final_result_allowed_when_all_inputs_final(self):
        lien = self._lien(state=EventAuthorityState.FINAL)
        claim = self._claim_status("ALLOWED", state=EventAuthorityState.FINAL)
        status = self._secured_status(state=EventAuthorityState.FINAL)
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                state=EventAuthorityState.FINAL,
            )
        )
        self.assertEqual(result.event.authority_state, EventAuthorityState.FINAL)

    def test_32_output_binds_exact_input_ids_hashes_and_lifecycle(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        result = self.compiler.compile(self._request(lien, claim, status=status))
        payload = dict(result.event.payload)
        for event in (lien, claim, status):
            self.assertIn(event.event_id, payload["input_event_ids_json"])
            self.assertIn(event.sha256, payload["input_event_hashes_json"])
        self.assertIn("input_lifecycle_bindings_json", payload)

    def test_33_exact_replay_is_idempotent(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        req = self._request(lien, claim, status=status)
        first = self.compiler.compile(req)
        second = self.compiler.compile(req)
        self.assertFalse(first.replay_idempotent)
        self.assertTrue(second.replay_idempotent)
        self.assertEqual(first.event.event_id, second.event.event_id)

    def test_34_changed_request_id_creates_new_event(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        first = self.compiler.compile(
            self._request(lien, claim, status=status, request_id="a")
        )
        second = self.compiler.compile(
            self._request(lien, claim, status=status, request_id="b")
        )
        self.assertNotEqual(first.event.event_id, second.event.event_id)

    def test_35_input_events_are_not_mutated(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        before = tuple(x.sha256 for x in (lien, claim, status))
        self.compiler.compile(self._request(lien, claim, status=status))
        after = tuple(
            self.store.get_event(x.event_id).sha256
            for x in (lien, claim, status)
        )
        self.assertEqual(before, after)

    def test_36_rule_authority_is_event_authority(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="0")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                rule_code=RULE_CAULKETT,
                rule_authority=CAULKETT_AUTH,
            )
        )
        self.assertEqual(result.event.authority, CAULKETT_AUTH)
        self.assertIn(
            "11 U.S.C. § 506(d)",
            dict(result.event.payload)["section_506d_authority_json"],
        )

    def test_37_unsupported_chapter_fails_closed(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status()
        with self.assertRaisesRegex(UnresolvedLegalState, "Chapter 7, 11, and 13"):
            self.compiler.compile(
                self._request(lien, claim, status=status, chapter=12)
            )

    def test_38_compile_time_requires_timezone(self):
        lien = self._lien()
        claim = self._claim_status("DISALLOWED", basis="OTHER")
        with self.assertRaisesRegex(UnresolvedLegalState, "timezone"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                    compiled_at=datetime(2026, 1, 22, 0, 0, 0),
                )
            )

    def test_39_output_preserves_506a_metrics_without_using_them_as_strip(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="0")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=status,
                rule_code=RULE_CAULKETT,
                rule_authority=CAULKETT_AUTH,
            )
        )
        payload = dict(result.event.payload)
        self.assertEqual(payload["allowed_claim_amount"], "100")
        self.assertEqual(payload["secured_portion_506a"], "0")
        self.assertEqual(payload["section_506d_effect"], "NO_STRIP")

    def test_40_unperfected_existing_lien_is_not_auto_voided_by_c8(self):
        lien = self._lien(perfection="UNPERFECTED")
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="80")
        result = self.compiler.compile(self._request(lien, claim, status=status))
        payload = dict(result.event.payload)
        self.assertEqual(payload["perfection_state"], "UNPERFECTED")
        self.assertEqual(payload["section_506d_effect"], "NO_STRIP")

    def test_41_no_proof_exception_never_requires_secured_status(self):
        lien = self._lien()
        claim = self._claim_status("NOT_ALLOWED_DUE_ONLY_TO_NO_PROOF")
        result = self.compiler.compile(
            self._request(
                lien,
                claim,
                status=None,
                rule_code=RULE_506D_EXCEPTION_2,
                rule_authority=SECTION_506D,
            )
        )
        self.assertEqual(
            dict(result.event.payload)["claim_allowance_state"],
            "NOT_ALLOWED_DUE_ONLY_TO_NO_PROOF",
        )

    def test_42_duplicate_bound_event_ids_fail_closed(self):
        lien = self._lien()
        req = Section506DCompileRequest(
            request_id="dup",
            compiled_at=T4,
            chapter=7,
            lien_existence=BoundDetermination(lien.event_id, lien.sha256),
            claim_status=BoundDetermination(lien.event_id, lien.sha256),
            secured_status=None,
            section_506d_authority=SECTION_506D,
            rule_basis_code=RULE_506D_VOID,
            rule_authority=SECTION_506D,
        )
        with self.assertRaisesRegex(UnresolvedLegalState, "unique"):
            self.compiler.compile(req)

    def test_43_claim_status_unknown_state_fails_closed(self):
        lien = self._lien()
        claim = self._claim_status("UNDETERMINED")
        with self.assertRaisesRegex(UnresolvedLegalState, "allowance_state"):
            self.compiler.compile(
                self._request(
                    lien,
                    claim,
                    status=None,
                    rule_code=RULE_506D_VOID,
                    rule_authority=SECTION_506D,
                )
            )

    def test_44_secured_portion_cannot_exceed_allowed_amount(self):
        lien = self._lien()
        claim = self._claim_status("ALLOWED")
        status = self._secured_status(allowed="100", available="100")
        payload = list(status.payload)
        payload = [
            (k, "101") if k == "secured_portion" else (k, v)
            for k, v in payload
        ]
        forged = CanonicalEvent(
            event_id="forged-status",
            event_type=status.event_type,
            event_effective_at=status.event_effective_at,
            event_recorded_at=status.event_recorded_at,
            authority=status.authority,
            payload=tuple(payload),
            authority_state=status.authority_state,
        )
        self.store.append_event(forged)
        with self.assertRaisesRegex(UnresolvedLegalState, "cannot exceed"):
            self.compiler.compile(
                self._request(lien, claim, status=forged)
            )


if __name__ == "__main__":
    unittest.main()
