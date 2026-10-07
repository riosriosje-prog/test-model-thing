import unittest
from datetime import datetime, timezone

from galia2.secured_claims import (
    AllocationRuleType,
    AuthorityReference,
    CanonicalEvent,
    CanonicalEventStore,
    ClaimComponent,
    ComponentType,
    DuplicateEventConflict,
    EventAuthorityState,
    LienPosition,
    PriorityState,
    UnresolvedLegalState,
    ValuationContext,
    ValuationEvent,
    allocate_506b_components,
    classify_secured_claim,
    lien_waterfall,
    make_snapshot,
    money,
    section_506b_cushion,
    valuation_context_equivalent,
)

UTC = timezone.utc
T1 = datetime(2026, 1, 1, tzinfo=UTC)
T2 = datetime(2026, 2, 1, tzinfo=UTC)
AUTH = AuthorityReference(
    authority_id="auth-506",
    authority_type="STATUTE",
    citation="11 U.S.C. § 506",
    jurisdiction="US",
)

def ctx(**overrides):
    data = dict(
        statutory_basis="11 U.S.C. § 506(a)",
        chapter=11,
        valuation_purpose="CRAMDOWN",
        legal_effective_date=T1,
        determination_date=T2,
        evidence_observation_date=T2,
        proposed_disposition="RETAIN",
        proposed_use="OPERATING_ASSET",
        collateral_scope="asset-1",
        creditor_interest_scope="lien-1",
        priority_snapshot_id="stack-1",
        valuation_standard="REPLACEMENT_VALUE",
    )
    data.update(overrides)
    return ValuationContext(**data)

class SecuredClaimKernelTests(unittest.TestCase):
    def test_01_debt_and_allowed_claim_are_not_forced_equal(self):
        c = classify_secured_claim(
            allowed_claim_amount=money("90"), creditor_interest_value=money("80")
        )
        self.assertEqual(c.allowed_claim_amount, money("90"))

    def test_02_allowance_and_secured_classification_are_distinct(self):
        c = classify_secured_claim(
            allowed_claim_amount=money("100"), creditor_interest_value=money("60")
        )
        self.assertEqual(c.secured_portion, money("60"))
        self.assertEqual(c.unsecured_deficiency, money("40"))

    def test_03_fully_secured_claim(self):
        c = classify_secured_claim(
            allowed_claim_amount=money("100"), creditor_interest_value=money("150")
        )
        self.assertEqual(c.secured_portion, money("100"))
        self.assertEqual(c.unsecured_deficiency, money("0"))

    def test_04_valuation_context_same_question_equivalent(self):
        self.assertTrue(valuation_context_equivalent(ctx(), ctx()))

    def test_05_valuation_purpose_difference_not_equivalent(self):
        self.assertFalse(
            valuation_context_equivalent(ctx(), ctx(valuation_purpose="STAY_RELIEF"))
        )

    def test_06_effective_date_difference_breaks_equivalence(self):
        self.assertFalse(
            valuation_context_equivalent(ctx(), ctx(legal_effective_date=T2))
        )

    def test_07_determination_date_alone_does_not_break_legal_question(self):
        later = datetime(2026, 3, 1, tzinfo=UTC)
        self.assertTrue(
            valuation_context_equivalent(ctx(), ctx(determination_date=later))
        )

    def test_08_valuation_validates_three_time_fields_independently(self):
        v = ValuationEvent(
            "val-1", "asset-1", "creditor-1", ctx(),
            money("100"), money("80"), money("60"), AUTH,
        )
        v.validate()
        self.assertNotEqual(v.context.legal_effective_date, v.context.determination_date)

    def test_09_creditor_interest_cannot_exceed_estate_interest(self):
        v = ValuationEvent(
            "val-1", "asset-1", "creditor-1", ctx(),
            money("100"), money("80"), money("90"), AUTH,
        )
        with self.assertRaises(ValueError):
            v.validate()

    def test_10_506b_cushion_is_noncircular(self):
        self.assertEqual(
            section_506b_cushion(
                net_collateral_for_506b=money("125"),
                pre_506b_claim_base=money("100"),
            ),
            money("25"),
        )

    def test_11_no_oversecurity_means_zero_cushion(self):
        self.assertEqual(
            section_506b_cushion(
                net_collateral_for_506b=money("90"),
                pre_506b_claim_base=money("100"),
            ),
            money("0"),
        )

    def test_12_components_all_fit_without_priority_rule(self):
        comps = (
            ClaimComponent("i", ComponentType.INTEREST, money("10")),
            ClaimComponent("f", ComponentType.FEE, money("5")),
        )
        out = allocate_506b_components(components=comps, cushion=money("20"))
        self.assertEqual(sum(x.secured_amount for x in out), money("15"))

    def test_13_insufficient_cushion_has_no_silent_priority(self):
        comps = (
            ClaimComponent("i", ComponentType.INTEREST, money("10")),
            ClaimComponent("f", ComponentType.FEE, money("10")),
        )
        with self.assertRaises(UnresolvedLegalState):
            allocate_506b_components(components=comps, cushion=money("12"))

    def test_14_authority_backed_sequence_can_allocate_short_cushion(self):
        comps = (
            ClaimComponent("i", ComponentType.INTEREST, money("10")),
            ClaimComponent("f", ComponentType.FEE, money("10")),
        )
        out = allocate_506b_components(
            components=comps,
            cushion=money("12"),
            rule_type=AllocationRuleType.COURT_ORDERED,
            allocation_sequence=("i", "f"),
        )
        by_id = {x.component_id: x.secured_amount for x in out}
        self.assertEqual(by_id, {"i": money("10"), "f": money("2")})

    def test_15_allocation_sequence_must_cover_all_components(self):
        comps = (
            ClaimComponent("i", ComponentType.INTEREST, money("10")),
            ClaimComponent("f", ComponentType.FEE, money("10")),
        )
        with self.assertRaises(ValueError):
            allocate_506b_components(
                components=comps,
                cushion=money("12"),
                rule_type=AllocationRuleType.COURT_ORDERED,
                allocation_sequence=("i",),
            )

    def test_16_senior_junior_waterfall(self):
        liens = (
            LienPosition("l1", "c1", money("80"), 1, PriorityState.SENIOR),
            LienPosition("l2", "c2", money("50"), 2, PriorityState.JUNIOR),
        )
        out = lien_waterfall(estate_interest_value=money("100"), liens=liens)
        self.assertEqual(out[0].secured_amount, money("80"))
        self.assertEqual(out[1].secured_amount, money("20"))

    def test_17_junior_deficiency_increases_when_value_is_consumed(self):
        liens = (
            LienPosition("l1", "c1", money("90"), 1, PriorityState.SENIOR),
            LienPosition("l2", "c2", money("40"), 2, PriorityState.JUNIOR),
        )
        out = lien_waterfall(estate_interest_value=money("100"), liens=liens)
        self.assertEqual(out[1].unsecured_deficiency, money("30"))

    def test_18_disputed_priority_fails_closed(self):
        liens = (LienPosition("l1", "c1", money("80"), 1, PriorityState.DISPUTED),)
        with self.assertRaises(UnresolvedLegalState):
            lien_waterfall(estate_interest_value=money("100"), liens=liens)

    def test_19_undetermined_priority_fails_closed(self):
        liens = (
            LienPosition("l1", "c1", money("80"), 1, PriorityState.UNDETERMINED),
        )
        with self.assertRaises(UnresolvedLegalState):
            lien_waterfall(estate_interest_value=money("100"), liens=liens)

    def test_20_pari_passu_shortfall_needs_rule(self):
        liens = (
            LienPosition("l1", "c1", money("80"), 1, PriorityState.PARI_PASSU),
            LienPosition("l2", "c2", money("20"), 1, PriorityState.PARI_PASSU),
        )
        with self.assertRaises(UnresolvedLegalState):
            lien_waterfall(estate_interest_value=money("50"), liens=liens)

    def test_21_pari_passu_explicit_pro_rata_rule(self):
        liens = (
            LienPosition(
                "l1", "c1", money("80"), 1, PriorityState.PARI_PASSU,
                pari_passu_rule="PRO_RATA_BY_ALLOWED_AMOUNT",
            ),
            LienPosition(
                "l2", "c2", money("20"), 1, PriorityState.PARI_PASSU,
                pari_passu_rule="PRO_RATA_BY_ALLOWED_AMOUNT",
            ),
        )
        out = lien_waterfall(estate_interest_value=money("50"), liens=liens)
        self.assertEqual(out[0].secured_amount, money("40"))
        self.assertEqual(out[1].secured_amount, money("10"))

    def test_22_canonical_event_is_frozen(self):
        e = CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH)
        with self.assertRaises(Exception):
            e.event_type = "MUTATED"

    def test_23_event_store_idempotent_replay(self):
        s = CanonicalEventStore()
        e = CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH)
        s.append(e); s.append(e)
        self.assertEqual(len(s.events()), 1)

    def test_24_event_id_conflict_rejected(self):
        s = CanonicalEventStore()
        s.append(CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH))
        with self.assertRaises(DuplicateEventConflict):
            s.append(CanonicalEvent("e1", "VALUATION", T1, T2, AUTH))

    def test_25_supersession_requires_existing_event(self):
        s = CanonicalEventStore()
        with self.assertRaises(UnresolvedLegalState):
            s.append(
                CanonicalEvent(
                    "e2", "RECONSIDERATION", T2, T2, AUTH,
                    supersedes_event_id="missing",
                )
            )

    def test_26_supersession_preserves_old_event(self):
        s = CanonicalEventStore()
        old = CanonicalEvent("e1", "ALLOWANCE", T1, T1, AUTH)
        new = CanonicalEvent(
            "e2", "RECONSIDERATION", T2, T2, AUTH, supersedes_event_id="e1"
        )
        s.append(old); s.append(new)
        self.assertEqual(len(s.events()), 2)
        self.assertEqual(s.get("e1").event_type, "ALLOWANCE")

    def test_27_event_hash_is_deterministic(self):
        a = CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH)
        b = CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH)
        self.assertEqual(a.sha256, b.sha256)

    def test_28_authority_state_is_separate_from_event_identity(self):
        e = CanonicalEvent(
            "e1", "SALE", T1, T2, AUTH,
            authority_state=EventAuthorityState.APPEAL_PENDING,
        )
        self.assertEqual(e.authority_state, EventAuthorityState.APPEAL_PENDING)

    def test_29_snapshot_requires_lineage(self):
        with self.assertRaises(UnresolvedLegalState):
            make_snapshot(
                snapshot_type="CLAIM_STATE",
                as_of=T2,
                purpose="§506(b)",
                source_events=(),
                calculation_version="c1",
                values={"secured": "10"},
            )

    def test_30_snapshot_records_source_event_ids(self):
        e = CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH)
        snap = make_snapshot(
            snapshot_type="CLAIM_STATE",
            as_of=T2,
            purpose="§506(b)",
            source_events=(e,),
            calculation_version="c1",
            values={"secured": "10"},
        )
        self.assertEqual(snap.source_event_ids, ("e1",))

    def test_31_snapshot_is_derived_not_source_mutation(self):
        e = CanonicalEvent("e1", "ALLOWANCE", T1, T2, AUTH)
        snap = make_snapshot(
            snapshot_type="CLAIM_STATE",
            as_of=T2,
            purpose="PLAN",
            source_events=(e,),
            calculation_version="c1",
            values={"plan_secured_amount": "100"},
        )
        self.assertEqual(e.event_type, "ALLOWANCE")
        self.assertEqual(dict(snap.values)["plan_secured_amount"], "100")

    def test_32_missing_material_context_fails_closed(self):
        with self.assertRaises(UnresolvedLegalState):
            ctx(valuation_purpose="").validate()

if __name__ == "__main__":
    unittest.main()
