import unittest
from dataclasses import replace
from datetime import datetime, timezone

from galia2.authority import AuthorityScope, PromotionAuthorization
from galia2.core import Receipt
from galia2.persistence import PromotionEnvelope
from galia2.preflight import PreflightCheck, PreflightReport
from galia2.reconciliation_authority_binding import ReconciliationAuthorityBinding
from galia2.reconciled_authority_provenance import seal_provenance

NOW = datetime(2026, 10, 7, 16, 0, tzinfo=timezone.utc)
H1, H2, H3 = "1"*64, "2"*64, "3"*64

def scope():
    return AuthorityScope("CASE-1", "CLAIM", ("CLAIM-1",))

def binding(**kw):
    v=dict(schema_version="GALIA-F23-RECONCILIATION-AUTHORITY-BINDING/1",
      reconciliation_sha256=H1,candidate_set_sha256=H2,conflict_component_sha256=H3,
      selected_candidate_id="A",provider_id="P",external_scope="receipt-signing",
      p5_scope_token=scope().token)
    v.update(kw); return ReconciliationAuthorityBinding(**v)

def authorization(**kw):
    v=dict(authorization_id="auth-1",decision_id="decision-1",reviewer="human",
      scope=scope(),target_commit="candidate-1",evidence_snapshot=("e1",),
      policy_version="p5",authorized_at=NOW)
    v.update(kw); return PromotionAuthorization(**v)

def preflight(receipt_id="pf-1"):
    return PreflightReport(case_id="CASE-1",target_commit="candidate-1",passed=True,
      checks=(PreflightCheck("all",True,"fixture"),),
      guards=frozenset({"preflight_passed","rollback_target_verified"}),
      receipt=Receipt(receipt_id=receipt_id,operation="PROMOTION_PREFLIGHT",
        input_commit="candidate-1",input_hashes=(),output_commit=None,output_hashes=(),
        policy_version="p6",actor="test",timestamp=NOW,result="PASS"))

def promotion(**kw):
    v=dict(commit_id="candidate-1",case_id="CASE-1",manifest_hash="4"*64,
      authority_decision_id="decision-1",authorization_id="auth-1",
      authorization_policy_version="p5",preflight_receipt_id="pf-1",
      persistence_policy_version="p7",published_at=NOW)
    v.update(kw); return PromotionEnvelope(**v)

def seal(b=None,a=None,pf=None,p=None,decision="decision-1"):
    return seal_provenance(binding=b or binding(),authorization=a or authorization(),
      preflight=pf or preflight(),promotion=p or promotion(),
      expected_authority_decision_id=decision)

class TestF24ReconciledAuthorityProvenance(unittest.TestCase):
    def test_seals_exact_chain_without_authority_escalation(self):
        out=seal()
        self.assertEqual(out.reconciliation_sha256,H1)
        self.assertEqual(out.authorization_id,"auth-1")
        self.assertEqual(out.preflight_receipt_id,"pf-1")
        self.assertEqual(out.promotion_envelope_sha256,promotion().sha256)
        self.assertEqual(out.authority_class,"EXTERNAL_AUTHORITY_ONLY")
        self.assertEqual(out.master_promotion_state,"AUTHORITY_HOLD")
        self.assertEqual(out.canonical_effect,"NONE")
        self.assertEqual(out.byte_identity_effect,"NONE")
        self.assertEqual(out.f5_effect,"NONE")
        self.assertEqual(out.sha256,out.sha256)

    def test_scope_mismatch_fails_closed(self):
        other=AuthorityScope("CASE-1","CLAIM",("OTHER",))
        with self.assertRaisesRegex(ValueError,"F23/P5 scope mismatch"):
            seal(a=authorization(scope=other))

    def test_authority_decision_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"P5 authority decision mismatch"):
            seal(decision="decision-other")

    def test_p7_authorization_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"P7/P5 authorization mismatch"):
            seal(p=promotion(authorization_id="auth-other"))

    def test_p7_decision_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"P7 authority decision mismatch"):
            seal(p=promotion(authority_decision_id="decision-other"))

    def test_preflight_receipt_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"P7/P6 preflight receipt mismatch"):
            seal(pf=preflight("pf-other"))

    def test_policy_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"P7/P5 policy mismatch"):
            seal(p=promotion(authorization_policy_version="other"))

    def test_f23_master_escalation_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"master authority invariant"):
            seal(b=binding(master_promotion_state="PROMOTION_READY"))

    def test_f23_canonical_escalation_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"master authority invariant"):
            seal(b=binding(canonical_effect="PROMOTE"))

    def test_f23_byte_or_f5_escalation_fails_closed(self):
        for field in ("byte_identity_effect","f5_effect"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError,"upstream gate invariant"):
                    seal(b=binding(**{field:"CLOSED"}))

    def test_f23_authority_class_escalation_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"authority class escalation"):
            seal(b=binding(authority_class="GALIA_MASTER_AUTHORITY"))

    def test_invalid_f23_hash_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"must be lowercase SHA-256"):
            seal(b=binding(reconciliation_sha256="not-a-hash"))

if __name__ == "__main__":
    unittest.main()
