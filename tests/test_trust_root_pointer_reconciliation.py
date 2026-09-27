import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POINTER_PATH = ROOT / "integrations/trust_root_active_pointer_v2.json"
SQL_PATH = ROOT / "supabase/bindings/galia_trust_root_pointer_reconciliation_v2.sql"
POINTER_BYTES = POINTER_PATH.read_bytes()
POINTER = json.loads(POINTER_BYTES)
SQL = SQL_PATH.read_text()

EXPECTED_POINTER_SHA = "eac0b7af19823a588f8d9a188592f0667af6d73c442aaff4d4096bc16030647c"
OLD_POINTER_SHA = "ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9"
CURRENT_MAIN = "25db17fa583d1561d746ee7d33407d3684ee561d"
MASTER_SHA = "9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354"
TRUST_ROOT_V8_SHA = "7aa0d35cdd6b3746c43f0cfd379fdb78e50347b32ff8fa0092fd7ded6956e778"


class TrustRootPointerReconciliationTests(unittest.TestCase):
    def test_pointer_bytes_have_exact_sha(self):
        self.assertEqual(hashlib.sha256(POINTER_BYTES).hexdigest(), EXPECTED_POINTER_SHA)

    def test_control_plane_matches_current_main(self):
        self.assertEqual(POINTER["control_plane"]["main_commit"], CURRENT_MAIN)
        self.assertEqual(POINTER["data_plane"]["github_binding_revision"], CURRENT_MAIN)

    def test_global_master_is_unchanged(self):
        root = POINTER["effective_current_trust_root"]
        self.assertEqual(root["master_sqlite_sha256"], MASTER_SHA)
        self.assertEqual(root["sha256"], TRUST_ROOT_V8_SHA)
        self.assertEqual(root["release_id"], "RC-GALIA-2026-09-13-004")

    def test_predecessor_pointer_is_preserved(self):
        self.assertEqual(POINTER["predecessor_active_pointer"]["sha256"], OLD_POINTER_SHA)

    def test_gates_are_unchanged(self):
        gates = POINTER["gates_after_activation"]
        self.assertEqual(gates["G20"], "PASS")
        self.assertEqual(gates["G22"], "PASS_SINGLE_BYTE_AUTHORITATIVE_INTEGRATION_BASE")
        self.assertEqual(gates["G27"], "PASS")
        self.assertEqual(gates["G28"], "OPEN_UNPROVEN_FORENSIC_ONLY")
        self.assertEqual(gates["SAFE_DELETE"], "HOLD")

    def test_scope_bindings_are_unchanged(self):
        self.assertEqual(POINTER["scope_bindings"]["RC-GALIA-2026-09-13-004"], "GLOBAL_MASTER")
        self.assertEqual(
            POINTER["scope_bindings"]["RC-GALIA-2026-09-15-003"],
            "SANTURCE_RESEARCH_CANONICAL_STATE",
        )

    def test_promotion_receipt_is_required(self):
        self.assertEqual(
            POINTER["activation_state"],
            "NOT_EFFECTIVE_UNTIL_EXTERNAL_PROMOTION_RECEIPT",
        )
        self.assertTrue(POINTER["authority"]["this_reconciliation"]["promotion_required"])

    def test_supabase_update_is_fail_closed_on_revision_and_pointer(self):
        self.assertIn(CURRENT_MAIN, SQL)
        self.assertIn(OLD_POINTER_SHA, SQL)
        self.assertIn("raise exception", SQL.lower())

    def test_supabase_update_binds_exact_successor_sha(self):
        self.assertIn(EXPECTED_POINTER_SHA, SQL)

    def test_no_authority_transfer(self):
        self.assertFalse(POINTER["supabase_reconciliation_if_promoted"]["authority_transfer"])
        self.assertIn("NO_CROSS_SCOPE_AUTHORITY_TRANSFER", POINTER["non_effects"])

    def test_no_master_or_hf_mutation(self):
        self.assertIn("NO_MASTER_SQLITE_CHANGE", POINTER["non_effects"])
        self.assertIn("NO_HF_MUTATION", POINTER["non_effects"])


if __name__ == "__main__":
    unittest.main()
