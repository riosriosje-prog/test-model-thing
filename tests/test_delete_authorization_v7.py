import unittest

from galia2.delete_authorization import (
    EXPECTED_DELETION_MANIFEST_SHA256,
    EXPECTED_FINAL_VAULT_MANIFEST_SHA256,
    EXPECTED_SCOPE,
    evaluate_delete_authorization,
)

def valid_receipt():
    return {
        "state": "EXPLICIT_HUMAN_APPROVAL_BOUND",
        "decision_id": "HUMAN-DELETE-TEST",
        "decision_text": "I explicitly authorize deletion of the exact 27 manifest targets.",
        "deletion_manifest_sha256": EXPECTED_DELETION_MANIFEST_SHA256,
        "final_vault_manifest_sha256": EXPECTED_FINAL_VAULT_MANIFEST_SHA256,
        "target_count": 27,
        "authorized_scope": EXPECTED_SCOPE,
        "delete_authorized": True,
        "destructive_action_executed": False,
    }

class DeleteAuthorizationV7Tests(unittest.TestCase):
    def test_absent_receipt_fails_closed(self):
        result=evaluate_delete_authorization(None)
        self.assertFalse(result.authorized)
        self.assertEqual(result.blockers, ("AUTHORIZATION_RECEIPT_ABSENT",))

    def test_generic_promotion_signal_is_not_enough(self):
        result=evaluate_delete_authorization({
            "state":"EXPLICIT_HUMAN_APPROVAL_BOUND",
            "decision_id":"PROMOTION-ONLY",
            "decision_text":"👨‍💼",
            "delete_authorized":False,
        })
        self.assertFalse(result.authorized)
        self.assertIn("DELETION_MANIFEST_HASH_MISMATCH", result.blockers)
        self.assertIn("FINAL_VAULT_HASH_MISMATCH", result.blockers)
        self.assertIn("DELETE_AUTHORIZED_TRUE_REQUIRED", result.blockers)

    def test_manifest_hash_mismatch_fails(self):
        r=valid_receipt()
        r["deletion_manifest_sha256"]="0"*64
        self.assertIn("DELETION_MANIFEST_HASH_MISMATCH", evaluate_delete_authorization(r).blockers)

    def test_vault_hash_mismatch_fails(self):
        r=valid_receipt()
        r["final_vault_manifest_sha256"]="0"*64
        self.assertIn("FINAL_VAULT_HASH_MISMATCH", evaluate_delete_authorization(r).blockers)

    def test_scope_mismatch_fails(self):
        r=valid_receipt()
        r["authorized_scope"]="ALL_FILES"
        self.assertIn("AUTHORIZED_SCOPE_MISMATCH", evaluate_delete_authorization(r).blockers)

    def test_exact_bound_receipt_can_authorize(self):
        result=evaluate_delete_authorization(valid_receipt())
        self.assertTrue(result.authorized)
        self.assertEqual(result.blockers, ())

    def test_module_contains_no_delete_primitive(self):
        from pathlib import Path
        source=Path("galia2/delete_authorization.py").read_text().lower()
        self.assertNotIn("unlink(", source)
        self.assertNotIn("remove(", source)
        self.assertNotIn("rmtree(", source)
        self.assertNotIn("delete_file", source)

if __name__ == "__main__":
    unittest.main()
