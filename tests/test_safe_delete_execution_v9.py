import unittest

from galia2.safe_delete_execution import (
    build_library_delete_operations,
    execute_authorized_deletion,
)
from galia2.safe_delete_post_receipt import verify_post_delete_receipt

def auth():
    return {
        "state":"EXPLICIT_HUMAN_APPROVAL_BOUND",
        "decision_id":"HUMAN-DELETE-TEST",
        "decision_text":"I explicitly authorize deletion of the exact 27 manifest targets.",
        "deletion_manifest_sha256":"6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708",
        "final_vault_manifest_sha256":"53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf",
        "target_count":27,
        "authorized_scope":"EXACT_27_TARGETS_IN_PROMOTED_DELETION_MANIFEST_ONLY",
        "delete_authorized":True,
        "destructive_action_executed":False,
    }

def plan():
    return {
        "state":"AUTHORIZED_EXECUTION_ELIGIBLE",
        "executable":True,
        "targets":[
            {
                "operation":"WOULD_DELETE_LIBRARY_OBJECT",
                "library_file_id":f"libfile_{i:02d}",
                "file_id":f"file_{i:02d}",
                "path":f"/tmp/{i}.zip",
                "expected_sha256":"a"*64,
                "expected_size_bytes":100+i,
                "preserved_in_sealed_vault":f"/GALIA_FINAL_VAULT_SEALED_2026-09-26/{i}.zip",
            }
            for i in range(27)
        ],
    }

def success_adapter(ops):
    return [
        {
            "operation":"delete",
            "status":"succeeded",
            "library_file_id":op["target"]["library_file_id"],
        }
        for op in ops
    ]

class SafeDeleteExecutionV9Tests(unittest.TestCase):
    def test_operations_use_only_library_file_id(self):
        ops=build_library_delete_operations(plan())
        self.assertEqual(len(ops),27)
        self.assertTrue(all(op["operation"]=="delete" for op in ops))
        self.assertTrue(all(op["target"]["kind"]=="file" for op in ops))
        self.assertTrue(all(set(op["target"])=={"kind","library_file_id"} for op in ops))

    def test_no_commit_flag_means_no_adapter_call(self):
        called={"value":False}
        def adapter(_):
            called["value"]=True
            return []
        result=execute_authorized_deletion(plan(),auth(),adapter,commit=False)
        self.assertFalse(result.executed)
        self.assertFalse(called["value"])
        self.assertIn("COMMIT_FLAG_REQUIRED",result.blockers)

    def test_bad_authorization_means_no_adapter_call(self):
        called={"value":False}
        def adapter(_):
            called["value"]=True
            return []
        result=execute_authorized_deletion(plan(),None,adapter,commit=True)
        self.assertFalse(result.executed)
        self.assertFalse(called["value"])

    def test_exact_authorization_and_commit_can_execute_fake_adapter(self):
        result=execute_authorized_deletion(plan(),auth(),success_adapter,commit=True)
        self.assertTrue(result.executed)
        self.assertEqual(result.state,"EXECUTED_EXACT_SCOPE")
        self.assertEqual(len(result.deleted_library_file_ids),27)

    def test_partial_adapter_failure_is_not_success(self):
        def adapter(ops):
            out=success_adapter(ops)
            out[7]["status"]="failed"
            return out
        result=execute_authorized_deletion(plan(),auth(),adapter,commit=True)
        self.assertFalse(result.executed)
        self.assertEqual(result.state,"PARTIAL_OR_FAILED_EXECUTION")
        self.assertIn("ADAPTER_7:DELETE_FAILED",result.blockers)

    def test_post_delete_receipt_requires_exact_27_and_intact_vault(self):
        result=execute_authorized_deletion(plan(),auth(),success_adapter,commit=True)
        sealed=[f"vault_{i}" for i in range(17)]
        post=["unrelated"]
        receipt=verify_post_delete_receipt(
            result.as_dict(),post,sealed,sealed
        )
        self.assertEqual(receipt["status"],"PASS")

    def test_post_delete_receipt_fails_if_vault_changes(self):
        result=execute_authorized_deletion(plan(),auth(),success_adapter,commit=True)
        receipt=verify_post_delete_receipt(
            result.as_dict(),[],["vault_1"],["vault_1","vault_2"]
        )
        self.assertEqual(receipt["status"],"FAIL")

if __name__=="__main__":
    unittest.main()
