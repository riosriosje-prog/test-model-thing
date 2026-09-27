import json
import unittest
from pathlib import Path

from galia2.safe_delete_library_batching import (
    MAX_LIBRARY_OPERATIONS_PER_CALL,
    build_manage_library_delete_ops,
    execute_batched_authorized_deletion,
    make_batches,
)

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/"governance/safe_delete_deletion_manifest.v1.json").read_text())
TARGETS=MANIFEST["targets"]

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

def pass_revalidate(batch_id,batch):
    return {"status":"PASS","batch_id":batch_id,"target_count":len(batch),"sealed_vault":"PASS"}

def success_adapter(batch_id,ops):
    return [
        {
            "operation":"delete",
            "status":"succeeded",
            "library_file_id":op["target"]["library_file_id"],
            "batch_id":batch_id,
        }
        for op in ops
    ]

class LibraryBatchingV10Tests(unittest.TestCase):
    def test_real_tool_limit_is_encoded(self):
        self.assertEqual(MAX_LIBRARY_OPERATIONS_PER_CALL,20)

    def test_exact_batch_shape_is_20_plus_7(self):
        batches=make_batches(TARGETS)
        self.assertEqual(tuple(map(len,batches)),(20,7))

    def test_ops_are_library_file_id_only(self):
        first=make_batches(TARGETS)[0]
        ops=build_manage_library_delete_ops(first)
        self.assertEqual(len(ops),20)
        for op in ops:
            self.assertEqual(op["operation"],"delete")
            self.assertEqual(set(op["target"]),{"kind","library_file_id"})
            self.assertEqual(op["target"]["kind"],"file")

    def test_no_authorization_means_no_revalidate_or_delete(self):
        calls={"revalidate":0,"delete":0}
        def rv(*args):
            calls["revalidate"]+=1
            return pass_revalidate(*args)
        def da(*args):
            calls["delete"]+=1
            return success_adapter(*args)
        result=execute_batched_authorized_deletion(TARGETS,None,rv,da,commit=True)
        self.assertFalse(result.executed)
        self.assertEqual(calls,{"revalidate":0,"delete":0})

    def test_no_commit_means_no_delete(self):
        calls={"delete":0}
        def da(*args):
            calls["delete"]+=1
            return success_adapter(*args)
        result=execute_batched_authorized_deletion(TARGETS,auth(),pass_revalidate,da,commit=False)
        self.assertFalse(result.executed)
        self.assertEqual(calls["delete"],0)

    def test_revalidation_runs_before_each_batch(self):
        seen=[]
        def rv(batch_id,batch):
            seen.append((batch_id,len(batch)))
            return pass_revalidate(batch_id,batch)
        result=execute_batched_authorized_deletion(TARGETS,auth(),rv,success_adapter,commit=True)
        self.assertTrue(result.executed)
        self.assertEqual(seen,[("BATCH-01",20),("BATCH-02",7)])

    def test_batch_2_never_runs_if_batch_1_has_failure(self):
        called=[]
        def adapter(batch_id,ops):
            called.append(batch_id)
            out=success_adapter(batch_id,ops)
            if batch_id=="BATCH-01":
                out[3]["status"]="failed"
            return out
        result=execute_batched_authorized_deletion(TARGETS,auth(),pass_revalidate,adapter,commit=True)
        self.assertFalse(result.executed)
        self.assertEqual(called,["BATCH-01"])
        self.assertNotIn("BATCH-02",result.completed_batches)

    def test_batch_2_revalidation_failure_stops_before_delete(self):
        delete_calls=[]
        def rv(batch_id,batch):
            if batch_id=="BATCH-02":
                return {"status":"FAIL","reason":"LIVE_DRIFT"}
            return pass_revalidate(batch_id,batch)
        def adapter(batch_id,ops):
            delete_calls.append(batch_id)
            return success_adapter(batch_id,ops)
        result=execute_batched_authorized_deletion(TARGETS,auth(),rv,adapter,commit=True)
        self.assertFalse(result.executed)
        self.assertEqual(delete_calls,["BATCH-01"])
        self.assertEqual(result.completed_batches,("BATCH-01",))
        self.assertEqual(len(result.deleted_library_file_ids),20)

    def test_full_fake_execution_is_exact_27(self):
        result=execute_batched_authorized_deletion(
            TARGETS,auth(),pass_revalidate,success_adapter,commit=True
        )
        self.assertTrue(result.executed)
        self.assertEqual(result.completed_batches,("BATCH-01","BATCH-02"))
        self.assertEqual(len(result.deleted_library_file_ids),27)

if __name__=="__main__":
    unittest.main()
