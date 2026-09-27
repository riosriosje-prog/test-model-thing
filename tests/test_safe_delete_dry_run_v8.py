import json
import unittest
from pathlib import Path

from galia2.safe_delete_dry_run import build_dry_run_plan

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance/safe_delete_deletion_manifest.v1.json").read_text())

def live_inventory():
    return [
        {
            "library_file_id": t["library_file_id"],
            "file_id": t["file_id"],
            "path": t["path"],
            "size_bytes": t["size_bytes"],
        }
        for t in MANIFEST["targets"]
    ]

def valid_auth():
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

class SafeDeleteDryRunV8Tests(unittest.TestCase):
    def test_without_human_authorization_stays_hold(self):
        plan=build_dry_run_plan(MANIFEST, live_inventory(), None)
        self.assertFalse(plan.executable)
        self.assertEqual(plan.state, "DRY_RUN_HOLD")
        self.assertIn("AUTH:AUTHORIZATION_RECEIPT_ABSENT", plan.blockers)

    def test_exact_authorization_and_live_inventory_can_be_execution_eligible(self):
        plan=build_dry_run_plan(MANIFEST, live_inventory(), valid_auth())
        self.assertTrue(plan.executable)
        self.assertEqual(plan.state, "AUTHORIZED_EXECUTION_ELIGIBLE")
        self.assertEqual(len(plan.targets), 27)

    def test_live_path_drift_blocks(self):
        live=live_inventory()
        live[0]["path"]="/moved/object.zip"
        plan=build_dry_run_plan(MANIFEST, live, valid_auth())
        self.assertFalse(plan.executable)
        self.assertIn("TARGET_0:LIVE_PATH_MISMATCH", plan.blockers)

    def test_live_file_id_drift_blocks(self):
        live=live_inventory()
        live[0]["file_id"]="file_changed"
        plan=build_dry_run_plan(MANIFEST, live, valid_auth())
        self.assertFalse(plan.executable)
        self.assertIn("TARGET_0:LIVE_FILE_ID_MISMATCH", plan.blockers)

    def test_live_size_drift_blocks(self):
        live=live_inventory()
        live[0]["size_bytes"] += 1
        plan=build_dry_run_plan(MANIFEST, live, valid_auth())
        self.assertFalse(plan.executable)
        self.assertIn("TARGET_0:LIVE_SIZE_MISMATCH", plan.blockers)

    def test_sealed_vault_target_is_forbidden(self):
        m=json.loads(json.dumps(MANIFEST))
        m["targets"][0]["path"]="/GALIA_FINAL_VAULT_SEALED_2026-09-26/forbidden.zip"
        live=live_inventory()
        live[0]["path"]=m["targets"][0]["path"]
        plan=build_dry_run_plan(m, live, valid_auth())
        self.assertFalse(plan.executable)
        self.assertIn("TARGET_0:SEALED_VAULT_TARGET_FORBIDDEN", plan.blockers)

    def test_plan_is_would_delete_only(self):
        plan=build_dry_run_plan(MANIFEST, live_inventory(), None)
        self.assertTrue(all(t["operation"]=="WOULD_DELETE_LIBRARY_OBJECT" for t in plan.targets))

    def test_module_has_no_mutation_primitives(self):
        source=(ROOT / "galia2/safe_delete_dry_run.py").read_text().lower()
        for token in ("unlink(", "rmtree(", "os.remove(", "delete_file", "manage_library", "shutil."):
            self.assertNotIn(token, source)

if __name__ == "__main__":
    unittest.main()
