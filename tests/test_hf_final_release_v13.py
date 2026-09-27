import json
import pathlib
import re
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

class HFFinalReleaseV13Tests(unittest.TestCase):
    def test_contract_binds_exact_master(self):
        c=json.loads((ROOT/"governance/hf_final_release_candidate.v1.json").read_text())
        self.assertEqual(c["target"]["repo_id"],"Junitos/galia-2")
        self.assertEqual(c["target"]["promotion_scope"],"DISTRIBUTION_MIRROR_ONLY")
        self.assertFalse(c["source_control_plane"]["canonical_authority_transferred"])
        binary=next(x for x in c["artifacts"] if x["role"]=="canonical_binary_snapshot")
        self.assertEqual(binary["sha256"],"9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354")
        self.assertEqual(binary["bytes"],488689664)

    def test_publisher_is_fail_closed_on_identity_and_hash(self):
        s=(ROOT/"tools/publish_hf_final_release.py").read_text()
        self.assertIn('who.get("name")!="Junitos"',s)
        self.assertIn("EXPECTED_SQLITE_SHA",s)
        self.assertIn("EXPECTED_SQLITE_BYTES",s)
        self.assertIn("canonical_authority_transferred",s)
        self.assertIn("DISTRIBUTION_MIRROR_ONLY",s)

    def test_workflow_has_no_automatic_trigger(self):
        s=(ROOT/".github/workflows/hf-final-release-1-0-1.yml").read_text()
        self.assertIn("workflow_dispatch:",s)
        self.assertNotRegex(s,r"(?m)^\s*push:")
        self.assertNotRegex(s,r"(?m)^\s*schedule:")
        self.assertIn("hf-final-release-input",s)

if __name__=="__main__":
    unittest.main()
