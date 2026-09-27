import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "integrations/cross_plane_bindings.v1.json").read_text())
MIGRATION = (ROOT / "supabase/migrations/20260927001000_galia_cross_plane_bindings_v1.sql").read_text()
BINDINGS = (ROOT / "supabase/bindings/galia_cross_plane_bindings_v1.sql").read_text()
TOKEN = "__PROMOTED_MAIN_COMMIT__"


class CrossPlaneBindingsPolicyTests(unittest.TestCase):
    def test_control_plane_is_github_only(self):
        self.assertEqual(POLICY["authority_invariants"]["source_of_truth"], "GITHUB")
        self.assertEqual(POLICY["authority_invariants"]["canonical_authority_provider"], "GITHUB")
        self.assertFalse(POLICY["authority_invariants"]["canonical_authority_transferred"])

    def test_github_binding_is_merge_stable(self):
        gh = POLICY["github"]
        self.assertEqual(gh["repository"], "riosriosje-prog/test-model-thing")
        self.assertEqual(gh["ref"], "main")
        self.assertEqual(gh["candidate_base_commit"], "384a1b1b2c804b6d7838cd301d61232dd6313895")
        self.assertTrue(gh["promotion_binding"]["promotion_receipt_must_bind_merge_commit"])
        self.assertEqual(gh["promotion_binding"]["template_token"], TOKEN)

    def test_binding_template_requires_exact_promoted_commit(self):
        self.assertGreaterEqual(BINDINGS.count(TOKEN), 2)
        self.assertIn("must be rendered with the exact promoted GitHub main commit", BINDINGS)
        self.assertIn("!~ '^[0-9a-f]{40}$'", BINDINGS)

    def test_binding_template_does_not_freeze_pre_merge_main_as_authority(self):
        pre_merge = "384a1b1b2c804b6d7838cd301d61232dd6313895"
        self.assertNotIn("'github_main_commit', '" + pre_merge + "'", BINDINGS)
        self.assertNotIn("\n    '" + pre_merge + "',\n    'main'", BINDINGS)

    def test_rendered_binding_accepts_only_40_lower_hex_shape(self):
        sample = "a" * 40
        rendered = BINDINGS.replace(TOKEN, sample)
        self.assertNotIn(TOKEN, rendered)
        self.assertRegex(sample, r"^[0-9a-f]{40}$")
        self.assertIn(sample, rendered)

    def test_hf_model_binding_is_exact(self):
        model = POLICY["hugging_face"]["model"]
        self.assertEqual(model["repo_id"], "Junitos/galia-2")
        self.assertEqual(
            model["payload_sha256"],
            "3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c",
        )
        self.assertEqual(
            model["manifest_sha256"],
            "a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2",
        )

    def test_hf_evidence_surface_is_schema_only(self):
        ds = POLICY["hugging_face"]["evidence_dataset"]
        self.assertEqual(ds["repo_id"], "Junitos/galia-2-evidence")
        self.assertEqual(ds["evidence_records"], 0)
        self.assertEqual(ds["raw_evidence_bytes"], 0)

    def test_supabase_project_is_exact(self):
        supa = POLICY["supabase"]
        self.assertEqual(supa["project_id"], "nzoviwitcqmsacwiizhh")
        self.assertEqual(supa["project_name"], "galia-cangrejos")
        self.assertEqual(supa["target_schema_version"], "1.4.0")

    def test_migration_preserves_old_external_anchors(self):
        lower = MIGRATION.lower()
        self.assertNotIn("drop table", lower)
        self.assertNotIn("alter table audit.external_anchors", lower)
        self.assertIn("preserves_external_anchors", MIGRATION)

    def test_new_tables_are_rls_fail_closed(self):
        lower = MIGRATION.lower()
        self.assertIn("alter table audit.cross_plane_bindings enable row level security", lower)
        self.assertIn("alter table audit.cross_plane_binding_edges enable row level security", lower)
        self.assertIn("revoke all on table audit.cross_plane_bindings from anon, authenticated", lower)
        self.assertIn("revoke all on table audit.cross_plane_binding_edges from anon, authenticated", lower)

    def test_non_github_canonical_authority_is_blocked_by_constraint(self):
        self.assertIn("provider = 'GITHUB' and authority_role = 'CONTROL_PLANE'", MIGRATION)

    def test_binding_sql_contains_no_hf_or_supabase_authority_transfer(self):
        self.assertIn("'HUGGING_FACE'", BINDINGS)
        self.assertIn("'SUPABASE'", BINDINGS)
        self.assertIn("'authority_transfer', false", BINDINGS)
        self.assertIn("'canonical_authority_provider', 'GITHUB'", BINDINGS)

    def test_binding_graph_closes_all_three_planes(self):
        required = {
            ("github-control-plane-main", "hf8-model-artifact", "BINDS_ARTIFACT"),
            ("github-control-plane-main", "hf9-evidence-schema", "BINDS_ARTIFACT"),
            ("github-control-plane-main", "supabase-data-plane", "BINDS_DATA_PLANE"),
            ("supabase-data-plane", "hf9-evidence-schema", "DISTRIBUTES_SCHEMA_TO"),
        }
        self.assertEqual({tuple(x) for x in POLICY["expected_edges"]}, required)

    def test_trust_root_binding_matches_promoted_global_master(self):
        tr = POLICY["trust_root"]
        self.assertEqual(
            tr["active_pointer_sha256"],
            "ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9",
        )
        self.assertEqual(
            tr["global_master_sqlite_sha256"],
            "9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354",
        )

    def test_no_evidence_data_migration_is_authorized(self):
        self.assertIn("NO_EVIDENCE_RECORD_MIGRATION", POLICY["non_effects"])
        self.assertIn("'evidence_data_migration', false", BINDINGS)


if __name__ == "__main__":
    unittest.main()
