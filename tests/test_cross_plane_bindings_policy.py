import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "integrations/cross_plane_bindings.v1.json").read_text())
MIGRATION = (ROOT / "supabase/migrations/20260927001000_galia_cross_plane_bindings_v1.sql").read_text()
BINDINGS = (ROOT / "supabase/bindings/galia_cross_plane_bindings_v1.sql").read_text()


def test_control_plane_is_github_only():
    assert POLICY["authority_invariants"]["source_of_truth"] == "GITHUB"
    assert POLICY["authority_invariants"]["canonical_authority_provider"] == "GITHUB"
    assert POLICY["authority_invariants"]["canonical_authority_transferred"] is False


def test_exact_current_github_main_is_bound():
    assert POLICY["github"]["repository"] == "riosriosje-prog/test-model-thing"
    assert POLICY["github"]["commit"] == "384a1b1b2c804b6d7838cd301d61232dd6313895"


def test_hf_model_binding_is_exact():
    model = POLICY["hugging_face"]["model"]
    assert model["repo_id"] == "Junitos/galia-2"
    assert model["payload_sha256"] == "3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c"
    assert model["manifest_sha256"] == "a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2"


def test_hf_evidence_surface_is_schema_only():
    ds = POLICY["hugging_face"]["evidence_dataset"]
    assert ds["repo_id"] == "Junitos/galia-2-evidence"
    assert ds["evidence_records"] == 0
    assert ds["raw_evidence_bytes"] == 0


def test_supabase_project_is_exact():
    supa = POLICY["supabase"]
    assert supa["project_id"] == "nzoviwitcqmsacwiizhh"
    assert supa["project_name"] == "galia-cangrejos"
    assert supa["target_schema_version"] == "1.4.0"


def test_migration_preserves_old_external_anchors():
    assert "drop table" not in MIGRATION.lower()
    assert "alter table audit.external_anchors" not in MIGRATION.lower()
    assert "preserves_external_anchors" in MIGRATION


def test_new_tables_are_rls_fail_closed():
    lower = MIGRATION.lower()
    assert "alter table audit.cross_plane_bindings enable row level security" in lower
    assert "alter table audit.cross_plane_binding_edges enable row level security" in lower
    assert "revoke all on table audit.cross_plane_bindings from anon, authenticated" in lower
    assert "revoke all on table audit.cross_plane_binding_edges from anon, authenticated" in lower


def test_non_github_canonical_authority_is_blocked_by_constraint():
    assert "provider = 'GITHUB' and authority_role = 'CONTROL_PLANE'" in MIGRATION


def test_binding_sql_contains_no_hf_or_supabase_authority_transfer():
    assert "'HUGGING_FACE'" in BINDINGS
    assert "'SUPABASE'" in BINDINGS
    assert "'authority_transfer', false" in BINDINGS
    assert "'canonical_authority_provider', 'GITHUB'" in BINDINGS


def test_binding_graph_closes_all_three_planes():
    required = {
        ("github-control-plane-main", "hf8-model-artifact", "BINDS_ARTIFACT"),
        ("github-control-plane-main", "hf9-evidence-schema", "BINDS_ARTIFACT"),
        ("github-control-plane-main", "supabase-data-plane", "BINDS_DATA_PLANE"),
        ("supabase-data-plane", "hf9-evidence-schema", "DISTRIBUTES_SCHEMA_TO"),
    }
    assert {tuple(x) for x in POLICY["expected_edges"]} == required


def test_trust_root_binding_matches_promoted_global_master():
    tr = POLICY["trust_root"]
    assert tr["active_pointer_sha256"] == "ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9"
    assert tr["global_master_sqlite_sha256"] == "9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354"


def test_no_evidence_data_migration_is_authorized():
    assert "NO_EVIDENCE_RECORD_MIGRATION" in POLICY["non_effects"]
    assert "'evidence_data_migration', false" in BINDINGS
