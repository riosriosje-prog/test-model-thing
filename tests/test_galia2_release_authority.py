import ast
import inspect
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from galia2.release_authority import (
    G22State,
    ReleaseAuthorizationQuality,
    ReleaseAuthorityDomain,
    ReleaseAuthorityEvidence,
    ReleaseAuthorityScope,
    cross_scope_transfer_required,
    g22_state,
)

MASTER_HASH = "9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354"
SANTURCE_HASH = "22865209ebb914543ce90ad933758d37f2f0abf760084c37380838bd121745f8"


def global_scope():
    return ReleaseAuthorityScope(
        "Galia", ReleaseAuthorityDomain.GLOBAL_MASTER, "GLOBAL_MASTER"
    )


def santurce_scope():
    return ReleaseAuthorityScope(
        "Galia",
        ReleaseAuthorityDomain.RESEARCH_CANONICAL_STATE,
        "SANTURCE_CANGREJOS",
    )


def master(**overrides):
    values = dict(
        release_id="RC-GALIA-2026-09-13-004",
        scope=global_scope(),
        artifact_sha256=MASTER_HASH,
        authorization_quality=ReleaseAuthorizationQuality.DIRECT_FILE_RECORD,
        source_evidence_ids=("promotion-record-13-004", "byte-receipt-master-101"),
        scope_binding_supported=True,
        raw_artifact_present=True,
        historically_promoted_supported=True,
        lineage_reconciled_within_scope=True,
        human_selected_in_current_review=True,
    )
    values.update(overrides)
    return ReleaseAuthorityEvidence(**values)


def research(**overrides):
    values = dict(
        release_id="RC-GALIA-2026-09-15-003",
        scope=santurce_scope(),
        artifact_sha256=SANTURCE_HASH,
        authorization_quality=ReleaseAuthorizationQuality.EXPLICIT_HUMAN_TRACE_REVALIDATED,
        source_evidence_ids=("promotion-record-15-003", "scope-binding-014"),
        scope_binding_supported=True,
        raw_artifact_present=True,
        historically_promoted_supported=True,
        lineage_reconciled_within_scope=False,
        human_selected_in_current_review=False,
    )
    values.update(overrides)
    return ReleaseAuthorityEvidence(**values)


class ReleaseAuthorityTests(unittest.TestCase):
    def test_scope_is_immutable(self):
        item = global_scope()
        with self.assertRaises(FrozenInstanceError):
            item.scope_id = "other"

    def test_scope_token_is_exact_and_stable(self):
        self.assertEqual(
            global_scope().token,
            "system:Galia|domain:GLOBAL_MASTER|scope:GLOBAL_MASTER",
        )

    def test_master_is_byte_authoritative_candidate(self):
        self.assertTrue(master().byte_authoritative_candidate)

    def test_global_g22_passes_with_exact_master_only(self):
        self.assertEqual(
            g22_state([master(), research()], target_scope=global_scope()),
            G22State.PASS_SINGLE_BYTE_AUTHORITATIVE_INTEGRATION_BASE,
        )

    def test_open_research_lineage_does_not_block_global_scope(self):
        self.assertFalse(research().lineage_reconciled_within_scope)
        self.assertEqual(
            g22_state([master(), research()], target_scope=global_scope()),
            G22State.PASS_SINGLE_BYTE_AUTHORITATIVE_INTEGRATION_BASE,
        )

    def test_research_scope_stays_blocked_while_lineage_open(self):
        self.assertEqual(
            g22_state([master(), research()], target_scope=santurce_scope()),
            G22State.BLOCK_NO_ELIGIBLE_INTEGRATION_BASE,
        )

    def test_cross_scope_transfer_is_explicitly_required(self):
        self.assertTrue(cross_scope_transfer_required(research(), master()))

    def test_unsupported_scope_binding_cannot_enter_target_scope(self):
        unbound = master(scope_binding_supported=False)
        self.assertEqual(
            g22_state([unbound], target_scope=global_scope()),
            G22State.BLOCK_NO_ELIGIBLE_INTEGRATION_BASE,
        )

    def test_raw_bytes_missing_blocks_known_authority_hash(self):
        missing = master(raw_artifact_present=False)
        self.assertEqual(
            g22_state([missing], target_scope=global_scope()),
            G22State.BLOCK_KNOWN_AUTHORITY_HASH_RAW_BYTES_ABSENT,
        )

    def test_no_current_human_selection_blocks(self):
        not_selected = master(human_selected_in_current_review=False)
        self.assertEqual(
            g22_state([not_selected], target_scope=global_scope()),
            G22State.BLOCK_NO_ELIGIBLE_INTEGRATION_BASE,
        )

    def test_defective_authorization_blocks(self):
        defective = master(
            authorization_quality=ReleaseAuthorizationQuality.DEFECTIVE_GENERIC_CONTINUATION
        )
        self.assertFalse(defective.human_authorization_supported)
        self.assertEqual(
            g22_state([defective], target_scope=global_scope()),
            G22State.BLOCK_NO_ELIGIBLE_INTEGRATION_BASE,
        )

    def test_two_eligible_same_scope_is_ambiguous(self):
        second = master(
            release_id="RC-GALIA-OTHER",
            artifact_sha256="a" * 64,
            source_evidence_ids=("other-record",),
        )
        self.assertEqual(
            g22_state([master(), second], target_scope=global_scope()),
            G22State.BLOCK_AMBIGUOUS_MULTIPLE_INTEGRATION_BASES,
        )

    def test_bad_hash_rejected(self):
        with self.assertRaises(ValueError):
            master(artifact_sha256="abc")

    def test_duplicate_evidence_ids_rejected(self):
        with self.assertRaises(ValueError):
            master(source_evidence_ids=("same", "same"))

    def test_module_has_no_filesystem_network_or_legacy_imports(self):
        import galia2.release_authority as m
        module_path = Path(inspect.getsourcefile(m))
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        forbidden = {
            "os", "pathlib", "subprocess", "shutil", "socket",
            "urllib", "requests", "main",
        }
        imported = set()
        called_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
        self.assertTrue(imported.isdisjoint(forbidden), imported & forbidden)
        self.assertNotIn("open", called_names)


if __name__ == "__main__":
    unittest.main()
