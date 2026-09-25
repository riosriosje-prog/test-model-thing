from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'huggingface' / 'policy' / 'control-artifact-plane.v1.json'
MIGRATION = ROOT / 'docs' / 'HUGGINGFACE_MIGRATION.md'
RETRAIN = ROOT / 'docs' / 'HF8_RETRAINING.md'
HF8_INTAKE = ROOT / 'docs' / 'HF8_WEIGHT_INTAKE_GATE.md'
HF9_GATE = ROOT / 'docs' / 'HF9_DATASET_EVIDENCE_GATE.md'
HF10_GATE = ROOT / 'docs' / 'HF10_SPACE_PARITY_GATE.md'
PROMOTION = ROOT / 'receipts' / 'huggingface' / 'hf8-v0-2-weight-promotion-receipt.json'

EXPECTED_MAIN = '051f56789de99a8db0d4aa044eaf120ea1d67805'
EXPECTED_PAYLOAD = '3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c'
EXPECTED_MANIFEST = 'a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2'


class ControlArtifactPlanePolicyTests(unittest.TestCase):
    def test_machine_policy_separates_control_and_artifact_authority(self):
        policy = json.loads(POLICY.read_text(encoding='utf-8'))
        self.assertEqual(policy['control_plane'], 'github')
        self.assertEqual(policy['ml_artifact_plane'], 'huggingface')
        self.assertEqual(policy['source_of_truth'], 'github')
        self.assertFalse(policy['canonical_authority_transferred'])
        principles = policy['principles']
        self.assertFalse(principles['code_authority_equals_model_artifact_authority'])
        self.assertFalse(principles['source_merge_implies_artifact_promotion'])
        self.assertFalse(principles['artifact_promotion_implies_source_merge'])
        self.assertFalse(principles['artifact_presence_implies_canonical_authority'])
        self.assertTrue(principles['human_promotion_required'])
        contract = policy['cross_plane_contract']
        self.assertFalse(contract['github_to_huggingface']['automatic_promotion_allowed'])
        self.assertTrue(contract['github_to_huggingface']['human_promotion_required'])
        self.assertTrue(contract['github_to_huggingface']['remote_reread_required'])
        self.assertFalse(contract['huggingface_to_github']['automatic_source_merge_allowed'])
        self.assertFalse(contract['huggingface_to_github']['canonical_authority_transfer_allowed'])
        self.assertFalse(contract['huggingface_to_github']['legacy_mutation_allowed'])

    def test_policy_is_bound_to_current_promoted_weight_and_main(self):
        policy = json.loads(POLICY.read_text(encoding='utf-8'))
        promotion = json.loads(PROMOTION.read_text(encoding='utf-8'))
        weight = policy['current_promoted_weight']
        self.assertEqual(policy['current_github_main'], EXPECTED_MAIN)
        self.assertEqual(weight['payload_sha256'], EXPECTED_PAYLOAD)
        self.assertEqual(weight['manifest_sha256'], EXPECTED_MANIFEST)
        self.assertEqual(weight['payload_sha256'], promotion['payload_sha256'])
        self.assertEqual(weight['payload_bytes'], promotion['payload_bytes'])
        self.assertEqual(weight['manifest_sha256'], promotion['manifest_sha256'])
        self.assertEqual(weight['promotion_scope'], promotion['promotion_scope'])
        self.assertTrue(promotion['promoted'])
        self.assertFalse(promotion['canonical_authority_transferred'])
        self.assertFalse(promotion['legacy_mutation_authorized'])

    def test_docs_do_not_regress_to_stale_hf8_hold_or_old_main(self):
        migration = MIGRATION.read_text(encoding='utf-8')
        retrain = RETRAIN.read_text(encoding='utf-8')
        self.assertIn(EXPECTED_MAIN, migration)
        self.assertIn(EXPECTED_MAIN, retrain)
        self.assertIn(EXPECTED_PAYLOAD, migration)
        self.assertIn(EXPECTED_PAYLOAD, retrain)
        self.assertNotIn('HF8_WEIGHT_ARTIFACT_GATE          = HOLD', migration)
        self.assertNotIn('a09c3e953ec1799b1704783c4c3d14a1a0017f62', migration)
        self.assertNotIn('GitHub PR #22 remains a separate source-integration decision', retrain)

    def test_gate_docs_reflect_current_split_states(self):
        hf8 = HF8_INTAKE.read_text(encoding='utf-8')
        hf9 = HF9_GATE.read_text(encoding='utf-8')
        hf10 = HF10_GATE.read_text(encoding='utf-8')

        self.assertIn('REAL WEIGHT PROMOTED', hf8)
        self.assertIn(EXPECTED_PAYLOAD, hf8)
        self.assertNotIn('Status: **HOLD / INTAKE TOOLING READY / NO SYNTHETIC WEIGHTS**', hf8)

        self.assertIn('HF9G dataset schema-surface promotion: PROMOTED', hf9)
        self.assertIn('HF9E evidence-record migration: HOLD', hf9)
        self.assertIn('HF9F image/source-byte migration: HOLD', hf9)
        self.assertNotIn('HF9G dataset promotion: HUMAN DECISION REQUIRED', hf9)

        self.assertIn('HF10_LINUX_MLX_RUNTIME_PARITY = PASS', hf10)
        self.assertIn('production_runtime_promoted   = false', hf10)
        self.assertIn('HF10B_DYNAMIC_GRADIO_SPACE = HOLD_TIER_CONSTRAINT', hf10)
        self.assertNotIn('HF10 remains non-promoted until', hf10)


if __name__ == '__main__':
    unittest.main()
