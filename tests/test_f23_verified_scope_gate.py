"""Isolated negative tests for F23 verified-scope gate.

These test early fail-closed checks without asserting trust-root authentication.
"""
from dataclasses import replace
import unittest
from galia2.authority import AuthorityScope
from galia2.f23_verified_scope_gate import VerifiedScopeAttestation, bind_with_verified_scope

A = VerifiedScopeAttestation(
    decision_id="d", reviewer_id="r", issuer_id="issuer",
    case_id="case-A", target_type="external-candidate", target_ids=("candidate-A",),
    reconciliation_sha256="a"*64, candidate_set_sha256="b"*64,
    conflict_component_sha256="c"*64, selected_candidate_id="candidate-A",
)
S = AuthorityScope(case_id="case-A", target_type="external-candidate", target_ids=("candidate-A",))
R = {"reconciliation_sha256":"a"*64, "candidate_set_sha256":"b"*64,
     "reconciled_component_sha256":"c"*64, "selected_candidate_id":"candidate-A"}

def call(scope=S, attestation=A, reconciliation=R):
    return bind_with_verified_scope(
        reconciliation, attestation=attestation,
        p5_scope=scope, expected_provider_id="provider-A", expected_external_scope="external-A")

class GateTests(unittest.TestCase):
    def test_missing_attestation(self):
        with self.assertRaisesRegex(ValueError, "attestation required"): call(attestation=None)
    def test_case_mismatch(self):
        with self.assertRaisesRegex(ValueError, "P5 scope mismatch"):
            call(scope=replace(S, case_id="foreign"))
    def test_type_mismatch(self):
        with self.assertRaisesRegex(ValueError, "P5 scope mismatch"):
            call(scope=replace(S, target_type="foreign"))
    def test_ids_mismatch(self):
        with self.assertRaisesRegex(ValueError, "P5 scope mismatch"):
            call(scope=replace(S, target_ids=("foreign",)))
    def test_reconciliation_mismatch(self):
        with self.assertRaisesRegex(ValueError, "attested reconciliation mismatch"):
            call(reconciliation=dict(R, reconciliation_sha256="d"*64))
    def test_crypto_rejects_unknown_issuer(self):
        from galia2.f23_attestation_crypto import verify_ed25519_signature
        with self.assertRaisesRegex(ValueError, "trusted issuer key missing"):
            verify_ed25519_signature(A, "", trusted_public_keys={})

    def test_crypto_rejects_invalid_attestation_type(self):
        from galia2.f23_attestation_crypto import verify_ed25519_signature
        with self.assertRaisesRegex(ValueError, "attestation type mismatch"):
            verify_ed25519_signature(None, "", trusted_public_keys={})

    def test_crypto_rejects_malformed_signature(self):
        from galia2.f23_attestation_crypto import verify_ed25519_signature
        with self.assertRaisesRegex(ValueError, "malformed signature encoding"):
            verify_ed25519_signature(A, "not-base64!", trusted_public_keys={"issuer": b"x" * 32})

    def test_invalid_target_ids_are_rejected(self):
        for invalid in ([], ("",), ("same", "same"), (None,)):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "invalid attested target ids"):
                    call(attestation=replace(A, target_ids=invalid))

    def test_invalid_scope_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "P5 scope required"):
            call(scope=None)

    def test_invalid_reconciliation_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "reconciliation mapping required"):
            call(reconciliation=None)

    def test_ed25519_roundtrip_and_tamper(self):
        import base64
        from galia2.f23_attestation_crypto import _canonical, verify_ed25519_signature
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        except ImportError:
            self.skipTest('cryptography unavailable')
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signature = base64.b64encode(key.sign(_canonical(A))).decode('ascii')
        trusted = {'issuer': pub}
        self.assertTrue(verify_ed25519_signature(A, signature, trusted_public_keys=trusted))
        self.assertFalse(verify_ed25519_signature(replace(A, case_id='other'), signature, trusted_public_keys=trusted))
        self.assertFalse(verify_ed25519_signature(replace(A, selected_candidate_id='other'), signature, trusted_public_keys=trusted))
    def test_no_trust_root_denies_all(self):
        with self.assertRaisesRegex(ValueError, "trusted issuer verification unavailable"):
            call()

if __name__ == "__main__":
    unittest.main()
