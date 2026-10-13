import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from galia2.f23_issuer_policy import IssuerPolicy, validate_issuer_policy

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
POLICY = IssuerPolicy("issuer", b"k" * 32, ("reviewer",), NOW - timedelta(days=1), NOW + timedelta(days=1))


class IssuerPolicyTests(unittest.TestCase):
    def check(self, policy=POLICY, *, issuer="issuer", reviewer="reviewer", at=NOW):
        return validate_issuer_policy(issuer, reviewer, at, policies={"issuer": policy})

    def test_valid_policy_returns_key_not_authority(self):
        self.assertEqual(self.check(), b"k" * 32)

    def test_unknown_issuer_rejected(self):
        with self.assertRaisesRegex(ValueError, "issuer not enrolled"):
            self.check(issuer="unknown")

    def test_malformed_revocation_flag_rejected(self):
        for invalid in (None, 0, "false"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "invalid revocation flag"):
                    self.check(replace(POLICY, revoked=invalid))

    def test_revoked_issuer_rejected(self):
        with self.assertRaisesRegex(ValueError, "issuer revoked"):
            self.check(replace(POLICY, revoked=True))

    def test_unauthorized_reviewer_rejected(self):
        with self.assertRaisesRegex(ValueError, "reviewer not authorized"):
            self.check(reviewer="other")

    def test_outside_validity_window_rejected(self):
        for instant in (POLICY.valid_from - timedelta(seconds=1), POLICY.valid_until):
            with self.subTest(instant=instant):
                with self.assertRaisesRegex(ValueError, "issuer policy inactive"):
                    self.check(at=instant)

    def test_naive_time_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware evaluation"):
            self.check(at=NOW.replace(tzinfo=None))

    def test_malformed_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid issuer key"):
            self.check(replace(POLICY, public_key=b"short"))

    def test_malformed_reviewer_policy_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid reviewer policy"):
            self.check(replace(POLICY, allowed_reviewer_ids=("reviewer", "reviewer")))

    def test_policy_identity_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "issuer not enrolled"):
            self.check(replace(POLICY, issuer_id="other"))

    def test_naive_policy_bounds_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware policy bounds"):
            self.check(replace(POLICY, valid_from=POLICY.valid_from.replace(tzinfo=None)))

    def test_validity_start_is_inclusive(self):
        self.assertEqual(self.check(at=POLICY.valid_from), POLICY.public_key)

    def test_missing_registry_rejected(self):
        with self.assertRaisesRegex(ValueError, "issuer policy registry required"):
            validate_issuer_policy("issuer", "reviewer", NOW, policies=None)

    def test_invalid_policy_bounds_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid policy interval"):
            self.check(replace(POLICY, valid_until=POLICY.valid_from))


if __name__ == "__main__":
    unittest.main()
