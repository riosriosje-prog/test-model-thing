import copy
import hashlib
import unittest

from galia2 import authority_reconciliation as f22
from galia2.authority import AuthorityScope
from galia2.reconciliation_authority_binding import bind_reconciliation


def h(v):
    return hashlib.sha256(v.encode()).hexdigest()


def candidate(cid, key, provider="P", scope="receipt-signing", tag="x"):
    return f22.seal_candidate({
        "candidate_id": cid, "provider_id": provider, "scope": scope,
        "key_id": key, "key_sha256": h("key-" + key),
        "source_artifact_sha256": h("artifact-" + tag),
        "lineage_sha256": h("lineage-" + tag),
        "valid_from_utc": "2026-01-01T00:00:00Z",
        "authority_assertion": "ACTIVE",
    })


def fixture():
    candidates = [candidate("A", "K1", tag="1"), candidate("B", "K2", tag="2")]
    decision = f22.make_human_decision(candidates, "A")
    reconciliation = f22.reconcile(candidates, decision)
    component = reconciliation["reconciled_component_sha256"]
    scope = AuthorityScope(case_id="CASE-1", target_type="CLAIM", target_ids=("CLAIM-1",))
    return reconciliation, component, scope


def bind(r, component, scope, **overrides):
    args = dict(
        expected_candidate_set_sha256=r["candidate_set_sha256"],
        expected_component_sha256=component,
        expected_selected_candidate_id="A",
        expected_provider_id="P",
        expected_external_scope="receipt-signing",
        p5_scope=scope,
    )
    args.update(overrides)
    return bind_reconciliation(r, **args)


class TestF23ReconciliationAuthorityBinding(unittest.TestCase):
    def test_valid_binding_is_external_only(self):
        r, component, scope = fixture()
        result = bind(r, component, scope)
        self.assertEqual(result.authority_class, "EXTERNAL_AUTHORITY_ONLY")
        self.assertEqual(result.master_promotion_state, "AUTHORITY_HOLD")
        self.assertEqual(result.canonical_effect, "NONE")
        self.assertEqual(result.byte_identity_effect, "NONE")
        self.assertEqual(result.f5_effect, "NONE")
        self.assertEqual(result.p5_scope_token, scope.token)

    def test_selected_revocation_cannot_bind(self):
        active = candidate("A", "K1", tag="1")
        revoked = candidate("R", "K1", tag="2")
        revoked["authority_assertion"] = "REVOKED"
        revoked = f22.seal_candidate({k: v for k, v in revoked.items() if k != "candidate_sha256"})
        candidates = [active, revoked]
        result = f22.reconcile(candidates, f22.make_human_decision(candidates, "R"))
        self.assertEqual(len(result["preserved_candidates"]), 2)
        scope = AuthorityScope(case_id="CASE-1", target_type="CLAIM", target_ids=("CLAIM-1",))
        with self.assertRaisesRegex(ValueError, "revocation cannot bind P5 scope"):
            bind(result, result["reconciled_component_sha256"], scope, expected_selected_candidate_id="R")

    def test_reconciliation_tamper_fails_closed(self):
        r, component, scope = fixture()
        bad = copy.deepcopy(r)
        bad["selected_candidate_id"] = "B"
        with self.assertRaisesRegex(ValueError, "reconciliation hash mismatch"):
            bind(bad, component, scope)

    def test_candidate_set_binding_mismatch_fails_closed(self):
        r, component, scope = fixture()
        with self.assertRaisesRegex(ValueError, "candidate set binding mismatch"):
            bind(r, component, scope, expected_candidate_set_sha256=h("other"))

    def test_component_binding_mismatch_fails_closed(self):
        r, component, scope = fixture()
        with self.assertRaisesRegex(ValueError, "conflict component binding mismatch"):
            bind(r, component, scope, expected_component_sha256=h("other"))

    def test_selected_candidate_binding_mismatch_fails_closed(self):
        r, component, scope = fixture()
        with self.assertRaisesRegex(ValueError, "selected candidate binding mismatch"):
            bind(r, component, scope, expected_selected_candidate_id="B")

    def test_provider_binding_mismatch_fails_closed(self):
        r, component, scope = fixture()
        with self.assertRaisesRegex(ValueError, "provider binding mismatch"):
            bind(r, component, scope, expected_provider_id="OTHER")

    def test_external_scope_binding_mismatch_fails_closed(self):
        r, component, scope = fixture()
        with self.assertRaisesRegex(ValueError, "external scope binding mismatch"):
            bind(r, component, scope, expected_external_scope="timestamp-signing")

    def test_partially_reconciled_f22_fails_closed(self):
        candidates = [
            candidate("A", "K1", provider="P1", tag="1"),
            candidate("B", "K2", provider="P1", tag="2"),
            candidate("C", "K3", provider="P2", scope="timestamp-signing", tag="3"),
            candidate("D", "K4", provider="P2", scope="timestamp-signing", tag="4"),
        ]
        decision = f22.make_human_decision(candidates, "A")
        r = f22.reconcile(candidates, decision)
        scope = AuthorityScope(case_id="CASE-1", target_type="CLAIM", target_ids=("CLAIM-1",))
        with self.assertRaisesRegex(ValueError, "not fully reconciled"):
            bind_reconciliation(
                r,
                expected_candidate_set_sha256=r["candidate_set_sha256"],
                expected_component_sha256=r["reconciled_component_sha256"],
                expected_selected_candidate_id="A",
                expected_provider_id="P1",
                expected_external_scope="receipt-signing",
                p5_scope=scope,
            )

    def test_master_hold_escalation_fails_even_if_rehashed(self):
        r, component, scope = fixture()
        bad = copy.deepcopy(r)
        bad["master_promotion_state"] = "PROMOTION_READY"
        bad["reconciliation_sha256"] = f22._hash({k:v for k,v in bad.items() if k != "reconciliation_sha256"})
        with self.assertRaisesRegex(ValueError, "master authority hold must remain"):
            bind(bad, component, scope)

    def test_canonical_effect_escalation_fails_even_if_rehashed(self):
        r, component, scope = fixture()
        bad = copy.deepcopy(r)
        bad["canonical_effect"] = "PROMOTE"
        bad["reconciliation_sha256"] = f22._hash({k:v for k,v in bad.items() if k != "reconciliation_sha256"})
        with self.assertRaisesRegex(ValueError, "canonical effect escalation forbidden"):
            bind(bad, component, scope)

    def test_byte_identity_or_f5_closure_fails_even_if_rehashed(self):
        r, component, scope = fixture()
        for field in ("byte_identity_effect", "f5_effect"):
            bad = copy.deepcopy(r)
            bad[field] = "CLOSED"
            bad["reconciliation_sha256"] = f22._hash({k:v for k,v in bad.items() if k != "reconciliation_sha256"})
            with self.assertRaisesRegex(ValueError, "upstream gate closure forbidden"):
                bind(bad, component, scope)


if __name__ == "__main__":
    unittest.main()
