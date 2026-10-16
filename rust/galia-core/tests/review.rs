//! P5 review signature fixtures: keys are TEST ONLY, not real human identities.
use ed25519_dalek::{SigningKey,Signer};
use galia_core_shadow::authority::{AuthorityScope,PromotionAuthorization};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::review::*;

fn signer(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn signature<T:serde::Serialize>(key:&SigningKey,domain:&[u8],payload:&T)->String{
    hex::encode(key.sign(&signing_preimage(domain,payload).unwrap()).to_bytes())
}
fn sha(c:u8)->String{std::iter::repeat(char::from(c)).take(64).collect()}

fn fixture()->ReviewVerificationRequest{
    let root=signer(7);let reviewer=signer(8);
    let scope=AuthorityScope{case_id:"case-1".into(),target_type:"CLAIM".into(),target_ids:vec!["claim-1".into()]};
    let auth=PromotionAuthorization{
        authorization_id:"auth-unique-11".into(),decision_id:"decision-11".into(),
        reviewer:"human-reviewer-7".into(),scope:scope.clone(),
        target_commit:"candidate-17".into(),evidence_snapshot:vec!["evidence-hash-1".into()],
        policy_version:"p5-policy-v1".into(),authorized_at:"2026-10-16T03:00:00Z".into(),
    };
    let registry=ReviewRegistry{
        format:REVIEW_REGISTRY_FORMAT.into(),namespace:"galia-tenant".into(),
        case_id:"case-1".into(),epoch:10,
        keys:vec![RegisteredReviewer{
            key_id:"key-review-7".into(),reviewer_id:"human-reviewer-7".into(),
            public_key_hex:hex::encode(reviewer.verifying_key().to_bytes()),
            case_id:"case-1".into(),target_type:"CLAIM".into(),revoked:false,
        }],
        revoked_authorization_ids:vec![],
        consumed_authorization_ids:vec![],consumed_nonce_sha256:vec![],
    };
    let decision=ReviewPayload{
        format:REVIEW_DECISION_FORMAT.into(),
        namespace:"galia-tenant".into(),case_id:"case-1".into(),
        registry_epoch:10,reviewer_key_id:"key-review-7".into(),
        decision:ReviewDecisionKind::Select,
        authorization:auth,
        manifest_sha256:sha(b'a'),nonce_sha256:sha(b'1'),
    };
    ReviewVerificationRequest{
        policy:ReviewVerificationPolicy{
            pinned_root_public_key_hex:hex::encode(root.verifying_key().to_bytes()),
            expected_namespace:"galia-tenant".into(),expected_scope:scope,
            expected_target_commit:"candidate-17".into(),
            expected_decision_id:"decision-11".into(),
            expected_manifest_sha256:sha(b'a'),
            expected_policy_version:"p5-policy-v1".into(),
            minimum_registry_epoch:10,
            independently_spent_authorization_ids:vec![],
            independently_spent_nonce_sha256:vec![],
        },
        registry:SignedReviewRegistry{
            root_signature_hex:signature(&root,REVIEW_REGISTRY_DOMAIN,&registry),
            payload:registry,
        },
        decision:SignedReviewDecision{
            reviewer_signature_hex:signature(&reviewer,REVIEW_DECISION_DOMAIN,&decision),
            payload:decision,
        },
    }
}
fn resign_root(x:&mut ReviewVerificationRequest){
    x.registry.root_signature_hex=signature(&signer(7),REVIEW_REGISTRY_DOMAIN,&x.registry.payload);
}
fn resign_review(x:&mut ReviewVerificationRequest){
    x.decision.reviewer_signature_hex=signature(&signer(8),REVIEW_DECISION_DOMAIN,&x.decision.payload);
}
fn denied(x:ReviewVerificationRequest){assert!(verify_review(&x).is_err());}
#[test]fn scoped_valid_signature_never_grants_human_authority(){
    let r=verify_review(&fixture()).unwrap();
    assert!(r.review_signature_valid&&r.active_registered_key&&r.exact_scope_matched&&r.replay_fences_checked);
    assert_eq!(r.registry_epoch,10);
    assert!(!r.human_identity_verified&&!r.human_authority_verified);
    assert!(!r.executable_guards_issued&&!r.authority_transfer&&!r.canonical_writeback);
    assert!(r.output_commit.is_none());
}
#[test]fn pinned_root_cannot_be_self_substituted(){
    let mut x=fixture();x.policy.pinned_root_public_key_hex=hex::encode(signer(9).verifying_key().to_bytes());
    denied(x);
    let mut x=fixture();x.registry.payload.epoch=11;denied(x);
}
#[test]fn delegated_key_must_be_active_and_scope_bound(){
    let mut x=fixture();x.registry.payload.keys[0].revoked=true;resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].reviewer_id="other-reviewer".into();resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].target_type="STAGE".into();resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].case_id="case-2".into();resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.keys[0].public_key_hex=x.policy.pinned_root_public_key_hex.clone();
    resign_root(&mut x);denied(x);
}
#[test]fn wrong_signature_or_reused_key_is_rejected(){
    let mut x=fixture();x.decision.reviewer_signature_hex=signature(&signer(99),REVIEW_DECISION_DOMAIN,&x.decision.payload);denied(x);
    let mut x=fixture();x.decision.reviewer_signature_hex=signature(&signer(8),REVIEW_REGISTRY_DOMAIN,&x.decision.payload);denied(x);
    let mut x=fixture();x.registry.payload.keys.push(x.registry.payload.keys[0].clone());resign_root(&mut x);denied(x);
    let mut x=fixture();let mut extra=x.registry.payload.keys[0].clone();extra.key_id="new-key-id".into();
    x.registry.payload.keys.push(extra);resign_root(&mut x);denied(x);
}
#[test]fn signed_select_cannot_change_to_hold_or_reject(){
    let mut x=fixture();x.decision.payload.decision=ReviewDecisionKind::Hold;resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.decision=ReviewDecisionKind::Reject;resign_review(&mut x);denied(x);
}
#[test]fn exact_claim_scope_target_decision_and_policy_required(){
    let mut x=fixture();x.decision.payload.authorization.scope.target_ids=vec!["claim-other".into()];
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.target_commit="candidate-18".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.decision_id="other-decision".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.policy_version="wrong-policy".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.authorization.reviewer="wrong-reviewer".into();
    resign_review(&mut x);denied(x);
}
#[test]fn signed_manifest_and_nonce_cannot_be_moved_between_cases(){
    let mut x=fixture();x.decision.payload.manifest_sha256=sha(b'b');resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.case_id="case-2".into();resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.namespace="other-tenant".into();resign_review(&mut x);denied(x);
    let mut x=fixture();x.decision.payload.registry_epoch=11;resign_review(&mut x);denied(x);
}
#[test]fn replay_and_revocation_fences_reject_even_valid_signatures(){
    let mut x=fixture();x.registry.payload.revoked_authorization_ids.push("auth-unique-11".into());
    resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.consumed_authorization_ids.push("auth-unique-11".into());
    resign_root(&mut x);denied(x);
    let mut x=fixture();x.registry.payload.consumed_nonce_sha256.push(sha(b'1'));
    resign_root(&mut x);denied(x);
    let mut x=fixture();x.policy.independently_spent_authorization_ids.push("auth-unique-11".into());
    denied(x);
    let mut x=fixture();x.policy.independently_spent_nonce_sha256.push(sha(b'1'));denied(x);
}
#[test]fn old_signed_registry_is_rejected_by_pinned_epoch(){
    let mut x=fixture();x.policy.minimum_registry_epoch=11;denied(x);
    let mut x=fixture();x.registry.payload.epoch=9;x.decision.payload.registry_epoch=9;
    resign_root(&mut x);resign_review(&mut x);denied(x);
}
#[test]fn unknown_fields_and_malformed_payload_rejected(){
    let mut x=serde_json::to_value(fixture()).unwrap();x["claims_canonical"]=serde_json::json!(true);
    assert!(serde_json::from_value::<ReviewVerificationRequest>(x).is_err());
    let mut x=fixture();x.decision.payload.nonce_sha256="not-sha".into();
    resign_review(&mut x);denied(x);
    let mut x=fixture();x.policy.expected_manifest_sha256="B".repeat(64);denied(x);
}
#[test]fn future_registry_can_revoke_previously_signed_decision(){
    let mut x=fixture();
    assert!(verify_review(&x).is_ok());
    x.registry.payload.epoch=11;
    x.decision.payload.registry_epoch=11;
    resign_review(&mut x);
    x.registry.payload.revoked_authorization_ids.push("auth-unique-11".into());
    resign_root(&mut x);
    denied(x);
}
#[test]fn review_key_does_not_sign_root_registry(){
    let mut x=fixture();
    x.registry.root_signature_hex=signature(&signer(8),REVIEW_REGISTRY_DOMAIN,&x.registry.payload);
    denied(x);
}
