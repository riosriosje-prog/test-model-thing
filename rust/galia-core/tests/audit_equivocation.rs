#![cfg(feature="tls-transport")]
//! GALIA v0.29: synthetic, OFFLINE signed-auditor fork evidence.
//! Test keys are deterministic; they are NOT independently held real keys.
use ed25519_dalek::{SigningKey,Signer};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::audit_equivocation::{
    compare_signed_audit_branches,AuditBranchFinding,
};
use galia_core_shadow::fenced_coordinator::{
    EpochGrant,FencingCheckpoint,FencingScope,
};
use galia_core_shadow::independent_audit::{
    AuditTrustPin,AuditStatement,SignedAuditStatement,
    AUDIT_FORMAT,AUDIT_DOMAIN,verify_signed_audit_chain,
};

fn pubkey(seed:u8)->String{
    hex::encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())
}
fn canonical<T:serde::Serialize>(v:&T)->Vec<u8>{
    serde_json::to_value(v).and_then(|v|serde_json::to_vec(&v)).unwrap()
}
fn digest(s:&str)->String{sha256(s.as_bytes())}
fn pin()->AuditTrustPin{
    AuditTrustPin{
        auditor_id:"external-auditor-a".into(),
        auditor_public_key_hex:pubkey(101),
        stream_id:"signed-log-a".into(),
        scope:FencingScope{
            namespace:"tenant".into(),case_id:"cangrejos".into(),
            service_id:"test-service".into(),
            pinned_observer_policy_sha256:digest("observer-policy"),
            pinned_response_signer_public_key_hex:pubkey(92),
        },
        floor_sequence:0,floor_signed_sha256:None,
        floor_checkpoint:FencingCheckpoint{
            record_count:0,journal_tip_sha256:None,
            active_grant:None,nonce_claim_count:0,
        },
    }
}
fn cp(n:u64,tag:&str)->FencingCheckpoint{
    if n==0{return pin().floor_checkpoint}
    FencingCheckpoint{
        record_count:n,journal_tip_sha256:Some(digest(tag)),
        active_grant:Some(EpochGrant{host_id:"host-a".into(),epoch:1}),
        nonce_claim_count:n-1,
    }
}
fn signed(pin:&AuditTrustPin,seq:u64,prev:Option<String>,cp:FencingCheckpoint)->SignedAuditStatement{
    let statement=AuditStatement{
        format:AUDIT_FORMAT.into(),auditor_id:pin.auditor_id.clone(),
        stream_id:pin.stream_id.clone(),
        scope_sha256:sha256(&canonical(&pin.scope)),
        sequence:seq,previous_signed_sha256:prev,checkpoint:cp,
    };
    let sk=SigningKey::from_bytes(&[101;32]);
    SignedAuditStatement{
        signature_hex:hex::encode(sk.sign(
            &signing_preimage(AUDIT_DOMAIN,&statement).unwrap()
        ).to_bytes()),statement,
    }
}
fn tip(a:&SignedAuditStatement)->String{sha256(&canonical(a))}
#[test]fn identical_signed_histories_are_not_equivocation(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let r=compare_signed_audit_branches(&p,&[a.clone()],&[a]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::IdenticalSignedHistory);
    assert_eq!(r.shared_signed_prefix_count,1);
    assert!(r.fork.is_none());
}
#[test]fn proper_extension_is_not_a_fork(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let b=signed(&p,2,Some(tip(&a)),cp(2,"b"));
    let r=compare_signed_audit_branches(&p,&[a.clone()],&[a,b]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::VerifiedPrefixExtension);
    assert_eq!(r.shared_signed_prefix_count,1);
    assert!(r.fork.is_none());
}
#[test]fn shorter_branch_can_be_on_right_without_false_fork(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let b=signed(&p,2,Some(tip(&a)),cp(2,"b"));
    let r=compare_signed_audit_branches(&p,&[a.clone(),b],&[a]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::VerifiedPrefixExtension);
    assert!(r.fork.is_none());
}
#[test]fn same_sequence_conflicting_signed_checkpoint_is_evidence(){
    let p=pin();
    let a=signed(&p,1,None,cp(1,"left"));
    let b=signed(&p,1,None,cp(1,"right"));
    let r=compare_signed_audit_branches(&p,&[a.clone()],&[b.clone()]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::SignedAuditorForkEvidence);
    assert_eq!(r.shared_signed_prefix_count,0);
    let f=r.fork.unwrap();
    assert_eq!(f.first_conflicting_sequence,1);
    assert!(f.shared_previous_signed_sha256.is_none());
    assert_eq!(f.left_signed_sha256,tip(&a));
    assert_eq!(f.right_signed_sha256,tip(&b));
    assert!(f.signed_checkpoint_diverged&&f.both_signatures_validated);
    assert!(!f.real_independent_auditor_custody_verified&&!f.canonical_writeback);
}
#[test]fn first_divergence_after_shared_prefix_is_located_correctly(){
    let p=pin();let first=signed(&p,1,None,cp(1,"first"));
    let a=signed(&p,2,Some(tip(&first)),cp(2,"left"));
    let b=signed(&p,2,Some(tip(&first)),cp(2,"right"));
    let r=compare_signed_audit_branches(&p,
        &[first.clone(),a],&[first.clone(),b]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::SignedAuditorForkEvidence);
    assert_eq!(r.shared_signed_prefix_count,1);
    let f=r.fork.unwrap();
    assert_eq!(f.first_conflicting_sequence,2);
    assert_eq!(f.shared_previous_signed_sha256,Some(tip(&first)));
}
#[test]fn audit_sequence_disagreement_is_evidence_even_if_heights_differ(){
    let p=pin();
    let a=signed(&p,1,None,cp(1,"a"));
    let b=signed(&p,1,None,cp(2,"b"));
    let r=compare_signed_audit_branches(&p,&[a],&[b]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::SignedAuditorForkEvidence);
    assert!(r.fork.unwrap().signed_checkpoint_diverged);
}
#[test]fn valid_signed_but_invented_audit_does_not_claim_historical_truth(){
    let p=pin();
    let signed_fiction=signed(&p,1,None,cp(99,"invented"));
    let other=signed(&p,1,None,cp(90,"other-invented"));
    let result=compare_signed_audit_branches(&p,
        &[signed_fiction],&[other]).unwrap();
    assert_eq!(result.finding,AuditBranchFinding::SignedAuditorForkEvidence);
    assert!(!result.signed_statements_prove_historical_truth);
    assert!(!result.real_public_gossip_verified);
    assert!(!result.automatic_quarantine_or_repair_permitted);
    assert!(!result.human_authority_verified);
    assert!(!result.canonical_writeback&&!result.authority_transfer);
}
#[test]fn forged_signature_cannot_manufacture_a_fork(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let mut b=signed(&p,1,None,cp(1,"b"));
    let key=SigningKey::from_bytes(&[102;32]);
    b.signature_hex=hex::encode(key.sign(
        &signing_preimage(AUDIT_DOMAIN,&b.statement).unwrap()
    ).to_bytes());
    assert!(compare_signed_audit_branches(&p,&[a],&[b]).is_err());
}
#[test]fn tampered_signed_payload_is_rejected_before_comparison(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let mut b=a.clone();
    b.statement.checkpoint.journal_tip_sha256=Some(digest("tamper"));
    assert!(compare_signed_audit_branches(&p,&[a],&[b]).is_err());
}
#[test]fn unrelated_scope_does_not_produce_false_attributed_evidence(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let mut wrong=pin();wrong.scope.case_id="foreign".into();
    assert!(compare_signed_audit_branches(&wrong,&[a.clone()],&[a]).is_err());
}
#[test]fn unknown_external_auditor_key_rejected(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let mut wrong=pin();wrong.auditor_public_key_hex=pubkey(103);
    assert!(compare_signed_audit_branches(&wrong,&[a.clone()],&[a]).is_err());
}
#[test]fn nonconsecutive_audit_sequence_not_comparable(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let skipped=signed(&p,3,Some(tip(&a)),cp(3,"c"));
    assert!(compare_signed_audit_branches(&p,&[a.clone(),skipped],&[a]).is_err());
}
#[test]fn mismatched_prior_signed_hash_rejected(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let bad=signed(&p,2,Some(digest("forged-prior")),cp(2,"b"));
    assert!(compare_signed_audit_branches(&p,&[a.clone(),bad],&[a]).is_err());
}
#[test]fn historical_external_floor_can_be_pinned_and_extended(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    let b=signed(&p,2,Some(tip(&a)),cp(2,"b"));
    let mut advanced=p;
    advanced.floor_sequence=1;
    advanced.floor_signed_sha256=Some(tip(&a));
    advanced.floor_checkpoint=a.statement.checkpoint;
    assert!(verify_signed_audit_chain(&advanced,&[b.clone()]).is_ok());
    let c=signed(&advanced,2,Some(tip(&a)),cp(2,"alt"));
    let r=compare_signed_audit_branches(&advanced,&[b],&[c]).unwrap();
    assert_eq!(r.finding,AuditBranchFinding::SignedAuditorForkEvidence);
    assert_eq!(r.fork.unwrap().first_conflicting_sequence,2);
}
#[test]fn empty_branch_and_unknown_authority_fields_are_rejected(){
    let p=pin();let a=signed(&p,1,None,cp(1,"a"));
    assert!(compare_signed_audit_branches(&p,&[],&[a.clone()]).is_err());
    let mut raw=serde_json::to_value(a).unwrap();
    raw["statement"]["canonical_writeback"]=serde_json::json!(true);
    assert!(serde_json::from_value::<SignedAuditStatement>(raw).is_err());
}
