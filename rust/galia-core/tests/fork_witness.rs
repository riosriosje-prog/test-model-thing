#![cfg(feature="tls-transport")]
//! GALIA v0.30: OFFLINE, deterministic synthetic witness keys.
//! No organizational independence, publication infrastructure or P5 authority.
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::fenced_coordinator::{EpochGrant,FencingCheckpoint,FencingScope};
use galia_core_shadow::independent_audit::{
    AuditTrustPin,AuditStatement,SignedAuditStatement,AUDIT_FORMAT,AUDIT_DOMAIN,
};
use galia_core_shadow::fork_witness::{
    TrustedForkWitness,ForkWitnessPolicy,ForkWitnessPayload,
    SignedForkWitnessEndorsement,expected_endorsement_payload,
    verify_fork_witness_quorum,FORK_WITNESS_FORMAT,FORK_WITNESS_DOMAIN,
};
fn pubkey(seed:u8)->String{
    hex::encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())
}
fn canonical<T:serde::Serialize>(value:&T)->Vec<u8>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v)).unwrap()
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
            pinned_observer_policy_sha256:digest("pinned-observers"),
            pinned_response_signer_public_key_hex:pubkey(92),
        },
        floor_sequence:0,floor_signed_sha256:None,
        floor_checkpoint:FencingCheckpoint{
            record_count:0,journal_tip_sha256:None,
            active_grant:None,nonce_claim_count:0,
        },
    }
}
fn checkpoint(count:u64,tip:&str)->FencingCheckpoint{
    FencingCheckpoint{
        record_count:count,journal_tip_sha256:Some(digest(tip)),
        active_grant:Some(EpochGrant{host_id:"host-a".into(),epoch:1}),
        nonce_claim_count:count-1,
    }
}
fn sign_audit(p:&AuditTrustPin,seq:u64,prev:Option<String>,
    cp:FencingCheckpoint)->SignedAuditStatement{
    let statement=AuditStatement{
        format:AUDIT_FORMAT.into(),auditor_id:p.auditor_id.clone(),
        stream_id:p.stream_id.clone(),scope_sha256:sha256(&canonical(&p.scope)),
        sequence:seq,previous_signed_sha256:prev,checkpoint:cp,
    };
    let signing_key=SigningKey::from_bytes(&[101;32]);
    SignedAuditStatement{
        signature_hex:hex::encode(signing_key.sign(
            &signing_preimage(AUDIT_DOMAIN,&statement).unwrap()
        ).to_bytes()),
        statement,
    }
}
fn histories()->(AuditTrustPin,Vec<SignedAuditStatement>,Vec<SignedAuditStatement>){
    let p=pin();
    let root=sign_audit(&p,1,None,checkpoint(1,"common"));
    let prev=Some(sha256(&canonical(&root)));
    let left=sign_audit(&p,2,prev.clone(),checkpoint(2,"left"));
    let right=sign_audit(&p,2,prev,checkpoint(2,"right"));
    (p,vec![root.clone(),left],vec![root,right])
}
fn roster(p:&AuditTrustPin)->ForkWitnessPolicy{
    ForkWitnessPolicy{
        format:FORK_WITNESS_FORMAT.into(),roster_epoch:5,
        auditor_id:p.auditor_id.clone(),
        auditor_public_key_hex:p.auditor_public_key_hex.clone(),
        audit_stream_id:p.stream_id.clone(),
        audit_scope_sha256:sha256(&canonical(&p.scope)),
        required_distinct_observers:2,
        witnesses:vec![
            TrustedForkWitness{observer_id:"a".into(),public_key_hex:pubkey(111),revoked:false},
            TrustedForkWitness{observer_id:"b".into(),public_key_hex:pubkey(112),revoked:false},
            TrustedForkWitness{observer_id:"c".into(),public_key_hex:pubkey(113),revoked:false},
        ],
    }
}
fn sign_vote(payload:ForkWitnessPayload,seed:u8)->SignedForkWitnessEndorsement{
    let key=SigningKey::from_bytes(&[seed;32]);
    SignedForkWitnessEndorsement{
        signature_hex:hex::encode(key.sign(
            &signing_preimage(FORK_WITNESS_DOMAIN,&payload).unwrap()
        ).to_bytes()),
        payload,
    }
}
fn vote(p:&AuditTrustPin,w:&ForkWitnessPolicy,
    a:&[SignedAuditStatement],b:&[SignedAuditStatement],
    id:&str,seed:u8)->SignedForkWitnessEndorsement{
    let payload=expected_endorsement_payload(p,w,a,b,id).unwrap();
    sign_vote(payload,seed)
}
#[test]fn distinct_quorum_verifies_one_specific_signed_fork(){
    let (p,a,b)=histories();let w=roster(&p);
    let result=verify_fork_witness_quorum(&p,&w,&a,&b,&[
        vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112)
    ]).unwrap();
    assert_eq!(result.first_conflicting_audit_sequence,2);
    assert_eq!(result.verified_distinct_observers,2);
    assert_eq!(result.required_distinct_observers,2);
    assert!(result.quorum_met&&result.auditor_signatures_reverified&&
        result.witness_signatures_verified);
    assert!(!result.real_independent_witness_custody_verified);
    assert!(!result.real_public_gossip_verified&&!result.historical_truth_verified);
    assert!(!result.automatic_quarantine_permitted&&!result.automatic_repair_permitted);
    assert!(!result.human_authority_verified&&!result.canonical_writeback&&
        !result.authority_transfer);
}
#[test]fn third_distinct_signature_can_endorse_the_same_packet(){
    let (p,a,b)=histories();let w=roster(&p);
    let result=verify_fork_witness_quorum(&p,&w,&a,&b,&[
        vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112),
        vote(&p,&w,&a,&b,"c",113)
    ]).unwrap();
    assert_eq!(result.verified_distinct_observers,3);
}
#[test]fn one_signature_is_insufficient_for_pinned_quorum(){
    let (p,a,b)=histories();let w=roster(&p);
    assert!(verify_fork_witness_quorum(&p,&w,&a,&b,&[
        vote(&p,&w,&a,&b,"a",111)
    ]).is_err());
}
#[test]fn same_observer_cannot_vote_twice_to_form_quorum(){
    let (p,a,b)=histories();let w=roster(&p);
    let v=vote(&p,&w,&a,&b,"a",111);
    assert!(verify_fork_witness_quorum(&p,&w,&a,&b,&[v.clone(),v]).is_err());
}
#[test]fn vote_signed_with_another_observers_key_is_rejected(){
    let (p,a,b)=histories();let w=roster(&p);
    assert!(verify_fork_witness_quorum(&p,&w,&a,&b,&[
        vote(&p,&w,&a,&b,"a",112),vote(&p,&w,&a,&b,"b",112)
    ]).is_err());
}
#[test]fn reordered_or_duplicate_roster_keys_are_invalid(){
    let (p,_,_)=histories();let mut w=roster(&p);
    w.witnesses.swap(0,1);
    assert!(w.validate(&p).is_err());
    let mut w=roster(&p);
    w.witnesses[1].public_key_hex=w.witnesses[0].public_key_hex.clone();
    assert!(w.validate(&p).is_err());
}
#[test]fn auditor_and_service_signing_keys_cannot_count_as_observers(){
    let p=pin();let mut w=roster(&p);
    w.witnesses[0].public_key_hex=p.auditor_public_key_hex.clone();
    assert!(w.validate(&p).is_err());
    let mut w=roster(&p);
    w.witnesses[0].public_key_hex=p.scope.pinned_response_signer_public_key_hex.clone();
    assert!(w.validate(&p).is_err());
}
#[test]fn revoked_observer_does_not_count_toward_minimum(){
    let (p,a,b)=histories();let mut w=roster(&p);
    w.witnesses[1].revoked=true;
    assert!(expected_endorsement_payload(&p,&w,&a,&b,"b").is_err());
    let mut w=roster(&p);
    w.witnesses[0].revoked=true;
    w.witnesses[1].revoked=true;
    assert!(w.validate(&p).is_err());
}
#[test]fn fabricated_proper_extension_is_not_fork_witnessable(){
    let (p,a,_)=histories();let w=roster(&p);
    assert!(expected_endorsement_payload(&p,&w,&a,&a,"a").is_err());
    let mut prefix=a.clone();prefix.pop();
    assert!(expected_endorsement_payload(&p,&w,&prefix,&a,"a").is_err());
}
#[test]fn changed_witness_roster_epoch_invalidates_old_votes(){
    let (p,a,b)=histories();let w=roster(&p);
    let votes=[vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112)];
    let mut new_w=w.clone();new_w.roster_epoch+=1;
    assert!(verify_fork_witness_quorum(&p,&new_w,&a,&b,&votes).is_err());
}
#[test]fn signatures_for_fork_one_do_not_certify_a_different_fork(){
    let (p,a,b)=histories();let w=roster(&p);
    let votes=[vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112)];
    let mut different=b.clone();
    different[1]=sign_audit(&p,2,Some(sha256(&canonical(&a[0]))),
        checkpoint(2,"third-fork"));
    assert!(verify_fork_witness_quorum(&p,&w,&a,&different,&votes).is_err());
}
#[test]fn tampered_auditor_statement_rejected_before_quorum_validation(){
    let (p,a,b)=histories();let w=roster(&p);
    let votes=[vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112)];
    let mut forged=b.clone();
    forged[1].statement.checkpoint.journal_tip_sha256=Some(digest("forged"));
    assert!(verify_fork_witness_quorum(&p,&w,&a,&forged,&votes).is_err());
}
#[test]fn wrong_auditor_trust_root_rejects_all_witnesses(){
    let (p,a,b)=histories();let w=roster(&p);
    let votes=[vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112)];
    let mut wrong=p.clone();wrong.auditor_public_key_hex=pubkey(105);
    assert!(verify_fork_witness_quorum(&wrong,&w,&a,&b,&votes).is_err());
}
#[test]fn unsorted_endorsements_cannot_silently_rewrite_policy_transcript(){
    let (p,a,b)=histories();let w=roster(&p);
    let votes=[vote(&p,&w,&a,&b,"b",112),vote(&p,&w,&a,&b,"a",111)];
    assert!(verify_fork_witness_quorum(&p,&w,&a,&b,&votes).is_err());
}
#[test]fn noncanonical_ed25519_signature_text_is_rejected(){
    let (p,a,b)=histories();let w=roster(&p);
    let mut votes=[vote(&p,&w,&a,&b,"a",111),vote(&p,&w,&a,&b,"b",112)];
    votes[0].signature_hex=votes[0].signature_hex.to_uppercase();
    assert!(verify_fork_witness_quorum(&p,&w,&a,&b,&votes).is_err());
}
#[test]fn unexpected_authority_fields_cannot_be_injected_into_signed_packet(){
    let (p,a,b)=histories();let w=roster(&p);
    let mut raw=serde_json::to_value(vote(&p,&w,&a,&b,"a",111)).unwrap();
    raw["payload"]["canonical_writeback"]=serde_json::json!(true);
    assert!(serde_json::from_value::<SignedForkWitnessEndorsement>(raw).is_err());
}
