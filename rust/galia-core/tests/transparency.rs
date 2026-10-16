#![cfg(feature="scratch-store")]
//! Noncanonical gossip fixture. Synthetic keys: signatures do not establish real independence.
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::transparency::*;
use galia_core_shadow::witness::{
    InMemoryWitness,MonotonicWitness,WitnessConfig,WitnessConsume,WitnessObservation,WitnessReceipt,FORMAT
};
use galia_core_shadow::witness_proof::*;
use galia_core_shadow::witness_continuity::*;
fn sk(c:u8)->SigningKey{SigningKey::from_bytes(&[c;32])}
fn pubkey(c:u8)->String{hex::encode(sk(c).verifying_key().to_bytes())}
fn sign<T:serde::Serialize>(c:u8,domain:&[u8],v:&T)->String{
    hex::encode(sk(c).sign(&signing_preimage(domain,v).unwrap()).to_bytes())
}
fn value<T:serde::Serialize+serde::de::DeserializeOwned>(v:&T)->T{
    serde_json::from_value(serde_json::to_value(v).unwrap()).unwrap()
}
fn cp()->WitnessTrustAnchor{
    WitnessTrustAnchor{
        signer_key_id:"witness1".into(),
        pinned_witness_public_key_hex:pubkey(33),
        pinned_review_root_public_key_hex:pubkey(7),
        expected_namespace:"tenant".into(),expected_case_id:"cangrejos".into(),
        minimum_registry_epoch:10,minimum_spent_count:0,floor_tip_sha256:None
    }
}
fn policy()->ObserverPolicy{
    ObserverPolicy{
        witness_anchor:cp(),roster_epoch:3,required_quorum:2,
        observers:vec![
            TrustedObserver{observer_id:"observer-a".into(),public_key_hex:pubkey(51),revoked:false},
            TrustedObserver{observer_id:"observer-b".into(),public_key_hex:pubkey(52),revoked:false},
            TrustedObserver{observer_id:"observer-c".into(),public_key_hex:pubkey(53),revoked:true},
        ]
    }
}
fn endorse(o:&SignedWitnessObservation,name:&str,seed:u8)->SignedGossipEndorsement{
    let raw=serde_json::to_value(o).and_then(|x|serde_json::to_vec(&x)).unwrap();
    let p=GossipEndorsementPayload{
        format:GOSSIP_FORMAT.into(),roster_epoch:3,observer_id:name.into(),
        namespace:o.observation.namespace.clone(),case_id:o.observation.case_id.clone(),
        witness_observation_sha256:sha256(&raw),
        spent_count:o.observation.spent_count,
        tip_sha256:o.observation.tip_sha256.clone(),
        registry_epoch:o.observation.registry_epoch,
    };
    SignedGossipEndorsement{signature_hex:sign(seed,GOSSIP_DOMAIN,&p),payload:p}
}
fn observation(count:u64,tip:Option<String>,epoch:u64)->SignedWitnessObservation{
    let o=WitnessObservation{
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        spent_count:count,tip_sha256:tip,registry_epoch:epoch,
    };
    SignedWitnessObservation{signer_key_id:"witness1".into(),
        signature_hex:sign(33,OBSERVATION_DOMAIN,&o),observation:o}
}
fn publication(o:SignedWitnessObservation)->PublishedWitnessView{
    PublishedWitnessView{
        endorsements:vec![endorse(&o,"observer-a",51),endorse(&o,"observer-b",52)],
        signed_observation:o
    }
}
fn history()->(PublishedWitnessView,PublishedWitnessView,WitnessContinuityRequest){
    let w=InMemoryWitness::new(WitnessConfig{
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        pinned_root_public_key_hex:pubkey(7),initial_registry_epoch:10,
    }).unwrap();
    let first=w.consume(&WitnessConsume{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        pinned_root_public_key_hex:pubkey(7),registry_epoch:10,
        authorization_id:"a1".into(),nonce_sha256:"1".repeat(64),
        signed_decision_sha256:"a".repeat(64),expected_tip_sha256:None,
    }).unwrap();
    let before=publication(observation(1,Some(first.tip_sha256.clone()),10));
    let second=w.consume(&WitnessConsume{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        pinned_root_public_key_hex:pubkey(7),registry_epoch:11,
        authorization_id:"a2".into(),nonce_sha256:"2".repeat(64),
        signed_decision_sha256:"b".repeat(64),expected_tip_sha256:Some(first.tip_sha256.clone()),
    }).unwrap();
    let third=w.consume(&WitnessConsume{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        pinned_root_public_key_hex:pubkey(7),registry_epoch:11,
        authorization_id:"a3".into(),nonce_sha256:"3".repeat(64),
        signed_decision_sha256:"c".repeat(64),expected_tip_sha256:Some(second.tip_sha256.clone()),
    }).unwrap();
    let after=publication(observation(3,Some(third.tip_sha256.clone()),11));
    let mut anchor=cp();
    anchor.minimum_spent_count=1;
    anchor.floor_tip_sha256=Some(first.tip_sha256);
    anchor.minimum_registry_epoch=10;
    let signed=|receipt:WitnessReceipt|{
        SignedWitnessReceipt{signer_key_id:"witness1".into(),
            signature_hex:sign(33,RECEIPT_DOMAIN,&receipt),receipt}
    };
    let proof=WitnessContinuityRequest{
        anchor,pinned_rotation_root_public_key_hex:pubkey(88),rotations:vec![],
        extension:vec![signed(second),signed(third)],
        current_observation:value(&after.signed_observation),
    };
    (before,after,proof)
}
#[test]fn two_out_of_band_pinned_observer_keys_pass_quorum(){
    let o=publication(observation(0,None,10));
    let r=verify_publication(&o,&policy()).unwrap();
    assert_eq!(r.observer_quorum,2);
    assert_eq!(r.count,0);
    assert!(!r.human_authority_verified&&!r.authority_transfer&&!r.canonical_writeback);
}
#[test]fn one_signer_and_duplicate_signer_fail_closed(){
    let mut o=publication(observation(0,None,10));
    o.endorsements.truncate(1);
    assert!(verify_publication(&o,&policy()).is_err());
    let mut o=publication(observation(0,None,10));
    o.endorsements[1]=value(&o.endorsements[0]);
    assert!(verify_publication(&o,&policy()).is_err());
}
#[test]fn revoked_unknown_and_role_confused_observers_cannot_vote(){
    let mut o=publication(observation(0,None,10));
    o.endorsements[1]=endorse(&o.signed_observation,"observer-c",53);
    assert!(verify_publication(&o,&policy()).is_err());
    let mut o=publication(observation(0,None,10));
    o.endorsements[1]=endorse(&o.signed_observation,"observer-x",58);
    assert!(verify_publication(&o,&policy()).is_err());
    let mut p=policy();
    p.observers[0].public_key_hex=pubkey(33);
    assert!(verify_publication(&publication(observation(0,None,10)),&p).is_err());
}
#[test]fn mutated_observer_payload_signature_and_witness_observation_fail(){
    let mut o=publication(observation(0,None,10));
    o.endorsements[0].payload.observer_id="observer-b".into();
    assert!(verify_publication(&o,&policy()).is_err());
    let mut o=publication(observation(0,None,10));
    o.endorsements[0].payload.witness_observation_sha256="f".repeat(64);
    o.endorsements[0].signature_hex=sign(51,GOSSIP_DOMAIN,&o.endorsements[0].payload);
    assert!(verify_publication(&o,&policy()).is_err());
    let mut o=publication(observation(0,None,10));
    o.signed_observation.observation.registry_epoch=12;
    assert!(verify_publication(&o,&policy()).is_err());
}
#[test]fn independently_pinned_key_and_roster_floor_required(){
    let mut p=policy();p.observers[1].public_key_hex=pubkey(66);
    assert!(verify_publication(&publication(observation(0,None,10)),&p).is_err());
    let mut p=policy();p.roster_epoch=4;
    assert!(verify_publication(&publication(observation(0,None,10)),&p).is_err());
    let mut p=policy();p.required_quorum=3;
    assert!(verify_publication(&publication(observation(0,None,10)),&p).is_err());
    let mut p=policy();p.witness_anchor.minimum_spent_count=1;
    p.witness_anchor.floor_tip_sha256=Some("1".repeat(64));
    assert!(verify_publication(&publication(observation(0,None,10)),&p).is_err());
}
#[test]fn two_signed_and_endorsed_conflicting_tips_produce_evidence(){
    let left=publication(observation(1,Some("a".repeat(64)),10));
    let right=publication(observation(1,Some("b".repeat(64)),10));
    let e=compare_publications(&left,&right,&policy()).unwrap();
    assert_eq!(e.kind,ComparisonKind::ConflictingSignedState);
    assert!(e.witness_equivocation_evidence);
    assert_ne!(e.left_observation_sha256,e.right_observation_sha256);
    assert!(!e.human_authority_verified);
}
#[test]fn signed_observation_same_height_epoch_conflict_is_evidence(){
    let left=publication(observation(1,Some("a".repeat(64)),10));
    let right=publication(observation(1,Some("a".repeat(64)),11));
    let e=compare_publications(&left,&right,&policy()).unwrap();
    assert_eq!(e.kind,ComparisonKind::ConflictingSignedState);
}
#[test]fn same_signed_state_is_not_fork_evidence(){
    let l=publication(observation(1,Some("a".repeat(64)),10));
    let r=publication(observation(1,Some("a".repeat(64)),10));
    let e=compare_publications(&l,&r,&policy()).unwrap();
    assert_eq!(e.kind,ComparisonKind::SameSignedState);
    assert!(!e.witness_equivocation_evidence);
}
#[test]fn different_heights_do_not_automatically_prove_extension(){
    let (l,r,_)=history();
    let cmp=compare_publications(&l,&r,&policy()).unwrap();
    assert_eq!(cmp.kind,ComparisonKind::DifferentHeightExtensionNotEstablished);
    assert!(!cmp.witness_equivocation_evidence);
}
#[test]fn full_signed_suffix_plus_quorum_proves_claimed_extension(){
    let (l,r,proof)=history();
    let out=verify_publication_extension(&l,&r,&policy(),&policy(),&proof).unwrap();
    assert_eq!(out.kind,ComparisonKind::VerifiedSignedExtension);
    assert!(!out.witness_equivocation_evidence);
}
#[test]fn omitted_or_reordered_receipt_blocks_extension(){
    let (l,r,mut p)=history();
    p.extension.remove(0);
    assert!(verify_publication_extension(&l,&r,&policy(),&policy(),&p).is_err());
    let (l,r,mut p)=history();
    p.extension.swap(0,1);
    assert!(verify_publication_extension(&l,&r,&policy(),&policy(),&p).is_err());
}
#[test]fn swapped_earlier_anchor_and_terminal_observation_fail(){
    let (l,r,mut p)=history();
    p.anchor.floor_tip_sha256=Some("f".repeat(64));
    assert!(verify_publication_extension(&l,&r,&policy(),&policy(),&p).is_err());
    let (l,r,mut p)=history();
    p.current_observation.observation.registry_epoch+=1;
    p.current_observation.signature_hex=sign(33,OBSERVATION_DOMAIN,&p.current_observation.observation);
    assert!(verify_publication_extension(&l,&r,&policy(),&policy(),&p).is_err());
}
#[test]fn rotated_observer_roster_without_authorized_transition_blocks_extension(){
    let (l,r,p)=history();
    let mut policy2=policy();
    policy2.roster_epoch=4;
    assert!(verify_publication_extension(&l,&r,&policy(),&policy2,&p).is_err());
    let mut policy2=policy();
    policy2.observers[0].public_key_hex=pubkey(59);
    assert!(verify_publication_extension(&l,&r,&policy(),&policy2,&p).is_err());
}
#[test]fn unknown_fields_and_insecure_quorum_rejected(){
    let mut p=policy();p.required_quorum=1;
    assert!(p.validate().is_err());
    let v=serde_json::json!({
        "payload":{
            "format":GOSSIP_FORMAT,
            "observer_id":"one",
            "roster_epoch":3,
            "namespace":"tenant",
            "case_id":"cangrejos",
            "witness_observation_sha256":"f".repeat(64),
            "spent_count":0,
            "tip_sha256":null,
            "registry_epoch":10,
            "extra":true
        },
        "signature_hex":"0".repeat(128)
    });
    assert!(serde_json::from_value::<SignedGossipEndorsement>(v).is_err());
}
