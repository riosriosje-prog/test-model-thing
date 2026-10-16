#![cfg(feature="scratch-store")]
//! GALIA witness continuity adversarial tests; keys are fixed test vectors only.
use ed25519_dalek::{SigningKey,Signer};
use galia_core_shadow::witness::{
    MonotonicWitness,InMemoryWitness,WitnessConfig,WitnessConsume,FORMAT,
};
use galia_core_shadow::witness_proof::*;
use galia_core_shadow::witness_continuity::*;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::attestation::signing_preimage;
fn sk(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn key(seed:u8)->String{hex::encode(sk(seed).verifying_key().to_bytes())}
fn digest(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn sig<T:serde::Serialize>(seed:u8,domain:&[u8],value:&T)->String{
    hex::encode(sk(seed).sign(&signing_preimage(domain,value).unwrap()).to_bytes())
}
fn canon<T:serde::Serialize>(v:&T)->Vec<u8>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x)).unwrap()
}
fn copy<T:serde::Serialize+serde::de::DeserializeOwned>(v:&T)->T{
    serde_json::from_value(serde_json::to_value(v).unwrap()).unwrap()
}
fn signed_receipt(receipt:galia_core_shadow::witness::WitnessReceipt,seed:u8,id:&str)
 ->SignedWitnessReceipt{
    SignedWitnessReceipt{signer_key_id:id.into(),
        signature_hex:sig(seed,RECEIPT_DOMAIN,&receipt),receipt}
}
fn make_rotation(index:u64,old_seed:u8,new_seed:u8,old_id:&str,new_id:&str,
    epoch:u64,prior:Option<String>)->WitnessRotation{
    let payload=WitnessRotationPayload{
        format:ROTATION_FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        effective_after_count:index,old_signer_key_id:old_id.into(),
        new_signer_key_id:new_id.into(),new_witness_public_key_hex:key(new_seed),
        minimum_registry_epoch:epoch,previous_rotation_sha256:prior,
    };
    WitnessRotation{
        root_signature_hex:sig(88,ROTATION_DOMAIN,&payload),
        old_signer_signature_hex:sig(old_seed,ROTATION_DOMAIN,&payload),payload,
    }
}
fn fixture()->WitnessContinuityRequest{
    let w=InMemoryWitness::new(WitnessConfig{
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        pinned_root_public_key_hex:key(7),initial_registry_epoch:10,
    }).unwrap();
    let mut prior=None;let mut receipts=vec![];
    for (i,epoch) in [10u64,11,12].into_iter().enumerate(){
        let request=WitnessConsume{
            format:FORMAT.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
            pinned_root_public_key_hex:key(7),registry_epoch:epoch,
            authorization_id:format!("auth-{}",i+1),
            nonce_sha256:digest(char::from(b'1'+i as u8)),
            signed_decision_sha256:digest('a'),expected_tip_sha256:prior,
        };
        let receipt=w.consume(&request).unwrap();
        prior=Some(receipt.tip_sha256.clone());
        receipts.push(receipt);
    }
    let first=make_rotation(1,33,34,"w1","w2",11,None);
    let first_hash=sha256(&canon(&first));
    let second=make_rotation(2,34,35,"w2","w3",12,Some(first_hash));
    let o=w.observe().unwrap();
    let signed_o=SignedWitnessObservation{
        signer_key_id:"w3".into(),signature_hex:sig(35,OBSERVATION_DOMAIN,&o),
        observation:o,
    };
    WitnessContinuityRequest{
        anchor:WitnessTrustAnchor{
            signer_key_id:"w1".into(),pinned_witness_public_key_hex:key(33),
            pinned_review_root_public_key_hex:key(7),expected_namespace:"tenant".into(),
            expected_case_id:"cangrejos".into(),minimum_registry_epoch:10,
            minimum_spent_count:0,floor_tip_sha256:None,
        },
        pinned_rotation_root_public_key_hex:key(88),
        rotations:vec![first,second],
        extension:vec![
            signed_receipt(copy(&receipts[0]),33,"w1"),
            signed_receipt(copy(&receipts[1]),34,"w2"),
            signed_receipt(copy(&receipts[2]),35,"w3"),
        ],
        current_observation:signed_o,
    }
}
#[test]fn signed_three_event_continuity_two_rotations_passes(){
    let result=verify_continuity(&fixture()).unwrap();
    assert_eq!(result.final_count,3);
    assert_eq!(result.receipts_verified,3);
    assert_eq!(result.rotations_verified,2);
    assert_eq!(result.ending_signer_key_id,"w3");
    assert_eq!(result.final_registry_epoch,12);
    assert!(!result.canonical_writeback&&!result.human_authority_verified);
    assert!(!result.human_identity_verified&&!result.authority_transfer);
    assert!(!result.executable_guards_issued);
}
#[test]fn missing_middle_receipt_and_reordering_are_rejected(){
    let mut f=fixture();f.extension.remove(1);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.extension.swap(0,1);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.extension.remove(2);
    assert!(verify_continuity(&f).is_err());
}
#[test]fn old_signer_cannot_sign_after_rotation(){
    let mut f=fixture();
    f.extension[1].signer_key_id="w1".into();
    f.extension[1].signature_hex=sig(33,RECEIPT_DOMAIN,&f.extension[1].receipt);
    assert!(verify_continuity(&f).is_err());
}
#[test]fn tampered_rotation_root_signature_and_wrong_previous_signer_fail(){
    let mut f=fixture();f.rotations[0].root_signature_hex=sig(77,ROTATION_DOMAIN,&f.rotations[0].payload);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.rotations[0].old_signer_signature_hex=sig(99,ROTATION_DOMAIN,&f.rotations[0].payload);
    assert!(verify_continuity(&f).is_err());
}
#[test]fn root_substitution_and_role_confusion_fail(){
    let mut f=fixture();f.pinned_rotation_root_public_key_hex=key(91);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.pinned_rotation_root_public_key_hex=f.anchor.pinned_review_root_public_key_hex.clone();
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.pinned_rotation_root_public_key_hex=f.anchor.pinned_witness_public_key_hex.clone();
    assert!(verify_continuity(&f).is_err());
}
#[test]fn rotation_history_hash_and_effective_count_are_enforced(){
    let mut f=fixture();
    f.rotations[1].payload.previous_rotation_sha256=Some(digest('f'));
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();
    f.rotations[0].payload.effective_after_count=2;
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();
    f.rotations[1].payload.effective_after_count=4;
    assert!(verify_continuity(&f).is_err());
}
#[test]fn replayed_signer_identity_or_public_key_rejected(){
    let mut f=fixture();f.rotations[1].payload.new_signer_key_id="w1".into();
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.rotations[1].payload.new_witness_public_key_hex=key(33);
    assert!(verify_continuity(&f).is_err());
}
#[test]fn signed_terminal_observation_must_agree_with_every_receipt(){
    let mut f=fixture();
    f.current_observation.observation.spent_count=2;
    f.current_observation.signature_hex=sig(35,OBSERVATION_DOMAIN,&f.current_observation.observation);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();
    f.current_observation.observation.tip_sha256=Some(digest('f'));
    f.current_observation.signature_hex=sig(35,OBSERVATION_DOMAIN,&f.current_observation.observation);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();f.current_observation.signer_key_id="w1".into();
    assert!(verify_continuity(&f).is_err());
}
#[test]fn receipt_mutation_even_if_resigned_breaks_prior_link(){
    let mut f=fixture();
    f.extension[1].receipt.tip_sha256=digest('f');
    f.extension[1].signature_hex=sig(34,RECEIPT_DOMAIN,&f.extension[1].receipt);
    assert!(verify_continuity(&f).is_err());
    let mut f=fixture();
    f.extension[2].receipt.registry_epoch=11;
    f.extension[2].signature_hex=sig(35,RECEIPT_DOMAIN,&f.extension[2].receipt);
    assert!(verify_continuity(&f).is_err());
}
#[test]fn pinned_historical_prefix_allows_exact_extension_only(){
    let f=fixture();
    let mut pinned=fixture();
    let first=&f.extension[0].receipt;
    pinned.anchor.minimum_spent_count=1;
    pinned.anchor.floor_tip_sha256=Some(first.tip_sha256.clone());
    pinned.extension.remove(0);
    let report=verify_continuity(&pinned).unwrap();
    assert_eq!(report.receipts_verified,2);
    assert_eq!(report.start_count,1);
    pinned.anchor.floor_tip_sha256=Some(digest('f'));
    assert!(verify_continuity(&pinned).is_err());
}
#[test]fn no_signed_extension_path_to_newer_observation_is_rejected(){
    let mut f=fixture();f.extension.clear();f.rotations.clear();
    assert!(verify_continuity(&f).is_err());
}
#[test]fn duplicate_nonce_in_resigned_extension_is_rejected(){
    let mut f=fixture();
    f.extension[2].receipt.nonce_sha256=f.extension[1].receipt.nonce_sha256.clone();
    f.extension[2].signature_hex=sig(35,RECEIPT_DOMAIN,&f.extension[2].receipt);
    assert!(verify_continuity(&f).is_err());
}
