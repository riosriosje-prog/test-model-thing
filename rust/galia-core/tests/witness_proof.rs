#![cfg(feature="scratch-store")]
//! v0.11 protocol simulations. Signing keys are test-only and NEVER persisted
//! by GALIA; this mock is not a deployed remote witness.
use std::sync::Arc;
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::durable_witness::DurableScratchWitness;
use galia_core_shadow::witness::{
    MonotonicWitness,WitnessConfig,WitnessConsume,WitnessReceipt,WitnessObservation,FORMAT,
};
use galia_core_shadow::witness_proof::*;
use galia_core_shadow::attestation::signing_preimage;
fn h(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn signer(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn sign<T:serde::Serialize>(key:&SigningKey,domain:&[u8],value:&T)->String{
    hex::encode(key.sign(&signing_preimage(domain,value).unwrap()).to_bytes())
}
fn cfg()->WitnessConfig{
    WitnessConfig{namespace:"t1".into(),case_id:"c1".into(),
        pinned_root_public_key_hex:hex::encode(signer(7).verifying_key().to_bytes()),
        initial_registry_epoch:10}
}
fn trust()->WitnessTrustAnchor{
    WitnessTrustAnchor{
        signer_key_id:"witness-key-1".into(),
        pinned_witness_public_key_hex:hex::encode(signer(33).verifying_key().to_bytes()),
        pinned_review_root_public_key_hex:cfg().pinned_root_public_key_hex,
        expected_namespace:"t1".into(),expected_case_id:"c1".into(),
        minimum_registry_epoch:10,minimum_spent_count:0,floor_tip_sha256:None,
    }
}
fn req(tip:Option<String>)->WitnessConsume{
    WitnessConsume{format:FORMAT.into(),namespace:"t1".into(),case_id:"c1".into(),
        pinned_root_public_key_hex:cfg().pinned_root_public_key_hex,
        registry_epoch:10,authorization_id:"auth-1".into(),
        nonce_sha256:h('1'),signed_decision_sha256:h('a'),
        expected_tip_sha256:tip}
}
struct SignedMock{
    delegate:Arc<DurableScratchWitness>,key:SigningKey,
    wrong_key:bool,mutate_receipt:bool,mutate_observation:bool,
}
impl SignedMock{
    fn new(store:DurableScratchWitness)->Self{
        Self{delegate:Arc::new(store),key:signer(33),wrong_key:false,
            mutate_receipt:false,mutate_observation:false}
    }
    fn signed_receipt(&self,mut r:WitnessReceipt)->SignedWitnessReceipt{
        let signature_hex=sign(&self.key,RECEIPT_DOMAIN,&r);
        if self.mutate_receipt{r.signed_decision_sha256=h('f');}
        SignedWitnessReceipt{
            signer_key_id:if self.wrong_key{"wrong".into()}else{"witness-key-1".into()},
            receipt:r,signature_hex}
    }
}
impl SignedWitnessTransport for SignedMock{
    fn signed_observe(&self)->Result<SignedWitnessObservation,String>{
        let mut observation=self.delegate.observe()?;
        let signature_hex=sign(&self.key,OBSERVATION_DOMAIN,&observation);
        if self.mutate_observation{observation.spent_count+=1;}
        Ok(SignedWitnessObservation{
            signer_key_id:if self.wrong_key{"wrong".into()}else{"witness-key-1".into()},
            observation,signature_hex})
    }
    fn signed_consume(&self,request:&WitnessConsume)->Result<SignedWitnessReceipt,String>{
        Ok(self.signed_receipt(self.delegate.consume(request)?))
    }
    fn signed_find_spend(&self,id:&str)->Result<Option<SignedWitnessReceipt>,String>{
        Ok(self.delegate.find_spend(id)?.map(|r|self.signed_receipt(r)))
    }
}
fn setup()->(tempfile::TempDir,DurableScratchWitness){
    let d=tempfile::tempdir().unwrap();
    let w=DurableScratchWitness::initialize_new(d.path().join("w"),cfg()).unwrap();
    (d,w)
}
#[test]fn signed_observation_and_receipt_verified_against_pinned_key(){
    let (_d,w)=setup();
    let verified=VerifiedWitnessAdapter::new(SignedMock::new(w),trust()).unwrap();
    assert_eq!(verified.observe().unwrap().spent_count,0);
    let receipt=verified.consume(&req(None)).unwrap();
    assert_eq!(receipt.spent_count,1);
    assert!(!receipt.canonical_writeback&&!receipt.authority_transfer);
    assert_eq!(verified.find_spend("auth-1").unwrap().unwrap().tip_sha256,receipt.tip_sha256);
    assert!(verified.consume(&req(Some(receipt.tip_sha256))).is_err());
}
#[test]fn forged_signature_and_wrong_signing_key_fail_closed(){
    let (_d,w)=setup();let mut wrong=SignedMock::new(w.clone());
    wrong.key=signer(99);
    let verified=VerifiedWitnessAdapter::new(wrong,trust()).unwrap();
    assert!(verified.observe().is_err());
    // Transport can commit before client detects forged receipt; no local authority.
    assert!(verified.consume(&req(None)).is_err());
    let mut wrong_id=SignedMock::new(w);wrong_id.wrong_key=true;
    let verified=VerifiedWitnessAdapter::new(wrong_id,trust()).unwrap();
    assert!(verified.observe().is_err());
}
#[test]fn mutation_after_signing_is_rejected(){
    let (_d,w)=setup();
    let mut tampered=SignedMock::new(w.clone());tampered.mutate_observation=true;
    assert!(VerifiedWitnessAdapter::new(tampered,trust()).unwrap().observe().is_err());
    let mut tampered=SignedMock::new(w);tampered.mutate_receipt=true;
    assert!(VerifiedWitnessAdapter::new(tampered,trust()).unwrap().consume(&req(None)).is_err());
}
#[test]fn key_role_separation_and_wrong_root_are_denied(){
    let (_d,w)=setup();
    let mut p=trust();
    p.pinned_witness_public_key_hex=p.pinned_review_root_public_key_hex.clone();
    assert!(VerifiedWitnessAdapter::new(SignedMock::new(w.clone()),p).is_err());
    let v=VerifiedWitnessAdapter::new(SignedMock::new(w),trust()).unwrap();
    let mut q=req(None);q.pinned_root_public_key_hex=h('a');
    assert!(v.consume(&q).is_err());
}
#[test]fn signed_observation_count_and_tip_floor_deny_rollback(){
    let (d,w)=setup();
    let v=VerifiedWitnessAdapter::new(SignedMock::new(w.clone()),trust()).unwrap();
    let original=v.consume(&req(None)).unwrap();
    let mut pinned=trust();
    pinned.minimum_spent_count=1;
    pinned.floor_tip_sha256=Some(original.tip_sha256.clone());
    let v=VerifiedWitnessAdapter::new(SignedMock::new(w.clone()),pinned.clone()).unwrap();
    assert_eq!(v.observe().unwrap().spent_count,1);
    pinned.floor_tip_sha256=Some(h('f'));
    assert!(VerifiedWitnessAdapter::new(SignedMock::new(w.clone()),pinned).unwrap().observe().is_err());
    // Remove the only journal entry: local disk alone can be completely rolled back.
    std::fs::remove_file(d.path().join("w/journal/00000000000000000001.json")).unwrap();
    let mut pinned=trust();pinned.minimum_spent_count=1;
    pinned.floor_tip_sha256=Some(original.tip_sha256);
    assert!(VerifiedWitnessAdapter::new(SignedMock::new(w),pinned).unwrap().observe().is_err());
}
#[test]fn wrong_signed_case_or_namespace_cannot_pass(){
    let (_d,w)=setup();
    let mut p=trust();p.expected_namespace="other".into();
    assert!(VerifiedWitnessAdapter::new(SignedMock::new(w.clone()),p).unwrap().observe().is_err());
    let mut p=trust();p.expected_case_id="other".into();
    assert!(VerifiedWitnessAdapter::new(SignedMock::new(w),p).unwrap().observe().is_err());
}
#[test]fn signed_observation_domain_cannot_be_reused_as_receipt_domain(){
    let observation=WitnessObservation{namespace:"t1".into(),case_id:"c1".into(),
        registry_epoch:10,spent_count:0,tip_sha256:None};
    let k=signer(33);
    let signed=SignedWitnessObservation{signer_key_id:"witness-key-1".into(),
        signature_hex:sign(&k,RECEIPT_DOMAIN,&observation),observation};
    assert!(verify_observation(&signed,&trust()).is_err());
}
