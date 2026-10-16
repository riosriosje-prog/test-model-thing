//! v0.11 signed witness adapter: NO server, private signing key or canonical authority.
//! Callers must provision root/pins independently. Valid signatures do NOT prove
//! signer custody, freshness, append-only witness service or human authorization.
use ed25519_dalek::{Signature,Verifier,VerifyingKey};
use serde::{Serialize,Deserialize};
use crate::attestation::signing_preimage;
use crate::witness::{MonotonicWitness,WitnessConsume,WitnessReceipt,WitnessObservation,FORMAT};

pub const OBSERVATION_DOMAIN:&[u8]=b"GALIA_WITNESS_OBSERVATION_V1\0";
pub const RECEIPT_DOMAIN:&[u8]=b"GALIA_WITNESS_RECEIPT_V1\0";
fn hash(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn safe(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
fn key(hexkey:&str)->Result<VerifyingKey,String>{
    if !hash(hexkey){return Err("invalid pinned public key hex".into())}
    let decoded=hex::decode(hexkey).map_err(|e|e.to_string())?;
    let arr:[u8;32]=decoded.try_into().map_err(|_|"invalid public key size")?;
    VerifyingKey::from_bytes(&arr).map_err(|e|e.to_string())
}
fn signature(key:&VerifyingKey,sig_hex:&str,domain:&[u8],value:&impl Serialize)->Result<(),String>{
    if sig_hex.len()!=128||!sig_hex.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("invalid witness Ed25519 signature encoding".into())
    }
    let raw=hex::decode(sig_hex).map_err(|e|e.to_string())?;
    let sig=Signature::from_slice(&raw).map_err(|e|e.to_string())?;
    key.verify(&signing_preimage(domain,value)?,&sig)
        .map_err(|_|"invalid Ed25519 witness signature".into())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessTrustAnchor{
    pub signer_key_id:String,
    pub pinned_witness_public_key_hex:String,
    pub pinned_review_root_public_key_hex:String,
    pub expected_namespace:String,
    pub expected_case_id:String,
    pub minimum_registry_epoch:u64,
    pub minimum_spent_count:u64,
    /// An exact pin at the minimum count, not an extension proof.
    pub floor_tip_sha256:Option<String>,
}
impl WitnessTrustAnchor{
    pub fn validate(&self)->Result<(),String>{
        if !safe(&self.signer_key_id)||!safe(&self.expected_namespace)||
            !safe(&self.expected_case_id)||!hash(&self.pinned_review_root_public_key_hex)||
            self.pinned_review_root_public_key_hex==self.pinned_witness_public_key_hex||
            self.minimum_registry_epoch==0||
            self.floor_tip_sha256.as_ref().is_some_and(|h|!hash(h))||
            (self.minimum_spent_count==0&&self.floor_tip_sha256.is_some())||
            (self.minimum_spent_count>0&&self.floor_tip_sha256.is_none()){
            return Err("invalid witness trust anchor or high-water pin".into())
        }
        key(&self.pinned_witness_public_key_hex)?;Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessObservation{
    pub signer_key_id:String,
    pub observation:WitnessObservation,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessReceipt{
    pub signer_key_id:String,
    pub receipt:WitnessReceipt,
    pub signature_hex:String,
}
pub fn verify_observation(s:&SignedWitnessObservation,a:&WitnessTrustAnchor)->Result<WitnessObservation,String>{
    a.validate()?;
    if s.signer_key_id!=a.signer_key_id{return Err("observation key ID mismatch".into())}
    signature(&key(&a.pinned_witness_public_key_hex)?,&s.signature_hex,OBSERVATION_DOMAIN,&s.observation)?;
    let x=&s.observation;
    if x.namespace!=a.expected_namespace||x.case_id!=a.expected_case_id||
        x.registry_epoch<a.minimum_registry_epoch||x.spent_count<a.minimum_spent_count||
        (x.spent_count==0&&x.tip_sha256.is_some())||
        (x.spent_count>0&&!x.tip_sha256.as_ref().is_some_and(|v|hash(v)))||
        (x.spent_count==a.minimum_spent_count&&x.tip_sha256!=a.floor_tip_sha256){
        return Err("signed observation violates pinned high-water mark".into())
    }
    Ok(WitnessObservation{
        namespace:x.namespace.clone(),case_id:x.case_id.clone(),
        registry_epoch:x.registry_epoch,spent_count:x.spent_count,tip_sha256:x.tip_sha256.clone()
    })
}
pub fn verify_receipt(s:&SignedWitnessReceipt,a:&WitnessTrustAnchor)->Result<WitnessReceipt,String>{
    a.validate()?;
    if s.signer_key_id!=a.signer_key_id{return Err("receipt key ID mismatch".into())}
    signature(&key(&a.pinned_witness_public_key_hex)?,&s.signature_hex,RECEIPT_DOMAIN,&s.receipt)?;
    let x=&s.receipt;
    if x.format!=FORMAT||x.namespace!=a.expected_namespace||x.case_id!=a.expected_case_id||
        x.registry_epoch==0||x.spent_count==0||!hash(&x.tip_sha256)||
        x.prior_tip_sha256.as_ref().is_some_and(|v|!hash(v))||
        !safe(&x.authorization_id)||!hash(&x.nonce_sha256)||
        !hash(&x.signed_decision_sha256)||x.canonical_writeback||x.authority_transfer {
        return Err("signed witness receipt scope/flags invalid".into())
    }
    Ok(WitnessReceipt{
        format:x.format.clone(),namespace:x.namespace.clone(),case_id:x.case_id.clone(),
        registry_epoch:x.registry_epoch,spent_count:x.spent_count,
        prior_tip_sha256:x.prior_tip_sha256.clone(),tip_sha256:x.tip_sha256.clone(),
        authorization_id:x.authorization_id.clone(),nonce_sha256:x.nonce_sha256.clone(),
        signed_decision_sha256:x.signed_decision_sha256.clone(),
        canonical_writeback:false,authority_transfer:false
    })
}
pub trait SignedWitnessTransport:Send+Sync{
    fn signed_observe(&self)->Result<SignedWitnessObservation,String>;
    fn signed_consume(&self,req:&WitnessConsume)->Result<SignedWitnessReceipt,String>;
    fn signed_find_spend(&self,authorization_id:&str)->Result<Option<SignedWitnessReceipt>,String>;
}
pub struct VerifiedWitnessAdapter<T:SignedWitnessTransport>{
    transport:T,anchor:WitnessTrustAnchor
}
impl<T:SignedWitnessTransport> VerifiedWitnessAdapter<T>{
    pub fn new(transport:T,anchor:WitnessTrustAnchor)->Result<Self,String>{
        anchor.validate()?;Ok(Self{transport,anchor})
    }
}
impl<T:SignedWitnessTransport> MonotonicWitness for VerifiedWitnessAdapter<T>{
    fn observe(&self)->Result<WitnessObservation,String>{
        verify_observation(&self.transport.signed_observe()?,&self.anchor)
    }
    fn consume(&self,req:&WitnessConsume)->Result<WitnessReceipt,String>{
        if req.namespace!=self.anchor.expected_namespace||
            req.case_id!=self.anchor.expected_case_id||
            req.pinned_root_public_key_hex!=self.anchor.pinned_review_root_public_key_hex||
            req.registry_epoch<self.anchor.minimum_registry_epoch{
            return Err("requested review root/case/epoch disagrees with pinned witness trust".into())
        }
        let receipt=verify_receipt(&self.transport.signed_consume(req)?,&self.anchor)?;
        if receipt.authorization_id!=req.authorization_id||
            receipt.nonce_sha256!=req.nonce_sha256||
            receipt.signed_decision_sha256!=req.signed_decision_sha256||
            receipt.registry_epoch!=req.registry_epoch||
            receipt.prior_tip_sha256!=req.expected_tip_sha256{
            return Err("signed receipt not bound to exact consume request".into())
        }
        Ok(receipt)
    }
    fn find_spend(&self,authorization_id:&str)->Result<Option<WitnessReceipt>,String>{
        if !safe(authorization_id){return Err("invalid authorization lookup ID".into())}
        let current=self.observe()?;
        match self.transport.signed_find_spend(authorization_id)?{
            None=>Ok(None),
            Some(signed)=>{
                let receipt=verify_receipt(&signed,&self.anchor)?;
                if receipt.authorization_id!=authorization_id||
                    receipt.spent_count>current.spent_count||
                    receipt.registry_epoch>current.registry_epoch||
                    (receipt.spent_count==current.spent_count&&
                     Some(receipt.tip_sha256.clone())!=current.tip_sha256){
                    return Err("signed historical receipt conflicts with signed observation".into())
                }
                Ok(Some(receipt))
            }
        }
    }
}
