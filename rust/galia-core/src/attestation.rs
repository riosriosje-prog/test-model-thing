//! Offline, read-only Ed25519 integrity checkpoint validation (P3 shadow).
//! This module never grants P5 human authority, authenticates a live key registry,
//! or proves freshness unless independently pinned caller constraints are genuine.
use std::collections::BTreeSet;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize,Serialize};
use crate::audit::{AuditReceipt,Checkpoint,verify_receipts};

pub const REGISTRY_FORMAT: &str = "GALIA_NONCANONICAL_TRUST_REGISTRY_V1";
pub const CHECKPOINT_FORMAT: &str = "GALIA_NONCANONICAL_SIGNED_CHECKPOINT_V1";
pub const REGISTRY_DOMAIN: &[u8] = b"GALIA_TRUST_REGISTRY_V1\0";
pub const CHECKPOINT_DOMAIN: &[u8] = b"GALIA_SIGNED_CHECKPOINT_V1\0";

fn required(s:&str)->bool{!s.trim().is_empty()}
fn safe_id(s:&str)->bool{required(s)&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
fn hash_valid(s:&str)->bool{
    s.len()==64 && s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse_public_key(hex_text:&str)->Result<VerifyingKey,String>{
    if !hash_valid(hex_text){return Err("invalid lowercase Ed25519 public key".into());}
    let raw=hex::decode(hex_text).map_err(|_|"invalid key hex")?;
    let arr:[u8;32]=raw.try_into().map_err(|_|"invalid Ed25519 key length")?;
    VerifyingKey::from_bytes(&arr).map_err(|_|"invalid Ed25519 verifying key".into())
}
fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    let sorted=serde_json::to_value(value).map_err(|e|e.to_string())?;
    serde_json::to_vec(&sorted).map_err(|e|e.to_string())
}
/// Public and deterministic signing preimage. Only checkpoint integrity — NOT P5 authority.
pub fn signing_preimage<T:Serialize>(domain:&[u8],value:&T)->Result<Vec<u8>,String>{
    let mut raw=Vec::from(domain);
    raw.extend(canonical(value)?);
    Ok(raw)
}
fn verify_detached(
    public_key_hex:&str,signature_hex:&str,domain:&[u8],value:&impl Serialize
)->Result<(),String>{
    let key=parse_public_key(public_key_hex)?;
    if signature_hex.len()!=128 || !signature_hex.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)){
        return Err("invalid lowercase Ed25519 signature hex".into());
    }
    let raw=hex::decode(signature_hex).map_err(|_|"invalid signature encoding")?;
    let sig=Signature::from_slice(&raw).map_err(|_|"invalid signature length")?;
    key.verify(&signing_preimage(domain,value)?,&sig)
        .map_err(|_|"signature verification failed".into())
}

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    /// Root is pinned by caller: CLI cannot establish if the caller really trusts it.
    pub pinned_root_public_key_hex:String,
    pub expected_namespace:String,
    pub expected_case_id:String,
    /// Must come from a durable independent high-water mark, not signed input.
    pub minimum_registry_epoch:u64,
    pub minimum_receipt_count:u64,
    /// Optional independently pinned historical checkpoint (enforces exact prefix).
    pub prior_checkpoint:Option<Checkpoint>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSigner {
    pub key_id:String,
    pub public_key_hex:String,
    pub case_id:String,
    /// Revocation is effective immediately for this verifier, including old checkpoints.
    /// Never infer historical validity without separate signed chronology.
    pub revoked:bool,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRegistry {
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    pub epoch:u64,
    pub signers:Vec<CheckpointSigner>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRegistry {
    pub payload:TrustRegistry,
    pub root_signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpointPayload {
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    pub registry_epoch:u64,
    pub signer_key_id:String,
    pub count:u64,
    pub tip_sha256:String,
    pub last_head_sha256:Option<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub payload:SignedCheckpointPayload,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequest {
    pub policy:TrustPolicy,
    pub signed_registry:SignedRegistry,
    pub signed_checkpoint:SignedCheckpoint,
    pub receipts:Vec<AuditReceipt>,
}
#[derive(Clone,Debug,Serialize)]
pub struct AttestationAssessment {
    pub status:&'static str,
    pub signature_valid:bool,
    pub registered_signer_active:bool,
    pub audit_chain_consistent:bool,
    pub prefix_anchor_checked:bool,
    pub registry_epoch:u64,
    pub receipt_count:u64,
    pub tip_sha256:String,
    pub last_head_sha256:Option<String>,
    pub canonical_writeback:bool,
    pub human_authority_verified:bool,
    pub authority_transfer:bool,
    pub output_commit:Option<String>,
}

/// Structural trust validation relative to *caller-pinned*, out-of-band policy.
/// A valid signature on a fabricated key registry is not human approval.
pub fn verify_attestation(request:&AttestationRequest)->Result<AttestationAssessment,String>{
    let policy=&request.policy;
    let registry=&request.signed_registry.payload;
    let signed=&request.signed_checkpoint.payload;
    if !safe_id(&policy.expected_namespace)||!safe_id(&policy.expected_case_id){
        return Err("expected namespace or case is invalid".into());
    }
    // Root verification happens BEFORE consulting any delegate signing key.
    verify_detached(&policy.pinned_root_public_key_hex,
        &request.signed_registry.root_signature_hex,REGISTRY_DOMAIN,registry)?;
    if registry.format!=REGISTRY_FORMAT || !safe_id(&registry.namespace)
        || !safe_id(&registry.case_id) || registry.epoch==0
        || registry.epoch<policy.minimum_registry_epoch
        || registry.namespace!=policy.expected_namespace
        || registry.case_id!=policy.expected_case_id
        || registry.signers.is_empty(){
        return Err("registry scope/format/epoch rollback mismatch".into());
    }
    let mut ids=BTreeSet::new();
    let mut keys=BTreeSet::new();
    for signer in &registry.signers {
        if !safe_id(&signer.key_id)||!safe_id(&signer.case_id)
            || signer.case_id!=registry.case_id
            || !ids.insert(signer.key_id.as_str())||!keys.insert(signer.public_key_hex.as_str()){
            return Err("invalid, reused or out-of-scope checkpoint signer".into());
        }
        parse_public_key(&signer.public_key_hex)?;
    }
    if signed.format!=CHECKPOINT_FORMAT
        || signed.namespace!=policy.expected_namespace
        || signed.case_id!=policy.expected_case_id
        || signed.registry_epoch!=registry.epoch
        || !safe_id(&signed.signer_key_id)
        || !hash_valid(&signed.tip_sha256)
        || signed.last_head_sha256.as_ref().is_some_and(|h|!hash_valid(h))
        || signed.count==0 || signed.count<policy.minimum_receipt_count {
        return Err("checkpoint namespace/case/epoch/count rollback mismatch".into());
    }
    let signer=registry.signers.iter()
        .find(|k|k.key_id==signed.signer_key_id)
        .ok_or("unknown signer key_id")?;
    if signer.revoked {
        return Err("checkpoint signer revoked by root-signed registry".into());
    }
    verify_detached(&signer.public_key_hex,&request.signed_checkpoint.signature_hex,
        CHECKPOINT_DOMAIN,signed)?;

    // Externally pinned prefix is checked against the ACTUAL supplied history,
    // not merely a claimed prefix hash in the new checkpoint.
    if let Some(prefix)=&policy.prior_checkpoint {
        if prefix.count==0 || prefix.count>signed.count
            || prefix.count as usize>request.receipts.len() {
            return Err("invalid external prefix anchor count".into());
        }
        verify_receipts(&request.receipts[..prefix.count as usize],Some(prefix))?;
    }
    let replay=verify_receipts(&request.receipts,Some(&Checkpoint {
        count:signed.count,tip_sha256:signed.tip_sha256.clone(),
        last_head_sha256:signed.last_head_sha256.clone(),
    }))?;
    Ok(AttestationAssessment {
        status:"CRYPTOGRAPHICALLY_CONSISTENT_ADVISORY_ONLY",
        signature_valid:true,registered_signer_active:true,audit_chain_consistent:true,
        prefix_anchor_checked:policy.prior_checkpoint.is_some(),
        registry_epoch:registry.epoch,receipt_count:replay.count,
        tip_sha256:signed.tip_sha256.clone(),
        last_head_sha256:replay.head_sha256,
        canonical_writeback:false,human_authority_verified:false,
        authority_transfer:false,output_commit:None,
    })
}
