//! GALIA Rust v0.28: read-only signed high-water audit of TWO scratch roots.
//!
//! A separately pinned Ed25519 auditor statement can reveal simultaneous
//! coordinator+anchor rollback IF its trusted count/tip survives outside BOTH
//! local stores. The module does not publish, sign, fetch or persist records:
//! signer custody, real independence and freshness remain unverified.
//! An audit result never grants human P5 authority or canonical writes.
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::fenced_coordinator::{
    DurableFencingCoordinator,FencingCheckpoint,FencingScope,FencingAuthority,
    IndependentMonotonicFencingAnchor,
};
use crate::witness_proof::{validate_public_key,verify_detached};

pub const AUDIT_FORMAT:&str="GALIA_NONCANONICAL_DUAL_ROOT_AUDIT_V1";
pub const AUDIT_DOMAIN:&[u8]=b"GALIA_DUAL_ROOT_AUDIT_V1\0";
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn is_hash(s:&str)->bool{
    s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn valid_id(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTrustPin{
    /// Independently provisioned and retained OUTSIDE both writable scratch
    /// journal roots. This module cannot verify that custody is independent.
    pub auditor_id:String,
    pub auditor_public_key_hex:String,
    pub stream_id:String,
    pub scope:FencingScope,
    pub floor_sequence:u64,
    pub floor_signed_sha256:Option<String>,
    pub floor_checkpoint:FencingCheckpoint,
}
impl AuditTrustPin{
    pub fn validate(&self)->Result<(),String>{
        self.scope.validate()?;
        self.floor_checkpoint.validate()?;
        if !valid_id(&self.auditor_id)||!valid_id(&self.stream_id)||
            self.auditor_public_key_hex==self.scope.pinned_response_signer_public_key_hex||
            (self.floor_sequence==0)!=self.floor_signed_sha256.is_none()||
            self.floor_signed_sha256.as_ref().is_some_and(|s|!is_hash(s))||
            (self.floor_sequence==0&&self.floor_checkpoint.record_count!=0){
            return Err("invalid independent auditor identity or trusted audit floor".into())
        }
        validate_public_key(&self.auditor_public_key_hex)?;
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStatement{
    pub format:String,
    pub auditor_id:String,
    pub stream_id:String,
    pub scope_sha256:String,
    pub sequence:u64,
    pub previous_signed_sha256:Option<String>,
    pub checkpoint:FencingCheckpoint,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditStatement{
    pub statement:AuditStatement,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize)]
pub struct DualRootAuditReport{
    pub status:&'static str,
    pub latest_audit_sequence:u64,
    pub latest_signed_sha256:String,
    pub current_checkpoint:FencingCheckpoint,
    pub signed_observations_verified:usize,
    pub historical_signed_prefixes_verified:bool,
    pub coordinator_and_anchor_exactly_match:bool,
    pub real_independent_auditor_deployed:bool,
    pub current_external_audit_freshness_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Signature and chain verification alone are INSUFFICIENT to prove an audit
/// history extends a real local journal. assess_dual_root_audit cross-checks
/// every signed historical prefix against the fully replayed local journal.
pub fn verify_signed_audit_chain(
    pin:&AuditTrustPin,signed:&[SignedAuditStatement],
)->Result<(Vec<FencingCheckpoint>,String),String>{
    pin.validate()?;
    if signed.is_empty()||signed.len()>128{
        return Err("missing or oversized independently signed audit chain".into())
    }
    let mut seq=pin.floor_sequence;
    let mut previous=pin.floor_signed_sha256.clone();
    let mut prior=pin.floor_checkpoint.clone();
    let scope_hash=sha256(&canonical(&pin.scope)?);
    let mut observed=Vec::with_capacity(signed.len());
    for record in signed{
        let p=&record.statement;
        p.checkpoint.validate()?;
        if p.format!=AUDIT_FORMAT||p.auditor_id!=pin.auditor_id||
            p.stream_id!=pin.stream_id||p.scope_sha256!=scope_hash||
            p.sequence!=seq.checked_add(1).ok_or("audit sequence overflow")?||
            p.previous_signed_sha256!=previous||
            p.checkpoint.record_count<prior.record_count||
            (p.checkpoint.record_count==prior.record_count&&p.checkpoint!=prior){
            return Err("audit scope, sequence, hash chain or monotonic height mismatch".into())
        }
        verify_detached(&pin.auditor_public_key_hex,&record.signature_hex,
            AUDIT_DOMAIN,p)?;
        previous=Some(sha256(&canonical(record)?));
        seq=p.sequence;
        prior=p.checkpoint.clone();
        observed.push(prior.clone());
    }
    Ok((observed,previous.ok_or("missing signed audit tip")?))
}
/// No writes of any kind. Detects dual-root rollback relative to a separate,
/// independently pinned signed observation, even if both local roots now agree.
/// Does not establish freshness or identity of an external auditor.
pub fn assess_dual_root_audit(
    coordinator:&DurableFencingCoordinator,
    anchor:&dyn IndependentMonotonicFencingAnchor,
    pin:&AuditTrustPin,
    signed:&[SignedAuditStatement],
)->Result<DualRootAuditReport,String>{
    let (checkpoints,last_hash)=verify_signed_audit_chain(pin,signed)?;
    if coordinator.scope()?!=pin.scope{
        return Err("coordinator's independently pinned scope differs".into())
    }
    // Full coordinator journal replay/prefix checks. Never trust only latest
    // self-reported height; the signed audit must match each historical prefix.
    coordinator.verify_floor(&pin.floor_checkpoint)?;
    for checkpoint in &checkpoints{
        coordinator.verify_floor(checkpoint)?;
    }
    let local=coordinator.checkpoint()?;
    let outside=anchor.current(&pin.scope)?;
    if local!=outside{
        return Err("local coordinator and separate scratch anchor diverge".into())
    }
    Ok(DualRootAuditReport{
        status:"SIGNED_DUAL_ROOT_SCRATCH_AUDIT_ADVISORY_ONLY",
        latest_audit_sequence:signed.last().ok_or("audit empty")?.statement.sequence,
        latest_signed_sha256:last_hash,current_checkpoint:local,
        signed_observations_verified:signed.len(),
        historical_signed_prefixes_verified:true,
        coordinator_and_anchor_exactly_match:true,
        real_independent_auditor_deployed:false,
        current_external_audit_freshness_verified:false,
        human_authority_verified:false,canonical_writeback:false,
        authority_transfer:false,
    })
}
