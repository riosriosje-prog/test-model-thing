//! GALIA v0.18 OFFLINE signed replay high-water anchor.
//! No remote auditor, trusted publishing, TLS, HSM, independent key custody,
//! distributed nonce ledger, human P5 authority or canonical writeback.
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::external_checkpoint::policy_digest;
use crate::external_transport::ExternalServiceTrust;
use crate::replay_fence::{DurableTranscriptReplayFence,ReplayJournalCheckpoint};
use crate::transparency::ObserverPolicy;
use crate::witness_proof::{validate_public_key,verify_detached};

pub const ANCHOR_FORMAT:&str="GALIA_NONCANONICAL_REPLAY_ANCHOR_V1";
pub const ANCHOR_DOMAIN:&[u8]=b"GALIA_REMOTE_REPLAY_ANCHOR_V1\0";
fn ident(s:&str)->bool{!s.trim().is_empty()&&s.len()<=256&&!s.chars().any(|c|c.is_control())}
fn hash(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAnchorTrust{
    /// Key and floor MUST be pinned independently of the scratch store.
    pub signer_key_id:String,
    pub signer_public_key_hex:String,
    pub stream_id:String,
    pub service_id:String,
    pub namespace:String,
    pub case_id:String,
    pub pinned_service_trust_sha256:String,
    pub pinned_observer_policy_sha256:String,
    pub floor_sequence:u64,
    pub floor_envelope_sha256:Option<String>,
    pub floor_checkpoint:ReplayJournalCheckpoint,
}
impl ReplayAnchorTrust{
    pub fn validate(&self,service:&ExternalServiceTrust,policy:&ObserverPolicy)->Result<(),String>{
        service.validate(policy)?;
        self.floor_checkpoint.validate()?;
        if !ident(&self.signer_key_id)||!ident(&self.stream_id)||
            !ident(&self.service_id)||!ident(&self.namespace)||!ident(&self.case_id)||
            self.service_id!=service.service_id||
            self.namespace!=service.checkpoint.namespace||
            self.case_id!=service.checkpoint.case_id||
            !hash(&self.pinned_service_trust_sha256)||
            self.pinned_service_trust_sha256!=sha256(&canonical(service)?)||
            !hash(&self.pinned_observer_policy_sha256)||
            self.pinned_observer_policy_sha256!=policy_digest(policy)?||
            (self.floor_sequence==0)!=self.floor_envelope_sha256.is_none()||
            (self.floor_sequence==0&&self.floor_checkpoint.accepted_count!=0)||
            self.floor_envelope_sha256.as_ref().is_some_and(|x|!hash(x)) {
            return Err("invalid or unbound replay anchor trust floor".into())
        }
        validate_public_key(&self.signer_public_key_hex)?;
        let k=&self.signer_public_key_hex;
        if k==&service.response_signer_public_key_hex||
            k==&service.checkpoint.external_signer_public_key_hex||
            k==&policy.witness_anchor.pinned_review_root_public_key_hex||
            k==&policy.witness_anchor.pinned_witness_public_key_hex||
            policy.observers.iter().any(|o|k==&o.public_key_hex) {
            return Err("replay anchor key aliases reviewer, service, auditor or observer".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAnchorPayload{
    pub format:String,
    pub signer_key_id:String,
    pub stream_id:String,
    pub service_id:String,
    pub namespace:String,
    pub case_id:String,
    pub service_trust_sha256:String,
    pub observer_policy_sha256:String,
    pub sequence:u64,
    pub previous_envelope_sha256:Option<String>,
    pub checkpoint:ReplayJournalCheckpoint,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReplayAnchor{
    pub payload:ReplayAnchorPayload,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize)]
pub struct ReplayAnchorVerification{
    pub status:&'static str,
    pub latest_sequence:u64,
    pub latest_envelope_sha256:String,
    pub latest_checkpoint:ReplayJournalCheckpoint,
    pub chain_length:u64,
    pub signed_chain_matches_local_prefixes:bool,
    pub externally_operated_auditor_verified:bool,
    pub independent_key_custody_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Verify a contiguous chain signed by a separately pinned public key.
/// Signatures alone do not establish the actual provenance of the pins.
pub fn verify_anchor_chain(
    trust:&ReplayAnchorTrust,service:&ExternalServiceTrust,policy:&ObserverPolicy,
    anchors:&[SignedReplayAnchor],
)->Result<(Vec<ReplayJournalCheckpoint>,String),String>{
    trust.validate(service,policy)?;
    if anchors.is_empty()||anchors.len()>128{
        return Err("missing or oversized signed replay anchor chain".into())
    }
    let mut seq=trust.floor_sequence;
    let mut prev=trust.floor_envelope_sha256.clone();
    let mut checkpoint=trust.floor_checkpoint.clone();
    let mut checkpoints=Vec::with_capacity(anchors.len());
    for signed in anchors{
        let p=&signed.payload;
        let next=seq.checked_add(1).ok_or("replay anchor sequence overflow")?;
        p.checkpoint.validate()?;
        if p.format!=ANCHOR_FORMAT||p.signer_key_id!=trust.signer_key_id||
            p.stream_id!=trust.stream_id||p.service_id!=trust.service_id||
            p.namespace!=trust.namespace||p.case_id!=trust.case_id||
            p.service_trust_sha256!=trust.pinned_service_trust_sha256||
            p.observer_policy_sha256!=trust.pinned_observer_policy_sha256||
            p.sequence!=next||p.previous_envelope_sha256!=prev||
            p.checkpoint.accepted_count<checkpoint.accepted_count||
            (p.checkpoint.accepted_count==checkpoint.accepted_count&&
             p.checkpoint.journal_tip_sha256!=checkpoint.journal_tip_sha256) {
            return Err("replay anchor continuity, state, or pin mismatch".into())
        }
        verify_detached(&trust.signer_public_key_hex,&signed.signature_hex,
            ANCHOR_DOMAIN,p)?;
        prev=Some(sha256(&canonical(signed)?));
        seq=next;
        checkpoint=p.checkpoint.clone();
        checkpoints.push(checkpoint.clone());
    }
    Ok((checkpoints,prev.ok_or("missing signed anchor digest")?))
}
/// Replay EVERY signed historical prefix against the immutable local log.
/// The current externally retained trust floor must be supplied separately.
pub fn verify_anchored_journal(
    fence:&DurableTranscriptReplayFence,
    service:&ExternalServiceTrust,policy:&ObserverPolicy,
    trust:&ReplayAnchorTrust,anchors:&[SignedReplayAnchor],
)->Result<ReplayAnchorVerification,String>{
    let (checkpoints,last_hash)=verify_anchor_chain(trust,service,policy,anchors)?;
    if fence.checkpoint_at(trust.floor_checkpoint.accepted_count)?
        !=trust.floor_checkpoint{
        return Err("scratch replay journal disagrees with independently pinned floor".into())
    }
    for checkpoint in &checkpoints{
        if fence.checkpoint_at(checkpoint.accepted_count)?!=*checkpoint {
            return Err("scratch replay history diverges from signed checkpoint prefix".into())
        }
    }
    let latest_checkpoint=checkpoints.last().ok_or("no signed anchor")?.clone();
    Ok(ReplayAnchorVerification{
        status:"REPLAY_HISTORY_MATCHES_SIGNED_CHECKPOINTS_ADVISORY_ONLY",
        latest_sequence:anchors.last().ok_or("empty anchor list")?.payload.sequence,
        latest_envelope_sha256:last_hash,
        latest_checkpoint,
        chain_length:u64::try_from(anchors.len()).map_err(|_|"anchor length overflow")?,
        signed_chain_matches_local_prefixes:true,
        externally_operated_auditor_verified:false,
        independent_key_custody_verified:false,
        human_authority_verified:false,
        canonical_writeback:false,
        authority_transfer:false,
    })
}
