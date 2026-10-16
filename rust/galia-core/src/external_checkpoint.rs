//! GALIA v0.15 — OFFLINE cryptographic checkpoint anchor and recovery gate.
//! No signing key, remote transport, independent durable deployment, repairs or
//! P5 human authority. "External" means that the caller MUST separately pin
//! public keys and checkpoint history outside the mutable scratch directory.
use std::collections::BTreeSet;
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::transparency::ObserverPolicy;
use crate::transparency_board::{BoardCheckpoint,DurableTransparencyBoard,SplitViewEvidence};
use crate::witness_proof::{validate_public_key,verify_detached};

pub const CHECKPOINT_FORMAT:&str="GALIA_NONCANONICAL_EXTERNAL_CHECKPOINT_V1";
pub const CHECKPOINT_DOMAIN:&[u8]=b"GALIA_EXTERNAL_BOARD_CHECKPOINT_V1\0";
fn ident(x:&str)->bool{!x.trim().is_empty()&&x.len()<=256&&!x.chars().any(|c|c.is_control())}
fn digest(x:&str)->bool{x.len()==64&&x.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
pub fn policy_digest(policy:&ObserverPolicy)->Result<String,String>{
    policy.validate()?;
    Ok(sha256(&canonical(policy)?))
}
pub fn evidence_digest(evidence:Option<&SplitViewEvidence>)->Result<Option<String>,String>{
    match evidence{
        None=>Ok(None),
        Some(e)=>Ok(Some(sha256(&canonical(e)?))),
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointAnchorTrust{
    /// Must be provisioned in an independently controlled trust store.
    pub external_signer_id:String,
    pub external_signer_public_key_hex:String,
    pub stream_id:String,
    pub namespace:String,
    pub case_id:String,
    pub pinned_observer_policy_sha256:String,
    /// Out-of-band recorded checkpoint hash/sequence and exact board state.
    pub floor_sequence:u64,
    pub floor_envelope_sha256:Option<String>,
    pub floor_board:BoardCheckpoint,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalBoardCheckpointPayload{
    pub format:String,
    pub external_signer_id:String,
    pub stream_id:String,
    pub namespace:String,
    pub case_id:String,
    pub observer_policy_sha256:String,
    pub sequence:u64,
    pub previous_envelope_sha256:Option<String>,
    pub board:BoardCheckpoint,
    /// Hash of complete immutable signed split-view evidence, if quarantined.
    pub quarantined_evidence_sha256:Option<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExternalBoardCheckpoint{
    pub payload:ExternalBoardCheckpointPayload,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize)]
pub struct AnchorInspection{
    pub status:&'static str,
    pub anchor_count:u64,
    pub latest_external_sequence:u64,
    pub latest_external_sha256:String,
    pub board_journal_count:u64,
    pub board_tip_sha256:Option<String>,
    pub evidence_sha256:Option<String>,
    pub quarantined:bool,
    pub automatic_fork_recovery_permitted:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
impl CheckpointAnchorTrust{
    pub fn validate(&self,policy:&ObserverPolicy)->Result<(),String>{
        policy.validate()?;
        if !ident(&self.external_signer_id)||!ident(&self.stream_id)||
            self.namespace!=policy.witness_anchor.expected_namespace||
            self.case_id!=policy.witness_anchor.expected_case_id||
            !digest(&self.pinned_observer_policy_sha256)||
            self.pinned_observer_policy_sha256!=policy_digest(policy)?||
            self.floor_envelope_sha256.as_ref().is_some_and(|s|!digest(s))||
            (self.floor_sequence==0)!=self.floor_envelope_sha256.is_none()||
            self.floor_board.journal_tip_sha256.as_ref().is_some_and(|s|!digest(s))||
            (self.floor_board.journal_count==0)!=self.floor_board.journal_tip_sha256.is_none(){
            return Err("external checkpoint trust floor invalid or wrong observer policy".into())
        }
        validate_public_key(&self.external_signer_public_key_hex)?;
        if self.external_signer_public_key_hex==policy.witness_anchor.pinned_witness_public_key_hex||
            self.external_signer_public_key_hex==policy.witness_anchor.pinned_review_root_public_key_hex||
            policy.observers.iter().any(|x|x.public_key_hex==self.external_signer_public_key_hex){
            return Err("external checkpoint signer must be distinct from witness/reviewer/observer keys".into())
        }
        Ok(())
    }
}
fn monotonic(prior:&BoardCheckpoint,next:&BoardCheckpoint)->Result<(),String>{
    if next.journal_tip_sha256.as_ref().is_some_and(|s|!digest(s))||
        (next.journal_count==0)!=next.journal_tip_sha256.is_none()||
        next.journal_count<prior.journal_count||
        (prior.quarantined&&!next.quarantined)||
        (prior.quarantined&&next.journal_count!=prior.journal_count)||
        (next.journal_count==prior.journal_count&&
            (next.journal_tip_sha256!=prior.journal_tip_sha256||
             next.quarantined!=prior.quarantined)){
        return Err("external checkpoint rollback, changed same-height state or cleared quarantine".into())
    }
    Ok(())
}
pub fn verify_anchor_chain(
    trust:&CheckpointAnchorTrust,policy:&ObserverPolicy,
    signed:&[SignedExternalBoardCheckpoint]
)->Result<(BoardCheckpoint,String,Option<String>),String>{
    trust.validate(policy)?;
    if signed.is_empty(){return Err("no new externally signed checkpoint provided".into())}
    let mut seq=trust.floor_sequence;
    let mut tip=trust.floor_envelope_sha256.clone();
    let mut state=trust.floor_board.clone();
    let mut evidence:Option<String>=None;
    let mut seen=BTreeSet::new();
    for envelope in signed{
        let p=&envelope.payload;
        let expected_seq=seq.checked_add(1).ok_or("external checkpoint counter overflow")?;
        if p.format!=CHECKPOINT_FORMAT||
            p.external_signer_id!=trust.external_signer_id||
            p.stream_id!=trust.stream_id||
            p.namespace!=trust.namespace||p.case_id!=trust.case_id||
            p.observer_policy_sha256!=trust.pinned_observer_policy_sha256||
            p.sequence!=expected_seq||p.previous_envelope_sha256!=tip||
            p.quarantined_evidence_sha256.as_ref().is_some_and(|s|!digest(s))||
            (p.board.quarantined!=p.quarantined_evidence_sha256.is_some()){
            return Err("signed checkpoint is out of scope, out of sequence or missing evidence".into())
        }
        monotonic(&state,&p.board)?;
        verify_detached(&trust.external_signer_public_key_hex,
            &envelope.signature_hex,CHECKPOINT_DOMAIN,p)?;
        let hash=sha256(&canonical(envelope)?);
        if !seen.insert(hash.clone()){return Err("duplicate signed checkpoint envelope".into())}
        seq=p.sequence;
        tip=Some(hash);
        state=p.board.clone();
        evidence=p.quarantined_evidence_sha256.clone();
    }
    Ok((state,tip.ok_or("no verified external hash")?,evidence))
}
/// Read-only cross-check of the complete signed externally retained chain
/// against locally replay-verified board state and complete fork evidence.
/// A mismatch yields error; no rollback, journal deletion or fork selection.
pub fn inspect_anchored_board(
    board:&DurableTransparencyBoard,
    trust:&CheckpointAnchorTrust,
    policy:&ObserverPolicy,
    signed:&[SignedExternalBoardCheckpoint],
)->Result<AnchorInspection,String>{
    let (claimed,hash,evidence_hash)=verify_anchor_chain(trust,policy,signed)?;
    let actual=board.checkpoint()?; // full signature and journal replay
    if canonical(&actual)?!=canonical(&claimed)?{
        return Err("local board differs from independently signed checkpoint".into())
    }
    let evidence=board.evidence()?;
    let actual_evidence=evidence_digest(evidence.as_ref())?;
    if actual_evidence!=evidence_hash {
        return Err("signed external checkpoint and locally stored fork evidence differ".into())
    }
    let last=signed.last().ok_or("no signed external checkpoint")?;
    Ok(AnchorInspection{
        status:if actual.quarantined{
            "SIGNED_FORK_EVIDENCE_PINNED_MANUAL_REVIEW_REQUIRED"
        }else{
            "SIGNED_BOARD_CHECKPOINT_CONSISTENT_ADVISORY_ONLY"
        },
        anchor_count:u64::try_from(signed.len()).map_err(|_|"count overflow")?,
        latest_external_sequence:last.payload.sequence,
        latest_external_sha256:hash,
        board_journal_count:actual.journal_count,
        board_tip_sha256:actual.journal_tip_sha256,
        evidence_sha256:actual_evidence,
        quarantined:actual.quarantined,
        automatic_fork_recovery_permitted:false,
        human_authority_verified:false,canonical_writeback:false,authority_transfer:false,
    })
}
