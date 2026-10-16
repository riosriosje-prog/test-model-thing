//! GALIA Rust v0.16: protocol verification at a future external-checkpoint
//! transport boundary. No network client, TLS stack, signing key, HSM or
//! independently authenticated trust bootstrap is implemented in this crate.
//! Caller-supplied TLS evidence MUST come from a separate real TLS verifier.
//! Success means cryptographic agreement relative to caller-pinned inputs,
//! NEVER remote availability, true peer independence or human P5 authority.
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::external_checkpoint::{
    CheckpointAnchorTrust,SignedExternalBoardCheckpoint,
    inspect_anchored_board,verify_anchor_chain,
};
use crate::transparency::ObserverPolicy;
use crate::transparency_board::DurableTransparencyBoard;
use crate::witness_proof::{validate_public_key,verify_detached};

pub const REQUEST_FORMAT:&str="GALIA_NONCANONICAL_REMOTE_CHECKPOINT_REQUEST_V1";
pub const RESPONSE_FORMAT:&str="GALIA_NONCANONICAL_REMOTE_CHECKPOINT_RESPONSE_V1";
pub const RESPONSE_DOMAIN:&[u8]=b"GALIA_REMOTE_CHECKPOINT_RESPONSE_V1\0";
fn ident(v:&str)->bool{!v.trim().is_empty()&&v.len()<=256&&!v.chars().any(|c|c.is_control())}
fn hash(v:&str)->bool{v.len()==64&&v.bytes().all(|x|x.is_ascii_digit()||(b'a'..=b'f').contains(&x))}
fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(value).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalServiceTrust{
    /// Must be pinned OUTSIDE both the scratch journal and the response.
    pub checkpoint:CheckpointAnchorTrust,
    pub service_id:String,
    pub response_signer_id:String,
    pub response_signer_public_key_hex:String,
    /// Actual TLS connection verification is a responsibility of a separate adapter.
    pub pinned_tls_peer_spki_sha256:String,
    /// 300 seconds is protocol maximum, not a claim of clock trust.
    pub max_challenge_seconds:u64,
}
impl ExternalServiceTrust{
    pub fn validate(&self,policy:&ObserverPolicy)->Result<(),String>{
        self.checkpoint.validate(policy)?;
        if !ident(&self.service_id)||!ident(&self.response_signer_id)
            ||!hash(&self.pinned_tls_peer_spki_sha256)
            ||self.max_challenge_seconds==0||self.max_challenge_seconds>300 {
            return Err("invalid externally pinned transport policy".into())
        }
        validate_public_key(&self.response_signer_public_key_hex)?;
        let key=&self.response_signer_public_key_hex;
        if key==&self.checkpoint.external_signer_public_key_hex
            ||key==&policy.witness_anchor.pinned_witness_public_key_hex
            ||key==&policy.witness_anchor.pinned_review_root_public_key_hex
            ||policy.observers.iter().any(|x|key==&x.public_key_hex){
            return Err("transport signer key must not alias checkpoint/reviewer/witness/observer".into())
        }
        Ok(())
    }
}
/// Trusted ONLY when obtained from the authenticated transport verifier.
/// The data structure itself cannot prove TLS or mTLS ever happened.
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPeerEvidence{
    pub tls_peer_spki_sha256:String,
    pub tls_exporter_sha256:String,
    pub mutual_tls_client_authenticated:bool,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCheckpointChallenge{
    pub format:String,
    pub service_id:String,
    pub stream_id:String,
    pub namespace:String,
    pub case_id:String,
    /// A cryptographically fresh nonce produced OUTSIDE this crate, never by server.
    pub nonce_sha256:String,
    pub floor_sequence:u64,
    pub floor_envelope_sha256:Option<String>,
    /// A TLS exporter hash from the same separately verified connection.
    pub tls_exporter_sha256:String,
    pub issued_at_unix_seconds:u64,
    pub expires_at_unix_seconds:u64,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCheckpointPayload{
    pub format:String,
    pub service_id:String,
    pub signer_id:String,
    pub challenge_sha256:String,
    pub nonce_sha256:String,
    pub tls_exporter_sha256:String,
    pub signed_at_unix_seconds:u64,
    pub checkpoint_chain:Vec<SignedExternalBoardCheckpoint>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRemoteCheckpointResponse{
    pub payload:RemoteCheckpointPayload,
    pub signature_hex:String,
}
/// No implicit success or side effects on transport/network failure.
pub trait RemoteCheckpointTransport:Send+Sync{
    fn exchange(&self,challenge:&RemoteCheckpointChallenge)
        ->Result<(TransportPeerEvidence,SignedRemoteCheckpointResponse),String>;
}
#[derive(Clone,Debug,Serialize)]
pub struct RemoteCheckpointAssessment{
    pub status:&'static str,
    pub checkpoint_count:u64,
    pub terminal_sequence:u64,
    pub terminal_envelope_sha256:String,
    pub local_board_quarantined:bool,
    pub claimed_tls_identity_matched:bool,
    pub challenge_binding_verified:bool,
    pub external_service_deployed_verified:bool,
    pub independent_key_custody_verified:bool,
    pub real_human_identity_verified:bool,
    pub human_authority_verified:bool,
    pub executable_guards_issued:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
pub fn verify_remote_exchange(
    board:&DurableTransparencyBoard,
    policy:&ObserverPolicy,
    trust:&ExternalServiceTrust,
    challenge:&RemoteCheckpointChallenge,
    peer:&TransportPeerEvidence,
    response:&SignedRemoteCheckpointResponse,
    trusted_now_unix_seconds:u64,
)->Result<RemoteCheckpointAssessment,String>{
    trust.validate(policy)?;
    if !peer.mutual_tls_client_authenticated
        ||peer.tls_peer_spki_sha256!=trust.pinned_tls_peer_spki_sha256
        ||!hash(&peer.tls_exporter_sha256) {
        return Err("transport evidence lacks claimed mTLS or matches wrong pinned TLS peer".into())
    }
    if challenge.format!=REQUEST_FORMAT||
        challenge.service_id!=trust.service_id||
        challenge.stream_id!=trust.checkpoint.stream_id||
        challenge.namespace!=trust.checkpoint.namespace||
        challenge.case_id!=trust.checkpoint.case_id||
        !hash(&challenge.nonce_sha256)||
        challenge.floor_sequence!=trust.checkpoint.floor_sequence||
        challenge.floor_envelope_sha256!=trust.checkpoint.floor_envelope_sha256||
        challenge.tls_exporter_sha256!=peer.tls_exporter_sha256{
        return Err("challenge not bound to pinned service, channel, case or anchor".into())
    }
    let duration=challenge.expires_at_unix_seconds
        .checked_sub(challenge.issued_at_unix_seconds)
        .ok_or("challenge deadline precedes issuance")?;
    if duration==0||duration>trust.max_challenge_seconds||
        trusted_now_unix_seconds<challenge.issued_at_unix_seconds||
        trusted_now_unix_seconds>challenge.expires_at_unix_seconds {
        return Err("challenge expired, not yet issued or outside clock window".into())
    }
    let payload=&response.payload;
    if payload.format!=RESPONSE_FORMAT||
        payload.service_id!=trust.service_id||
        payload.signer_id!=trust.response_signer_id||
        payload.nonce_sha256!=challenge.nonce_sha256||
        payload.tls_exporter_sha256!=peer.tls_exporter_sha256||
        !hash(&payload.challenge_sha256)||
        payload.challenge_sha256!=sha256(&canonical(challenge)?)||
        payload.signed_at_unix_seconds<challenge.issued_at_unix_seconds||
        payload.signed_at_unix_seconds>trusted_now_unix_seconds||
        payload.signed_at_unix_seconds>challenge.expires_at_unix_seconds||
        payload.checkpoint_chain.is_empty()||
        payload.checkpoint_chain.len()>128 {
        return Err("signed remote response invalid, stale or not bound to challenge".into())
    }
    verify_detached(&trust.response_signer_public_key_hex,
        &response.signature_hex,RESPONSE_DOMAIN,payload)?;
    // Both independently scoped checkpoint signatures AND complete signed
    // local transparency-board replay are required before reporting consistency.
    let (terminal,tip,_evidence)=verify_anchor_chain(
        &trust.checkpoint,policy,&payload.checkpoint_chain)?;
    let inspected=inspect_anchored_board(
        board,&trust.checkpoint,policy,&payload.checkpoint_chain)?;
    if terminal.quarantined!=inspected.quarantined{
        return Err("remote checkpoint and replayed local quarantine disagree".into())
    }
    let count=u64::try_from(payload.checkpoint_chain.len())
        .map_err(|_|"checkpoint chain too long")?;
    Ok(RemoteCheckpointAssessment{
        status:if inspected.quarantined{
            "REMOTE_TRANSCRIPT_CONSISTENT_QUARANTINED_MANUAL_REVIEW"
        }else{
            "REMOTE_TRANSCRIPT_CRYPTOGRAPHICALLY_CONSISTENT_ADVISORY_ONLY"
        },
        checkpoint_count:count,
        terminal_sequence:inspected.latest_external_sequence,
        terminal_envelope_sha256:tip,
        local_board_quarantined:inspected.quarantined,
        claimed_tls_identity_matched:true,
        challenge_binding_verified:true,
        external_service_deployed_verified:false,
        independent_key_custody_verified:false,
        real_human_identity_verified:false,
        human_authority_verified:false,
        executable_guards_issued:false,
        canonical_writeback:false,
        authority_transfer:false,
    })
}
pub fn fetch_and_verify(
    board:&DurableTransparencyBoard,
    policy:&ObserverPolicy,
    trust:&ExternalServiceTrust,
    challenge:&RemoteCheckpointChallenge,
    transport:&dyn RemoteCheckpointTransport,
    trusted_now_unix_seconds:u64,
)->Result<RemoteCheckpointAssessment,String>{
    let (peer,response)=transport.exchange(challenge)?;
    verify_remote_exchange(board,policy,trust,challenge,
        &peer,&response,trusted_now_unix_seconds)
}
