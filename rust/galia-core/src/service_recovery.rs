//! GALIA v0.21 — offline, independently pinned signed service-state comparison.
//! Two separately pinned local service identities can publish diagnostic views
//! of their own checkpoint/nonce high-water marks. Cross-host agreement is NOT
//! established: no consensus, remote transport or repair writes are provided.
//! Authenticity depends on out-of-band key custody and high-water retention.
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::attestation::signing_preimage;
use crate::external_checkpoint::policy_digest;
use crate::external_transport::ExternalServiceTrust;
use crate::mtls_checkpoint_server::{ServiceSnapshot,ScratchCheckpointServiceStore};
use crate::transparency::ObserverPolicy;
use crate::witness_proof::{validate_public_key,verify_detached};

pub const SERVICE_VIEW_FORMAT:&str="GALIA_NONCANONICAL_SERVICE_VIEW_V1";
pub const SERVICE_VIEW_DOMAIN:&[u8]=b"GALIA_SIGNED_SERVICE_VIEW_V1\0";
fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(value).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
fn ident(v:&str)->bool{!v.trim().is_empty()&&v.len()<=256&&!v.chars().any(|c|c.is_control())}
fn hash(v:&str)->bool{v.len()==64&&v.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePeerTrust{
    /// Provisioned OUTSIDE the scratch journals. Does not prove key custody.
    pub host_id:String,
    pub signer_key_id:String,
    pub signer_public_key_hex:String,
    pub service_id:String,
    pub namespace:String,
    pub case_id:String,
    pub service_trust_sha256:String,
    pub observer_policy_sha256:String,
    /// Optional out-of-band high-water, checked against complete local journal
    /// prefixes when the local store is available; a detached view cannot
    /// establish an extension on its own.
    pub floor:Option<ServiceSnapshot>,
}
impl ServicePeerTrust{
    pub fn validate(&self,service:&ExternalServiceTrust,policy:&ObserverPolicy)->Result<(),String>{
        service.validate(policy)?;
        if !ident(&self.host_id)||!ident(&self.signer_key_id)||
            !ident(&self.service_id)||!ident(&self.namespace)||!ident(&self.case_id)||
            self.service_id!=service.service_id||
            self.namespace!=service.checkpoint.namespace||
            self.case_id!=service.checkpoint.case_id||
            !hash(&self.service_trust_sha256)||
            self.service_trust_sha256!=sha256(&canonical(service)?)||
            !hash(&self.observer_policy_sha256)||
            self.observer_policy_sha256!=policy_digest(policy)?{
            return Err("peer trust not separately scoped to exact host/service/case".into())
        }
        validate_public_key(&self.signer_public_key_hex)?;
        let k=&self.signer_public_key_hex;
        if k==&service.response_signer_public_key_hex||
            k==&service.checkpoint.external_signer_public_key_hex||
            k==&policy.witness_anchor.pinned_review_root_public_key_hex||
            k==&policy.witness_anchor.pinned_witness_public_key_hex||
            policy.observers.iter().any(|p|k==&p.public_key_hex){
            return Err("peer view signer must not alias production identity roles".into())
        }
        if let Some(f)=&self.floor{f.validate()?}
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePeerViewPayload{
    pub format:String,
    pub host_id:String,
    pub signer_key_id:String,
    pub service_id:String,
    pub namespace:String,
    pub case_id:String,
    pub service_trust_sha256:String,
    pub observer_policy_sha256:String,
    pub snapshot:ServiceSnapshot,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServicePeerView{
    pub payload:ServicePeerViewPayload,
    pub signature_hex:String,
}
/// Detached signed evidence proves integrity relative to a supplied signing
/// key only. It does NOT independently confirm the underlying live service.
pub fn verify_peer_view(
    view:&SignedServicePeerView,
    trust:&ServicePeerTrust,
    service:&ExternalServiceTrust,policy:&ObserverPolicy,
)->Result<String,String>{
    trust.validate(service,policy)?;
    let p=&view.payload;
    p.snapshot.validate()?;
    if p.format!=SERVICE_VIEW_FORMAT||
        p.host_id!=trust.host_id||p.signer_key_id!=trust.signer_key_id||
        p.service_id!=trust.service_id||
        p.namespace!=trust.namespace||p.case_id!=trust.case_id||
        p.service_trust_sha256!=trust.service_trust_sha256||
        p.observer_policy_sha256!=trust.observer_policy_sha256{
        return Err("signed peer observation does not match pinned host scope".into())
    }
    if let Some(f)=&trust.floor{
        let s=&p.snapshot;
        if s.checkpoint_count<f.checkpoint_count||s.nonce_count<f.nonce_count||
            (s.checkpoint_count==f.checkpoint_count&&
             s.checkpoint_tip_sha256!=f.checkpoint_tip_sha256)||
            (s.nonce_count==f.nonce_count&&s.nonce_tip_sha256!=f.nonce_tip_sha256){
            return Err("signed peer observation below pinned high-water floor".into())
        }
    }
    verify_detached(&trust.signer_public_key_hex,&view.signature_hex,
        SERVICE_VIEW_DOMAIN,p)?;
    Ok(sha256(&canonical(view)?))
}
/// When a peer's local scratch journal is available, cryptographically verify
/// the signed view then validate every local entry/prefix against the signed
/// snapshot AND against the independent retained high-water floor.
pub fn inspect_local_peer(
    store:&ScratchCheckpointServiceStore,
    view:&SignedServicePeerView,
    trust:&ServicePeerTrust,
    service:&ExternalServiceTrust,policy:&ObserverPolicy,
)->Result<ServiceSnapshot,String>{
    verify_peer_view(view,trust,service,policy)?;
    if let Some(f)=&trust.floor{store.verify_external_floor(f)?;}
    let local=store.snapshot()?;
    if local!=view.payload.snapshot{
        return Err("signed peer view and fully replayed local scratch logs differ".into())
    }
    Ok(local)
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
pub enum PeerComparisonKind{
    IdenticalSignedState,
    SignedStateDivergence,
    DifferentHeightsConsistencyUnproven,
}
#[derive(Clone,Debug,Serialize)]
pub struct PeerRecoveryAssessment{
    pub kind:PeerComparisonKind,
    pub left_signed_view_sha256:String,
    pub right_signed_view_sha256:String,
    pub exact_checkpoint_match:bool,
    pub exact_nonce_history_match:bool,
    pub signed_divergence_evidence:bool,
    pub automatic_recovery_permitted:bool,
    pub cross_host_consensus_verified:bool,
    pub real_host_independence_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// Compare individually signed and separately pinned host observations. A
/// split nonce history at the same count is divergence, NOT proof of malicious
/// equivocation: independent hosts may have legitimately accepted different
/// requests in a partition. No automatic winner, repair or authority transfer.
pub fn compare_peer_views(
    left:&SignedServicePeerView,left_pin:&ServicePeerTrust,left_service:&ExternalServiceTrust,
    right:&SignedServicePeerView,right_pin:&ServicePeerTrust,right_service:&ExternalServiceTrust,
    policy:&ObserverPolicy,
)->Result<PeerRecoveryAssessment,String>{
    let left_hash=verify_peer_view(left,left_pin,left_service,policy)?;
    let right_hash=verify_peer_view(right,right_pin,right_service,policy)?;
    if left_pin.host_id==right_pin.host_id||
        left_pin.signer_public_key_hex==right_pin.signer_public_key_hex||
        left_pin.service_id!=right_pin.service_id||
        left_pin.namespace!=right_pin.namespace||
        left_pin.case_id!=right_pin.case_id||
        left_pin.observer_policy_sha256!=right_pin.observer_policy_sha256{
        return Err("peer comparison requires distinct signer/host and same logical scope".into())
    }
    let a=&left.payload.snapshot;let b=&right.payload.snapshot;
    let checkpoint_equal=a.checkpoint_count==b.checkpoint_count&&
        a.checkpoint_tip_sha256==b.checkpoint_tip_sha256;
    let nonce_equal=a.nonce_count==b.nonce_count&&
        a.nonce_tip_sha256==b.nonce_tip_sha256;
    let conflicting=(a.checkpoint_count==b.checkpoint_count&&!checkpoint_equal)||
        (a.nonce_count==b.nonce_count&&!nonce_equal);
    let kind=if conflicting{PeerComparisonKind::SignedStateDivergence}
        else if checkpoint_equal&&nonce_equal{PeerComparisonKind::IdenticalSignedState}
        else{PeerComparisonKind::DifferentHeightsConsistencyUnproven};
    Ok(PeerRecoveryAssessment{
        kind,left_signed_view_sha256:left_hash,right_signed_view_sha256:right_hash,
        exact_checkpoint_match:checkpoint_equal,exact_nonce_history_match:nonce_equal,
        signed_divergence_evidence:conflicting,
        automatic_recovery_permitted:false,cross_host_consensus_verified:false,
        real_host_independence_verified:false,human_authority_verified:false,
        canonical_writeback:false,authority_transfer:false,
    })
}
