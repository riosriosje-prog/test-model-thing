//! v0.13 noncanonical, offline observer gossip and split-view evidence.
//! Independent keys are trusted ONLY relative to a separately provisioned
//! roster. Neither key custody, fresh gossip nor transport independence can
//! be established from caller-supplied data. No P5/canonical authority.
use std::collections::{BTreeMap,BTreeSet};
use serde::{Deserialize,Serialize};
use crate::attestation::signing_preimage;
use crate::audit::sha256;
use crate::witness_proof::{
    WitnessTrustAnchor,SignedWitnessObservation,verify_observation,verify_detached,
    validate_public_key,
};
use crate::witness_continuity::{WitnessContinuityRequest,verify_continuity};

pub const GOSSIP_FORMAT:&str="GALIA_NONCANONICAL_WITNESS_GOSSIP_V1";
pub const GOSSIP_DOMAIN:&[u8]=b"GALIA_WITNESS_GOSSIP_OBSERVER_V1\0";

fn label(s:&str)->bool{!s.trim().is_empty() && s.len()<=256 &&
    !s.chars().any(|c|c.is_control())}
fn digest(s:&str)->bool{s.len()==64 &&
    s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn canonical<T:Serialize>(obj:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(obj).and_then(|v|serde_json::to_vec(&v))
        .map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedObserver{
    pub observer_id:String,
    pub public_key_hex:String,
    pub revoked:bool,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverPolicy{
    /// The witness key itself and these independent roster keys MUST be
    /// provisioned out-of-band, not selected by the publication being checked.
    pub witness_anchor:WitnessTrustAnchor,
    pub roster_epoch:u64,
    pub required_quorum:u64,
    pub observers:Vec<TrustedObserver>,
}
impl ObserverPolicy{
    pub fn validate(&self)->Result<(),String>{
        self.witness_anchor.validate()?;
        if self.roster_epoch==0||self.required_quorum<2 ||
            self.observers.len()<2 ||
            self.required_quorum>u64::try_from(self.observers.len()).map_err(|_|"too many observers")?{
            return Err("invalid observer roster epoch/quorum".into());
        }
        let mut ids=BTreeSet::new();
        let mut keys=BTreeSet::new();
        let mut active=0u64;
        for o in &self.observers{
            if !label(&o.observer_id)||
                !ids.insert(o.observer_id.as_str())||
                !keys.insert(o.public_key_hex.as_str())||
                o.public_key_hex==self.witness_anchor.pinned_witness_public_key_hex||
                o.public_key_hex==self.witness_anchor.pinned_review_root_public_key_hex {
                return Err("observer roster key reuse, role confusion or invalid ID".into());
            }
            validate_public_key(&o.public_key_hex)?;
            if !o.revoked{active+=1;}
        }
        if active<self.required_quorum{
            return Err("observer policy has insufficient nonrevoked keys".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipEndorsementPayload{
    pub format:String,
    pub roster_epoch:u64,
    pub observer_id:String,
    pub namespace:String,
    pub case_id:String,
    /// Hash of the EXACT signed witness observation envelope, not only its tip.
    pub witness_observation_sha256:String,
    pub spent_count:u64,
    pub tip_sha256:Option<String>,
    pub registry_epoch:u64,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGossipEndorsement{
    pub payload:GossipEndorsementPayload,
    pub signature_hex:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedWitnessView{
    pub signed_observation:SignedWitnessObservation,
    pub endorsements:Vec<SignedGossipEndorsement>,
}
#[derive(Clone,Debug,Serialize)]
pub struct PublicationReport{
    pub status:&'static str,
    pub observer_quorum:u64,
    pub roster_epoch:u64,
    pub observation_sha256:String,
    pub count:u64,
    pub tip_sha256:Option<String>,
    pub registry_epoch:u64,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
pub fn verify_publication(
    view:&PublishedWitnessView, policy:&ObserverPolicy
)->Result<PublicationReport,String>{
    policy.validate()?;
    let o=verify_observation(&view.signed_observation,&policy.witness_anchor)?;
    let hash=sha256(&canonical(&view.signed_observation)?);
    let roster:BTreeMap<&str,&TrustedObserver>=policy.observers.iter()
        .map(|x|(x.observer_id.as_str(),x)).collect();
    let mut approved=BTreeSet::new();
    for signed in &view.endorsements{
        let p=&signed.payload;
        if p.format!=GOSSIP_FORMAT||p.roster_epoch!=policy.roster_epoch||
            !label(&p.observer_id)||
            p.namespace!=o.namespace||p.case_id!=o.case_id||
            p.witness_observation_sha256!=hash||
            !digest(&p.witness_observation_sha256)||
            p.spent_count!=o.spent_count||
            p.tip_sha256!=o.tip_sha256||
            p.registry_epoch!=o.registry_epoch {
            return Err("gossip endorsement not bound to exact signed witness observation".into())
        }
        let record=roster.get(p.observer_id.as_str())
            .ok_or("unknown observer ID")?;
        if record.revoked||!approved.insert(p.observer_id.as_str()){
            return Err("revoked or duplicate observer endorsement".into())
        }
        verify_detached(&record.public_key_hex,&signed.signature_hex,GOSSIP_DOMAIN,p)?;
    }
    let quorum=u64::try_from(approved.len()).map_err(|_|"observer count overflow")?;
    if quorum<policy.required_quorum{return Err("insufficient independently pinned observer signatures".into())}
    Ok(PublicationReport{
        status:"OBSERVER_QUORUM_CONSISTENT_ADVISORY_ONLY",
        observer_quorum:quorum,roster_epoch:policy.roster_epoch,
        observation_sha256:hash,count:o.spent_count,
        tip_sha256:o.tip_sha256,registry_epoch:o.registry_epoch,
        human_authority_verified:false,canonical_writeback:false,authority_transfer:false
    })
}
#[derive(Clone,Debug,Eq,PartialEq,Serialize)]
pub enum ComparisonKind{
    SameSignedState,
    ConflictingSignedState,
    DifferentHeightExtensionNotEstablished,
    VerifiedSignedExtension,
}
#[derive(Clone,Debug,Serialize)]
pub struct GossipComparison{
    pub kind:ComparisonKind,
    /// Enough to retrieve BOTH independently verifiable full publications,
    /// which MUST be retained separately as actual evidence.
    pub left_observation_sha256:String,
    pub right_observation_sha256:String,
    pub left_count:u64,
    pub right_count:u64,
    pub witness_equivocation_evidence:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
pub fn compare_publications(
    left:&PublishedWitnessView,right:&PublishedWitnessView,policy:&ObserverPolicy
)->Result<GossipComparison,String>{
    let a=verify_publication(left,policy)?;
    let b=verify_publication(right,policy)?;
    let kind=if a.count==b.count{
        if a.tip_sha256==b.tip_sha256 && a.registry_epoch==b.registry_epoch {
            ComparisonKind::SameSignedState
        }else{
            ComparisonKind::ConflictingSignedState
        }
    }else{
        ComparisonKind::DifferentHeightExtensionNotEstablished
    };
    Ok(GossipComparison{
        witness_equivocation_evidence:kind==ComparisonKind::ConflictingSignedState,
        kind,left_observation_sha256:a.observation_sha256,
        right_observation_sha256:b.observation_sha256,
        left_count:a.count,right_count:b.count,
        human_authority_verified:false,canonical_writeback:false,authority_transfer:false
    })
}
/// Two independently endorsed views at different heights are NOT proven
/// consistent until v0.12 verifies EVERY signed intermediate receipt and any
/// rotations from the earlier view's precise count, tip, signer, and epoch.
pub fn verify_publication_extension(
    earlier:&PublishedWitnessView,later:&PublishedWitnessView,
    earlier_policy:&ObserverPolicy,later_policy:&ObserverPolicy,
    proof:&WitnessContinuityRequest
)->Result<GossipComparison,String>{
    // Observer keys/roster must remain pinned across this comparison.
    // A witness signing-key rotation is allowed only via the signed v0.12 path.
    if earlier_policy.roster_epoch!=later_policy.roster_epoch||
        earlier_policy.required_quorum!=later_policy.required_quorum||
        canonical(&earlier_policy.observers)?!=canonical(&later_policy.observers)?||
        earlier_policy.witness_anchor.expected_case_id!=later_policy.witness_anchor.expected_case_id||
        earlier_policy.witness_anchor.expected_namespace!=later_policy.witness_anchor.expected_namespace||
        earlier_policy.witness_anchor.pinned_review_root_public_key_hex!=
            later_policy.witness_anchor.pinned_review_root_public_key_hex {
        return Err("observer roster or review-root changed without pinned transition".into())
    }
    let old=verify_publication(earlier,earlier_policy)?;
    let new=verify_publication(later,later_policy)?;
    if old.count>=new.count{
        return Err("extension requires strictly increasing height".into())
    }
    let mut cmp=GossipComparison{
        kind:ComparisonKind::DifferentHeightExtensionNotEstablished,
        left_observation_sha256:old.observation_sha256,
        right_observation_sha256:new.observation_sha256,
        left_count:old.count,right_count:new.count,
        witness_equivocation_evidence:false,human_authority_verified:false,
        canonical_writeback:false,authority_transfer:false,
    };
    let a=&earlier.signed_observation;
    let b=&later.signed_observation;
    if proof.anchor.signer_key_id!=a.signer_key_id||
        proof.anchor.pinned_witness_public_key_hex!=earlier_policy.witness_anchor.pinned_witness_public_key_hex||
        proof.anchor.pinned_review_root_public_key_hex!=earlier_policy.witness_anchor.pinned_review_root_public_key_hex||
        proof.anchor.expected_namespace!=earlier_policy.witness_anchor.expected_namespace||
        proof.anchor.expected_case_id!=earlier_policy.witness_anchor.expected_case_id||
        proof.anchor.minimum_spent_count!=a.observation.spent_count||
        proof.anchor.floor_tip_sha256!=a.observation.tip_sha256||
        proof.anchor.minimum_registry_epoch!=a.observation.registry_epoch||
        canonical(&proof.current_observation)?!=canonical(b)?{
        return Err("continuity proof endpoints/key do not match endorsed observations".into())
    }
    let result=verify_continuity(proof)?;
    if result.final_count!=b.observation.spent_count||
        result.final_tip_sha256!=b.observation.tip_sha256||
        result.final_registry_epoch!=b.observation.registry_epoch||
        result.ending_signer_key_id!=later_policy.witness_anchor.signer_key_id{
        return Err("continuity verifier returned wrong terminal state or signer".into())
    }
    cmp.kind=ComparisonKind::VerifiedSignedExtension;
    Ok(cmp)
}
