//! GALIA v0.9 WITNESS SIMULATION (opt-in scratch feature only).
//! Defines a monotonic consume-and-compare contract to be implemented by an
//! INDEPENDENT durable trusted service in the future. This in-memory example
//! is NOT persistent, externally reachable, authenticated or production-ready.
//! A successful result does NOT grant human approval or canonical authority.
use std::collections::BTreeSet;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FORMAT:&str="GALIA_NONCANONICAL_WITNESS_V1";
fn sha(raw:&[u8])->String {format!("{:x}",Sha256::digest(raw))}
fn lowercase_hash(value:&str)->bool{
    value.len()==64 && value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn identity(value:&str)->bool{
    !value.trim().is_empty() && value.len()<=256 &&
        !value.chars().any(|c|c.is_control())
}
fn to_bytes<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    let json=serde_json::to_value(value).map_err(|e|e.to_string())?;
    serde_json::to_vec(&json).map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig{
    /// Pinned by the witness operator, not delegated to caller requests.
    pub namespace:String,
    pub case_id:String,
    pub pinned_root_public_key_hex:String,
    pub initial_registry_epoch:u64,
}
impl WitnessConfig{
    pub fn validate(&self)->Result<(),String>{
        if !identity(&self.namespace)||!identity(&self.case_id)
            ||!lowercase_hash(&self.pinned_root_public_key_hex)
            ||self.initial_registry_epoch==0 {
            return Err("witness independently pinned identity/root/epoch invalid".into())
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessObservation{
    pub namespace:String,
    pub case_id:String,
    pub registry_epoch:u64,
    pub spent_count:u64,
    pub tip_sha256:Option<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConsume{
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    pub pinned_root_public_key_hex:String,
    pub registry_epoch:u64,
    pub authorization_id:String,
    pub nonce_sha256:String,
    pub signed_decision_sha256:String,
    /// Compare-and-swap token from an independent witness observation.
    pub expected_tip_sha256:Option<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceipt{
    pub format:String,
    pub namespace:String,
    pub case_id:String,
    pub registry_epoch:u64,
    pub spent_count:u64,
    pub prior_tip_sha256:Option<String>,
    pub tip_sha256:String,
    pub authorization_id:String,
    pub nonce_sha256:String,
    pub signed_decision_sha256:String,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
/// CONTRACT ONLY: implementing services MUST persist the entire spend transition
/// in one linearizable transaction, expose an authenticated observation, and
/// enforce root pins, replay and registry epoch monotonicity without caller control.
/// This interface does not itself prove that an implementation is external,
/// durable, authenticated, trusted or linearizable.
pub trait MonotonicWitness:Send+Sync{
    fn observe(&self)->Result<WitnessObservation,String>;
    fn consume(&self,request:&WitnessConsume)->Result<WitnessReceipt,String>;
    /// Optional replay-verified receipt lookup. Unimplemented in-memory by default.
    fn find_spend(&self,_authorization_id:&str)->Result<Option<WitnessReceipt>,String>{
        Err("witness receipt lookup unsupported".into())
    }
}
#[derive(Debug)]
struct MemoryState {
    epoch:u64,
    tip:Option<String>,
    spent_count:u64,
    ids:BTreeSet<String>,
    nonces:BTreeSet<String>,
}
/// Same-process simulation only. Losing this object loses its entire history.
/// NEVER use it as a production witness or an authority provider.
#[derive(Debug)]
pub struct InMemoryWitness{
    config:WitnessConfig,
    state:Mutex<MemoryState>,
}
impl InMemoryWitness{
    pub fn new(config:WitnessConfig)->Result<Self,String>{
        config.validate()?;
        Ok(Self{
            state:Mutex::new(MemoryState{
                epoch:config.initial_registry_epoch,
                tip:None,spent_count:0,ids:BTreeSet::new(),nonces:BTreeSet::new()
            }),
            config,
        })
    }
    fn lock(&self)->Result<std::sync::MutexGuard<'_,MemoryState>,String>{
        self.state.lock().map_err(|_|"witness mutex poisoned: fail closed".into())
    }
    fn validate_request(&self,req:&WitnessConsume)->Result<(),String>{
        if req.format!=FORMAT ||req.namespace!=self.config.namespace
            ||req.case_id!=self.config.case_id
            ||req.pinned_root_public_key_hex!=self.config.pinned_root_public_key_hex
            ||req.registry_epoch==0
            ||!identity(&req.authorization_id)
            ||!lowercase_hash(&req.nonce_sha256)
            ||!lowercase_hash(&req.signed_decision_sha256)
            ||req.expected_tip_sha256.as_ref().is_some_and(|x|!lowercase_hash(x)){
            return Err("witness request does not match independent scope/root policy".into())
        }
        Ok(())
    }
}
impl MonotonicWitness for InMemoryWitness{
    fn observe(&self)->Result<WitnessObservation,String>{
        let state=self.lock()?;
        Ok(WitnessObservation{
            namespace:self.config.namespace.clone(),
            case_id:self.config.case_id.clone(),
            registry_epoch:state.epoch,
            spent_count:state.spent_count,
            tip_sha256:state.tip.clone(),
        })
    }
    fn consume(&self,req:&WitnessConsume)->Result<WitnessReceipt,String>{
        self.validate_request(req)?;
        let mut state=self.lock()?;
        if req.registry_epoch<state.epoch {
            return Err("witness rejected registry-epoch rollback".into())
        }
        if req.expected_tip_sha256!=state.tip {
            return Err("witness CAS conflict: observation no longer current".into())
        }
        if state.ids.contains(&req.authorization_id)||state.nonces.contains(&req.nonce_sha256) {
            return Err("witness replay: authorization ID or nonce spent".into())
        }
        let next_count=state.spent_count.checked_add(1).ok_or("witness count overflow")?;
        let prior=state.tip.clone();
        let mut wire=to_bytes(req)?;
        // Explicit counter prevents serialization ambiguities across repeated
        // but distinct valid events; must be preserved by future service.
        wire.extend_from_slice(&next_count.to_be_bytes());
        let tip=sha(&wire);
        let receipt=WitnessReceipt{
            format:FORMAT.into(),namespace:self.config.namespace.clone(),
            case_id:self.config.case_id.clone(),registry_epoch:req.registry_epoch,
            spent_count:next_count,prior_tip_sha256:prior,
            tip_sha256:tip.clone(),authorization_id:req.authorization_id.clone(),
            nonce_sha256:req.nonce_sha256.clone(),
            signed_decision_sha256:req.signed_decision_sha256.clone(),
            canonical_writeback:false,authority_transfer:false,
        };
        state.ids.insert(req.authorization_id.clone());
        state.nonces.insert(req.nonce_sha256.clone());
        state.epoch=req.registry_epoch;
        state.spent_count=next_count;
        state.tip=Some(tip);
        Ok(receipt)
    }
}
#[cfg(test)]
mod tests {
 use super::*;
 fn h(c:char)->String{std::iter::repeat(c).take(64).collect()}
 fn fixture()->InMemoryWitness{
    InMemoryWitness::new(WitnessConfig{
        namespace:"tenant".into(),case_id:"case".into(),
        pinned_root_public_key_hex:h('a'),initial_registry_epoch:7
    }).unwrap()
 }
 fn request(auth:&str,nonce:char,tip:Option<String>)->WitnessConsume{
    WitnessConsume{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"case".into(),
        pinned_root_public_key_hex:h('a'),registry_epoch:7,
        authorization_id:auth.into(),nonce_sha256:h(nonce),
        signed_decision_sha256:h('f'),expected_tip_sha256:tip,
    }
 }
 #[test]fn duplicate_nonce_and_authorization_denied(){
    let w=fixture();
    let first=w.consume(&request("a",'1',None)).unwrap();
    assert_eq!(first.spent_count,1);
    assert!(!first.canonical_writeback&&!first.authority_transfer);
    assert!(w.consume(&request("a",'2',Some(first.tip_sha256.clone()))).is_err());
    assert!(w.consume(&request("b",'1',Some(first.tip_sha256.clone()))).is_err());
    assert_eq!(w.observe().unwrap().spent_count,1);
 }
 #[test]fn stale_compare_and_swap_rejected_even_with_unique_ids(){
    let w=fixture();
    let _first=w.consume(&request("a",'1',None)).unwrap();
    assert!(w.consume(&request("b",'2',None)).is_err());
    assert!(w.consume(&request("b",'2',w.observe().unwrap().tip_sha256)).is_ok());
 }
 #[test]fn independent_scope_and_epoch_floor_reject_forgery(){
    let w=fixture();let mut wrong=request("x",'1',None);
    wrong.pinned_root_public_key_hex=h('b');assert!(w.consume(&wrong).is_err());
    let mut wrong=request("x",'1',None);
    wrong.case_id="other".into();assert!(w.consume(&wrong).is_err());
    let mut wrong=request("x",'1',None);
    wrong.registry_epoch=6;assert!(w.consume(&wrong).is_err());
    let mut higher=request("x",'1',None);
    higher.registry_epoch=9;
    w.consume(&higher).unwrap();
    let mut old=request("y",'2',w.observe().unwrap().tip_sha256);
    old.registry_epoch=8;assert!(w.consume(&old).is_err());
 }
 #[test]fn shared_witness_across_simulated_hosts_has_one_winner(){
    use std::sync::{Arc,Barrier};
    use std::thread;
    let w=Arc::new(fixture());
    let barrier=Arc::new(Barrier::new(5));
    let jobs=(0..4).map(|i|{
        let w=Arc::clone(&w);let b=Arc::clone(&barrier);
        thread::spawn(move||{
            let req=request(&format!("auth-{i}"),char::from(b'1'+i as u8),None);
            b.wait();w.consume(&req).is_ok()
        })
    }).collect::<Vec<_>>();
    barrier.wait();
    let winners=jobs.into_iter().map(|j|j.join().unwrap()).filter(|won|*won).count();
    assert_eq!(winners,1);
    assert_eq!(w.observe().unwrap().spent_count,1);
 }
}
