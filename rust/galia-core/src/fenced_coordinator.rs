//! GALIA Rust v0.22 — experimental single-authority local fencing coordinator.
//! This is NOT distributed consensus, a quorum, or a production remote service.
//! Two simulated hosts may share one durable scratch root; cooperative exclusive
//! file locking serializes epoch transitions and nonce claims across processes.
//! Without access to this coordinator, a fenced request MUST FAIL CLOSED.
//! A filesystem snapshot rollback, stolen role/key or unguarded legacy service
//! can bypass these local-only properties. Human AUTHORITY_HOLD is unchanged.
use std::collections::{BTreeSet,BTreeMap};
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::external_transport::{SignedRemoteCheckpointResponse,RESPONSE_DOMAIN};
use crate::witness_proof::{validate_public_key,verify_detached};

const FORMAT:&str="GALIA_NONCANONICAL_EPOCH_FENCING_V1";
const MARKER:&str=".GALIA_NONCANONICAL_EPOCH_FENCING_V1";
const LOCK:&str=".coordinator.lock";
const JOURNAL:&str="journal";

fn serialize<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn valid_id(v:&str)->bool{!v.trim().is_empty()&&v.len()<=256&&!v.chars().any(|c|c.is_control())}
fn valid_hash(v:&str)->bool{v.len()==64&&v.bytes().all(|x|x.is_ascii_digit()||(b'a'..=b'f').contains(&x))}
fn real_dir(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err("coordinator directory must be real".into())}
    Ok(())
}
fn regular(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err("coordinator file must be regular, not symlink".into())}
    Ok(())
}
fn read(p:&Path)->Result<Vec<u8>,String>{regular(p)?;fs::read(p).map_err(|e|e.to_string())}
fn write_once(p:&Path,bytes:&[u8])->Result<(),String>{
    let mut f=OpenOptions::new().write(true).create_new(true).open(p).map_err(|e|e.to_string())?;
    f.write_all(bytes).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}
fn sync_dir(p:&Path)->Result<(),String>{
    File::open(p).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct FencingScope{
    pub namespace:String,
    pub case_id:String,
    pub service_id:String,
    /// SHA-256 of an independently pinned, shared observer policy for the federation.
    pub pinned_observer_policy_sha256:String,
    /// Independently pinned service signing key; not self-declared by a reply.
    pub pinned_response_signer_public_key_hex:String,
}
impl FencingScope{
    pub fn validate(&self)->Result<(),String>{
        if !valid_id(&self.namespace)||!valid_id(&self.case_id)||!valid_id(&self.service_id)||
            !valid_hash(&self.pinned_observer_policy_sha256){
            return Err("invalid independently supplied fencing scope".into())
        }
        validate_public_key(&self.pinned_response_signer_public_key_hex)?;
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct EpochGrant{
    pub host_id:String,
    pub epoch:u64,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct FencingCheckpoint{
    pub record_count:u64,
    pub journal_tip_sha256:Option<String>,
    pub active_grant:Option<EpochGrant>,
    pub nonce_claim_count:u64,
}
impl FencingCheckpoint{
    pub fn validate(&self)->Result<(),String>{
        if (self.record_count==0)!=self.journal_tip_sha256.is_none()||
            self.journal_tip_sha256.as_ref().is_some_and(|h|!valid_hash(h))||
            self.nonce_claim_count>self.record_count||
            (self.record_count==0)!=self.active_grant.is_none(){
            return Err("invalid fencing checkpoint".into())
        }
        if let Some(g)=&self.active_grant{
            if g.epoch==0||!valid_id(&g.host_id){return Err("invalid checkpoint grant".into())}
        }
        Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE",tag="kind",deny_unknown_fields)]
enum FencingAction{
    AcquireEpoch{grant:EpochGrant},
    ConsumeNonce{grant:EpochGrant,nonce_sha256:String},
    CommitResponse{grant:EpochGrant,nonce_sha256:String,response_sha256:String,response_json:String},
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct FencingEntry{
    format:String,
    sequence:u64,
    previous_sha256:Option<String>,
    action:FencingAction,
}
struct State{
    count:u64,
    tip:Option<String>,
    epoch:u64,
    active:Option<EpochGrant>,
    nonces:BTreeSet<String>,
    committed:BTreeMap<String,String>,
    committed_host:BTreeMap<String,String>,
    prefix:Vec<FencingCheckpoint>,
}
impl State{
    fn blank()->Self{Self{
        count:0,tip:None,epoch:0,active:None,
        nonces:BTreeSet::new(),committed:BTreeMap::new(),
        committed_host:BTreeMap::new(),prefix:Vec::new()
    }}
    fn checkpoint(&self)->FencingCheckpoint{FencingCheckpoint{
        record_count:self.count,
        journal_tip_sha256:self.tip.clone(),
        active_grant:self.active.clone(),
        nonce_claim_count:self.nonces.len() as u64,
    }}
    fn apply(&mut self,entry:&FencingEntry,raw:&[u8],scope:&FencingScope)->Result<(),String>{
        let next=self.count.checked_add(1).ok_or("coordinator sequence overflow")?;
        if entry.format!=FORMAT||entry.sequence!=next||
            entry.previous_sha256!=self.tip||serialize(entry)?!=raw{
            return Err("fencing journal sequence/chain mismatch".into())
        }
        match &entry.action{
            FencingAction::AcquireEpoch{grant}=>{
                if !valid_id(&grant.host_id)||
                    grant.epoch!=self.epoch.checked_add(1).ok_or("fencing epoch overflow")?{
                    return Err("fencing epoch rollback or invalid new holder".into())
                }
                self.epoch=grant.epoch;self.active=Some(grant.clone());
            },
            FencingAction::ConsumeNonce{grant,nonce_sha256}=>{
                if self.active.as_ref()!=Some(grant)||!valid_hash(nonce_sha256)||
                    !self.nonces.insert(nonce_sha256.clone()){
                    return Err("fencing claim stale, duplicate or invalid".into())
                }
            },
            FencingAction::CommitResponse{grant,nonce_sha256,response_sha256,response_json}=>{
                if self.active.as_ref()!=Some(grant)||
                    !valid_hash(nonce_sha256)||!valid_hash(response_sha256)||
                    response_json.is_empty()||response_json.len()>1024*1024||
                    sha256(response_json.as_bytes())!=*response_sha256 {
                    return Err("invalid or stale commit-point fencing and content hash".into())
                }
                let json:serde_json::Value=serde_json::from_str(response_json)
                    .map_err(|e|e.to_string())?;
                if serialize(&json)?!=response_json.as_bytes(){
                    return Err("commit response must be canonical JSON".into())
                }
                let signed:SignedRemoteCheckpointResponse=serde_json::from_str(response_json)
                    .map_err(|e|e.to_string())?;
                if signed.payload.nonce_sha256!=*nonce_sha256||
                    signed.payload.service_id!=scope.service_id {
                    return Err("commit transcript wrong nonce or service scope".into())
                }
                verify_detached(&scope.pinned_response_signer_public_key_hex,
                    &signed.signature_hex,RESPONSE_DOMAIN,&signed.payload)?;
                if !self.nonces.insert(nonce_sha256.clone()){
                    return Err("nonce already committed or claimed".into())
                }
                self.committed.insert(nonce_sha256.clone(),response_json.clone());
                self.committed_host.insert(nonce_sha256.clone(),grant.host_id.clone());
            }
        }
        self.count=next;
        self.tip=Some(sha256(raw));
        self.prefix.push(self.checkpoint());
        Ok(())
    }
}
struct LockGuard(File);
impl Drop for LockGuard{fn drop(&mut self){let _=FileExt::unlock(&self.0);}}
#[derive(Clone)]
pub struct DurableFencingCoordinator{
    root:PathBuf,
    scope:FencingScope,
}
/// Protocol boundary for a real authenticated coordinator adapter. The only
/// implementation in v0.22 is local cooperative scratch storage. If a remote
/// coordinator is unreachable, an adapter MUST return Err without fallback.
/// Every storage commit must compare the epoch under the SAME lock as the
/// actual durable record append. A preflight check plus later write is unsafe.
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedCommitReceipt{
    pub status:String,
    pub grant:EpochGrant,
    pub nonce_sha256:String,
    pub response_sha256:String,
    pub checkpoint:FencingCheckpoint,
    pub durable_scratch_record_committed:bool,
    pub cross_host_consensus_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
pub trait FencingAuthority:Send+Sync{
    fn scope(&self)->Result<FencingScope,String>;
    fn claim(&self,grant:&EpochGrant,nonce_sha256:&str)->Result<FencingCheckpoint,String>;
    /// Commit the canonical signed-response JSON *inside* coordinator epoch
    /// validation. The default is fail closed; external adapters may not
    /// silently degrade this to the old claim-then-write semantics.
    fn commit_response(&self,_grant:&EpochGrant,_nonce_sha256:&str,
        _response_json:&str)->Result<FencedCommitReceipt,String>{
        Err("commit-boundary fencing is unsupported by this coordinator".into())
    }
}
impl DurableFencingCoordinator{
    pub fn initialize_new(root:impl AsRef<Path>,scope:FencingScope)->Result<Self,String>{
        scope.validate()?;
        let p=root.as_ref();
        if fs::symlink_metadata(p).is_ok(){
            return Err("refuse to initialize existing coordinator root".into())
        }
        fs::create_dir(p).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(p,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;
        }
        write_once(&p.join(MARKER),&serialize(&scope)?)?;
        fs::create_dir(p.join(JOURNAL)).map_err(|e|e.to_string())?;
        write_once(&p.join(LOCK),b"")?;
        sync_dir(p)?;
        Self::open(p,scope)
    }
    pub fn open(root:impl AsRef<Path>,scope:FencingScope)->Result<Self,String>{
        scope.validate()?;
        let p=root.as_ref();
        real_dir(p)?;real_dir(&p.join(JOURNAL))?;regular(&p.join(LOCK))?;
        if read(&p.join(MARKER))?!=serialize(&scope)?{
            return Err("coordinator root does not match externally supplied scope".into())
        }
        let me=Self{root:fs::canonicalize(p).map_err(|e|e.to_string())?,scope};
        let _lock=me.lock()?;
        me.replay()?;
        Ok(me)
    }
    fn lock(&self)->Result<LockGuard,String>{
        regular(&self.root.join(LOCK))?;
        let f=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&f).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=serialize(&self.scope)?{
            return Err("fencing scope changed after opening".into())
        }
        Ok(LockGuard(f))
    }
    fn replay(&self)->Result<State,String>{
        let dir=self.root.join(JOURNAL);
        real_dir(&dir)?;
        let mut records=Vec::new();
        for item in fs::read_dir(&dir).map_err(|e|e.to_string())?{
            let item=item.map_err(|e|e.to_string())?;
            regular(&item.path())?;
            records.push((item.file_name().into_string().map_err(|_|"nonUTF8 coordinator file")?,item.path()));
        }
        records.sort_by(|a,b|a.0.cmp(&b.0));
        let mut state=State::blank();
        for (i,(name,path)) in records.into_iter().enumerate(){
            let n=u64::try_from(i).map_err(|_|"journal too long")?
                .checked_add(1).ok_or("journal too long")?;
            if name!=format!("{n:020}.json"){
                return Err("unexpected coordinator file or missing entry".into())
            }
            let bytes=read(&path)?;
            let entry:FencingEntry=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
            state.apply(&entry,&bytes,&self.scope)?;
        }
        Ok(state)
    }
    fn append(&self,state:&mut State,action:FencingAction)->Result<(),String>{
        let entry=FencingEntry{
            format:FORMAT.into(),
            sequence:state.count.checked_add(1).ok_or("coordinator sequence overflow")?,
            previous_sha256:state.tip.clone(),action,
        };
        let bytes=serialize(&entry)?;
        state.apply(&entry,&bytes,&self.scope)?;
        write_once(&self.root.join(JOURNAL).join(format!("{:020}.json",entry.sequence)),&bytes)?;
        sync_dir(&self.root.join(JOURNAL))
    }
    /// Explicit controlled failover via CAS. NO wall-clock lease expiry or
    /// automatic takeover: outside governance must authorize the next epoch.
    pub fn advance_epoch(&self,expected_epoch:u64,host_id:&str)->Result<EpochGrant,String>{
        if !valid_id(host_id){return Err("invalid fencing holder".into())}
        let _lock=self.lock()?;
        let mut state=self.replay()?;
        if state.epoch!=expected_epoch{
            return Err("epoch CAS failed; another owner already advanced".into())
        }
        let epoch=expected_epoch.checked_add(1).ok_or("epoch overflow")?;
        let grant=EpochGrant{host_id:host_id.into(),epoch};
        self.append(&mut state,FencingAction::AcquireEpoch{grant:grant.clone()})?;
        Ok(grant)
    }
    pub fn checkpoint(&self)->Result<FencingCheckpoint,String>{
        let _lock=self.lock()?;
        let snap=self.replay()?.checkpoint();
        snap.validate()?;
        Ok(snap)
    }
    /// Read-only comparison against an independently protected high-water
    /// prefix. Only protects rollback if that high-water pin survives outside.
    pub fn verify_floor(&self,floor:&FencingCheckpoint)->Result<FencingCheckpoint,String>{
        floor.validate()?;
        let _lock=self.lock()?;
        let s=self.replay()?;
        if floor.record_count>s.count{return Err("coordinator below external high-water".into())}
        let local=if floor.record_count==0{
            FencingCheckpoint{record_count:0,journal_tip_sha256:None,
                active_grant:None,nonce_claim_count:0}
        }else{
            s.prefix.get(usize::try_from(floor.record_count-1).map_err(|_|"count overflow")?)
                .ok_or("missing coordinator historical prefix")?.clone()
        };
        if &local!=floor{return Err("coordinator diverges from independent high-water".into())}
        Ok(s.checkpoint())
    }
}
impl DurableFencingCoordinator{
    /// Read back the exact durable signed-response JSON from the SAME
    /// coordinator journal which atomically claimed its nonce.
    pub fn committed_response(&self,nonce_sha256:&str)->Result<Option<String>,String>{
        if !valid_hash(nonce_sha256){return Err("invalid queried nonce".into())}
        let _guard=self.lock()?;
        Ok(self.replay()?.committed.get(nonce_sha256).cloned())
    }
    /// Read-only recovery strictly limited to the HOST that committed the
    /// signed response. Both unknown and foreign-host nonce return None to
    /// avoid revealing another peer's journal entries across the RPC.
    /// Original commit lineage and Ed25519 signatures are replay-verified.
    /// Does NOT modify nonce, epoch, active owner, or any canonical state.
    pub fn committed_response_for_host(
        &self,nonce_sha256:&str,authenticated_host_id:&str
    )->Result<Option<String>,String>{
        if !valid_hash(nonce_sha256)||!valid_id(authenticated_host_id){
            return Err("invalid read-only receipt recovery parameters".into())
        }
        let _guard=self.lock()?;
        let state=self.replay()?;
        if state.committed_host.get(nonce_sha256).map(String::as_str)
            !=Some(authenticated_host_id){
            return Ok(None)
        }
        Ok(state.committed.get(nonce_sha256).cloned())
    }
}
impl FencingAuthority for DurableFencingCoordinator{
    fn scope(&self)->Result<FencingScope,String>{Ok(self.scope.clone())}
    fn claim(&self,grant:&EpochGrant,nonce_sha256:&str)->Result<FencingCheckpoint,String>{
        if !valid_hash(nonce_sha256){return Err("invalid nonce SHA-256".into())}
        let _lock=self.lock()?;
        let mut state=self.replay()?;
        if state.active.as_ref()!=Some(grant){
            return Err("stale host/epoch fencing token".into())
        }
        if state.nonces.contains(nonce_sha256){return Err("global scratch nonce already claimed".into())}
        self.append(&mut state,FencingAction::ConsumeNonce{
            grant:grant.clone(),nonce_sha256:nonce_sha256.into(),
        })?;
        Ok(state.checkpoint())
    }
    fn commit_response(&self,grant:&EpochGrant,nonce_sha256:&str,
        response_json:&str)->Result<FencedCommitReceipt,String>{
        if !valid_hash(nonce_sha256)||response_json.is_empty()||
            response_json.len()>1024*1024 {
            return Err("invalid bounded commit-point nonce/content".into())
        }
        let response_sha256=sha256(response_json.as_bytes());
        let _guard=self.lock()?;
        let mut state=self.replay()?;
        if state.active.as_ref()!=Some(grant)||
            state.nonces.contains(nonce_sha256){
            return Err("stale/duplicate fencing token rejected AT durable commit point".into())
        }
        self.append(&mut state,FencingAction::CommitResponse{
            grant:grant.clone(),nonce_sha256:nonce_sha256.into(),
            response_sha256:response_sha256.clone(),response_json:response_json.into(),
        })?;
        Ok(FencedCommitReceipt{
            status:"SINGLE_FILESYSTEM_EPOCH_FENCED_SCRATCH_COMMIT_ONLY".into(),
            grant:grant.clone(),nonce_sha256:nonce_sha256.into(),
            response_sha256,checkpoint:state.checkpoint(),
            durable_scratch_record_committed:true,cross_host_consensus_verified:false,
            human_authority_verified:false,canonical_writeback:false,authority_transfer:false,
        })
    }

}
