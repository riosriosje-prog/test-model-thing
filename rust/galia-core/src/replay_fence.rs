//! GALIA v0.17 LOCAL SCRATCH-ONLY transcript replay fence.
//! Duplicate valid signed transcripts were intentionally accepted in v0.16.
//! This feature-gated adapter commits a *single* immutable, fsynced record after
//! successful signature, channel-evidence and local-board verification, under
//! an exclusive cooperating-process filesystem lock.
//! No real TLS, remote service, trusted clock, HSM, distributed consensus,
//! independent rollback protection, verified human P5 authority or promotion.
use std::collections::BTreeSet;
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use serde::{Serialize,Deserialize};
use crate::audit::sha256;
use crate::external_checkpoint::policy_digest;
use crate::external_transport::{
    ExternalServiceTrust,RemoteCheckpointChallenge,RemoteCheckpointTransport,
    SignedRemoteCheckpointResponse,TransportPeerEvidence,RemoteCheckpointAssessment,
    verify_remote_exchange,
};
use crate::transparency::ObserverPolicy;
use crate::transparency_board::DurableTransparencyBoard;
use crate::replay_anchor::{ReplayAnchorTrust,SignedReplayAnchor,verify_anchored_journal};

pub const REPLAY_FORMAT:&str="GALIA_NONCANONICAL_REMOTE_REPLAY_FENCE_V1";
const MARKER:&str=".GALIA_NONCANONICAL_REMOTE_REPLAY_FENCE_V1";
const JOURNAL:&str="accepted";
const LOCK:&str=".replay.lock";
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn hash(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn folder(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err("replay directory is not a real directory".into());}
    Ok(())
}
fn file(p:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(p).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err("replay file is not a real regular file".into());}
    Ok(())
}
fn read(p:&Path)->Result<Vec<u8>,String>{
    file(p)?;fs::read(p).map_err(|e|e.to_string())
}
fn create(p:&Path,bytes:&[u8])->Result<(),String>{
    let mut f=OpenOptions::new().write(true).create_new(true).open(p)
        .map_err(|e|e.to_string())?;
    f.write_all(bytes).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}
fn sync_dir(p:&Path)->Result<(),String>{
    File::open(p).and_then(|f|f.sync_all()).map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayMarker{
    format:String,
    /// Configuration must be provisioned separately, not accepted from a peer.
    service_trust_sha256:String,
    observer_policy_sha256:String,
    service_id:String,
    namespace:String,
    case_id:String,
}
impl ReplayMarker{
    fn new(trust:&ExternalServiceTrust,policy:&ObserverPolicy)->Result<Self,String>{
        trust.validate(policy)?;
        let m=Self{
            format:REPLAY_FORMAT.into(),
            service_trust_sha256:sha256(&canonical(trust)?),
            observer_policy_sha256:policy_digest(policy)?,
            service_id:trust.service_id.clone(),
            namespace:trust.checkpoint.namespace.clone(),
            case_id:trust.checkpoint.case_id.clone(),
        };
        m.check()?;Ok(m)
    }
    fn check(&self)->Result<(),String>{
        if self.format!=REPLAY_FORMAT||
            !hash(&self.service_trust_sha256)||
            !hash(&self.observer_policy_sha256)||
            self.service_id.is_empty()||self.namespace.is_empty()||self.case_id.is_empty(){
            return Err("replay fence marker invalid".into())
        }Ok(())
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayEntry{
    format:String,
    sequence:u64,
    previous_entry_sha256:Option<String>,
    nonce_sha256:String,
    challenge_sha256:String,
    signed_response_sha256:String,
    remote_terminal_envelope_sha256:String,
    remote_terminal_sequence:u64,
    accepted_at_trusted_unix_seconds:u64,
}
impl ReplayEntry{
    fn check(&self)->Result<(),String>{
        if self.format!=REPLAY_FORMAT||self.sequence==0||
            !hash(&self.nonce_sha256)||!hash(&self.challenge_sha256)||
            !hash(&self.signed_response_sha256)||
            !hash(&self.remote_terminal_envelope_sha256)||
            self.remote_terminal_sequence==0||
            self.previous_entry_sha256.as_ref().is_some_and(|v|!hash(v)){
            return Err("invalid replay journal entry".into())
        }Ok(())
    }
}
struct ReplayHistory{
    count:u64,tip:Option<String>,nonces:BTreeSet<String>,
    responses:BTreeSet<String>,last_accepted_time:u64,prefix_tips:Vec<String>,
}
/// An unsigned local journal state, useful only when authenticated by a separate
/// out-of-band signed checkpoint and trust floor.
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayJournalCheckpoint{
    pub accepted_count:u64,
    pub journal_tip_sha256:Option<String>,
}
impl ReplayJournalCheckpoint{
    pub fn validate(&self)->Result<(),String>{
        if (self.accepted_count==0)!=self.journal_tip_sha256.is_none()||
            self.journal_tip_sha256.as_ref().is_some_and(|s|!hash(s)){
            return Err("invalid replay journal checkpoint count/tip".into())
        }
        Ok(())
    }
}
fn prefix(history:&ReplayHistory,count:u64)->Result<ReplayJournalCheckpoint,String>{
    if count>history.count{return Err("replay journal truncated below anchored count".into())}
    let tip=if count==0{None}else{
        let index=usize::try_from(count-1).map_err(|_|"checkpoint count overflow")?;
        Some(history.prefix_tips.get(index).ok_or("missing anchored prefix")?.clone())
    };
    Ok(ReplayJournalCheckpoint{accepted_count:count,journal_tip_sha256:tip})
}
fn check_prefix(history:&ReplayHistory,checkpoint:&ReplayJournalCheckpoint)->Result<(),String>{
    checkpoint.validate()?;
    if &prefix(history,checkpoint.accepted_count)?!=checkpoint{
        return Err("independent replay checkpoint disagrees with locally replayed prefix".into())
    }
    Ok(())
}
struct Guard(File);
impl Drop for Guard{
    fn drop(&mut self){let _=FileExt::unlock(&self.0);}
}
#[derive(Debug,Clone)]
pub struct DurableTranscriptReplayFence{
    root:PathBuf,marker:ReplayMarker,
}
#[derive(Debug,Serialize)]
pub struct ReplayAcceptance{
    pub assessment:RemoteCheckpointAssessment,
    pub scratch_consumed:bool,
    pub accepted_count:u64,
    pub replay_journal_tip_sha256:String,
    pub real_transport_authenticated:bool,
    pub independently_trusted_clock_verified:bool,
    pub independently_pinned_rollback_anchor_verified:bool,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
impl DurableTranscriptReplayFence{
    /// Only an explicit brand-new scratch root is accepted. This directory
    /// MUST NOT be the canonical GALIA store or a trusted external witness.
    pub fn initialize_new(root:impl AsRef<Path>,trust:&ExternalServiceTrust,
        policy:&ObserverPolicy)->Result<Self,String>{
        let marker=ReplayMarker::new(trust,policy)?;
        let p=root.as_ref();
        if fs::symlink_metadata(p).is_ok(){return Err("replay scratch root already exists".into())}
        fs::create_dir(p).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(p,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        create(&p.join(MARKER),&canonical(&marker)?)?;
        fs::create_dir(p.join(JOURNAL)).map_err(|e|e.to_string())?;
        create(&p.join(LOCK),b"")?;
        sync_dir(p)?;
        Self::open(p,trust,policy)
    }
    pub fn open(root:impl AsRef<Path>,trust:&ExternalServiceTrust,
        policy:&ObserverPolicy)->Result<Self,String>{
        let marker=ReplayMarker::new(trust,policy)?;
        let p=root.as_ref();
        folder(p)?;folder(&p.join(JOURNAL))?;file(&p.join(LOCK))?;
        if read(&p.join(MARKER))?!=canonical(&marker)?{
            return Err("replay store does not match independently supplied pins".into())
        }
        let canonical_root=fs::canonicalize(p).map_err(|e|e.to_string())?;
        let store=Self{root:canonical_root,marker};
        let _guard=store.lock()?;
        store.history()?;
        Ok(store)
    }
    fn lock(&self)->Result<Guard,String>{
        file(&self.root.join(LOCK))?;
        let f=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&f).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=canonical(&self.marker)?{
            return Err("replay root marker changed".into())
        }
        Ok(Guard(f))
    }
    fn history(&self)->Result<ReplayHistory,String>{
        let dir=self.root.join(JOURNAL);
        folder(&dir)?;
        let mut entries=Vec::new();
        for ent in fs::read_dir(&dir).map_err(|e|e.to_string())?{
            let ent=ent.map_err(|e|e.to_string())?;
            file(&ent.path())?;
            entries.push((ent.file_name().into_string().map_err(|_|"non-UTF8 replay file")?,ent.path()));
        }
        entries.sort_by(|a,b|a.0.cmp(&b.0));
        let mut tip=None;
        let mut nonces=BTreeSet::new();
        let mut responses=BTreeSet::new();
        let mut last_time=0u64;
        let mut prefix_tips=Vec::new();
        for (index,(name,p)) in entries.iter().enumerate(){
            let sequence=u64::try_from(index).map_err(|_|"replay count overflow")?
                .checked_add(1).ok_or("replay count overflow")?;
            if name!=&format!("{sequence:020}.json"){
                return Err("replay log filename gap or undeclared entry".into())
            }
            let raw=read(p)?;
            let e:ReplayEntry=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
            e.check()?;
            if raw!=canonical(&e)?||
                e.sequence!=sequence||e.previous_entry_sha256!=tip||
                e.accepted_at_trusted_unix_seconds<last_time||
                !nonces.insert(e.nonce_sha256)||
                !responses.insert(e.signed_response_sha256){
                return Err("replay journal tampering, rollback, or duplicate nonce/response".into())
            }
            last_time=e.accepted_at_trusted_unix_seconds;
            tip=Some(sha256(&raw));
            prefix_tips.push(tip.clone().ok_or("missing journal tip")?);
        }
        Ok(ReplayHistory{count:u64::try_from(entries.len()).map_err(|_|"count overflow")?,
            tip,nonces,responses,last_accepted_time:last_time,prefix_tips})
    }
    pub fn inspect(&self)->Result<(u64,Option<String>),String>{
        let _guard=self.lock()?;let h=self.history()?;Ok((h.count,h.tip))
    }
    /// Full replay and an exact prefix hash for a historical local height.
    /// This is not independently authenticated until compared with a signed
    /// checkpoint retained outside the mutable scratch filesystem.
    pub fn checkpoint_at(&self,count:u64)->Result<ReplayJournalCheckpoint,String>{
        let _guard=self.lock()?;prefix(&self.history()?,count)
    }
    pub fn checkpoint(&self)->Result<ReplayJournalCheckpoint,String>{
        let _guard=self.lock()?;let history=self.history()?;
        prefix(&history,history.count)
    }
    /// Check a separately signed external high-water checkpoint BEFORE local
    /// consume. The precise historical prefix is rechecked *under the same
    /// filesystem lock* as nonce consumption; no cooperative TOCTOU window.
    pub fn accept_anchored_verified(
        &self,board:&DurableTransparencyBoard,policy:&ObserverPolicy,
        trust:&ExternalServiceTrust,challenge:&RemoteCheckpointChallenge,
        peer:&TransportPeerEvidence,response:&SignedRemoteCheckpointResponse,
        trusted_now_unix_seconds:u64,
        anchor_trust:&ReplayAnchorTrust,anchors:&[SignedReplayAnchor],
    )->Result<ReplayAcceptance,String>{
        let anchored=verify_anchored_journal(self,trust,policy,anchor_trust,anchors)?;
        self.accept_inner(board,policy,trust,challenge,peer,response,
            trusted_now_unix_seconds,Some(&anchored.latest_checkpoint))
    }
    /// Verify everything before trying to consume. Under lock, reject nonce or
    /// signed transcript reuse across cooperating processes and process restarts.
    /// A partial write or fsync error fails closed, with manual repair only.
    pub fn accept_verified(
        &self,board:&DurableTransparencyBoard,policy:&ObserverPolicy,
        trust:&ExternalServiceTrust,challenge:&RemoteCheckpointChallenge,
        peer:&TransportPeerEvidence,response:&SignedRemoteCheckpointResponse,
        trusted_now_unix_seconds:u64,
    )->Result<ReplayAcceptance,String>{
        self.accept_inner(board,policy,trust,challenge,peer,response,
            trusted_now_unix_seconds,None)
    }
    fn accept_inner(
        &self,board:&DurableTransparencyBoard,policy:&ObserverPolicy,
        trust:&ExternalServiceTrust,challenge:&RemoteCheckpointChallenge,
        peer:&TransportPeerEvidence,response:&SignedRemoteCheckpointResponse,
        trusted_now_unix_seconds:u64,
        pinned_prefix:Option<&ReplayJournalCheckpoint>,
    )->Result<ReplayAcceptance,String>{
        let expected=ReplayMarker::new(trust,policy)?;
        if canonical(&expected)?!=canonical(&self.marker)?{
            return Err("replay acceptance policy differs from initialized trust".into())
        }
        let assessment=verify_remote_exchange(board,policy,trust,
            challenge,peer,response,trusted_now_unix_seconds)?;
        let response_hash=sha256(&canonical(response)?);
        let challenge_hash=sha256(&canonical(challenge)?);
        let _guard=self.lock()?;
        let history=self.history()?;
        if let Some(pinned)=pinned_prefix{check_prefix(&history,pinned)?;}
        if trusted_now_unix_seconds<history.last_accepted_time{
            return Err("local scratch accepted-time rollback; external trusted clock required".into())
        }
        if history.nonces.contains(&challenge.nonce_sha256)||
            history.responses.contains(&response_hash){
            return Err("signed remote transcript already consumed by local replay fence".into())
        }
        let sequence=history.count.checked_add(1).ok_or("replay counter overflow")?;
        let e=ReplayEntry{
            format:REPLAY_FORMAT.into(),sequence,
            previous_entry_sha256:history.tip,
            nonce_sha256:challenge.nonce_sha256.clone(),
            challenge_sha256:challenge_hash,
            signed_response_sha256:response_hash,
            remote_terminal_envelope_sha256:assessment.terminal_envelope_sha256.clone(),
            remote_terminal_sequence:assessment.terminal_sequence,
            accepted_at_trusted_unix_seconds:trusted_now_unix_seconds,
        };
        e.check()?;
        let raw=canonical(&e)?;
        let tip=sha256(&raw);
        create(&self.root.join(JOURNAL).join(format!("{sequence:020}.json")),&raw)?;
        sync_dir(&self.root.join(JOURNAL))?;
        Ok(ReplayAcceptance{
            assessment,scratch_consumed:true,accepted_count:sequence,
            replay_journal_tip_sha256:tip,
            real_transport_authenticated:false,
            independently_trusted_clock_verified:false,
            independently_pinned_rollback_anchor_verified:false,
            human_authority_verified:false,canonical_writeback:false,authority_transfer:false,
        })
    }
    pub fn fetch_and_accept(
        &self,board:&DurableTransparencyBoard,policy:&ObserverPolicy,
        trust:&ExternalServiceTrust,challenge:&RemoteCheckpointChallenge,
        transport:&dyn RemoteCheckpointTransport,trusted_now_unix_seconds:u64
    )->Result<ReplayAcceptance,String>{
        let (peer,response)=transport.exchange(challenge)?;
        self.accept_verified(board,policy,trust,challenge,&peer,&response,
            trusted_now_unix_seconds)
    }
}
