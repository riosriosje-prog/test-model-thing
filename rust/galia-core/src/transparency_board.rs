//! GALIA v0.14: opt-in, LOCAL NONCANONICAL signed-publication evidence board.
//! Replay-verified immutable journal, offline exchange, and fail-closed split-view
//! quarantine. Neither observer independence nor human promotion authority is proven.
//! This is NOT a remote transparency service, external witness, or consensus engine.
use std::fs::{self,File,OpenOptions};
use std::io::Write;
use std::path::{Path,PathBuf};
use fs2::FileExt;
use serde::{Deserialize,Serialize};
use crate::audit::sha256;
use crate::transparency::{
    ObserverPolicy,PublishedWitnessView,ComparisonKind,
    verify_publication,compare_publications,verify_publication_extension,
};
use crate::witness_continuity::WitnessContinuityRequest;

const MARKER:&str=".GALIA_NONCANONICAL_TRANSPARENCY_BOARD_V1";
const LOCK:&str=".transparency.lock";
const JOURNAL:&str="publications";
const FORMAT:&str="GALIA_NONCANONICAL_TRANSPARENCY_BOARD_V1";
fn canonical<T:Serialize>(v:&T)->Result<Vec<u8>,String>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x))
        .map_err(|e|e.to_string())
}
fn dir(path:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.file_type().is_dir(){return Err("board path must be a real non-symlink directory".into())}
    Ok(())
}
fn regular(path:&Path)->Result<(),String>{
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.file_type().is_file(){return Err("board file must be regular, not symlink".into())}
    Ok(())
}
fn read(path:&Path)->Result<Vec<u8>,String>{
    regular(path)?;fs::read(path).map_err(|e|e.to_string())
}
fn sync_dir(path:&Path)->Result<(),String>{
    File::open(path).and_then(|x|x.sync_all()).map_err(|e|e.to_string())
}
fn create_new(path:&Path,raw:&[u8])->Result<(),String>{
    let mut file=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|e|e.to_string())?;
    file.write_all(raw).map_err(|e|e.to_string())?;
    file.sync_all().map_err(|e|e.to_string())
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationTransfer{
    pub view:PublishedWitnessView,
    pub extension:Option<WitnessContinuityRequest>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct BoardEntry{
    format:String,
    index:u64,
    previous_entry_sha256:Option<String>,
    transfer:PublicationTransfer,
}
#[derive(Clone,Debug,Serialize)]
pub struct SplitViewEvidence{
    pub format:&'static str,
    pub count:u64,
    pub left:PublishedWitnessView,
    pub right:PublishedWitnessView,
    pub left_observation_sha256:String,
    pub right_observation_sha256:String,
    pub canonical_writeback:bool,
    pub human_authority_verified:bool,
    pub authority_transfer:bool,
}
#[derive(Clone,Debug,Serialize)]
pub struct BoardReport{
    pub status:&'static str,
    pub journal_count:u64,
    pub journal_tip_sha256:Option<String>,
    pub highest_published_count:u64,
    pub quarantined:bool,
    pub evidence_observations:Option<(String,String)>,
    pub human_authority_verified:bool,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardCheckpoint{
    pub journal_count:u64,
    pub journal_tip_sha256:Option<String>,
    pub quarantined:bool,
}
struct State{
    journal:Vec<BoardEntry>,
    tip:Option<String>,
    head:Option<usize>,
    conflict:Option<SplitViewEvidence>,
}
impl State{
    fn blank()->Self{
        Self{journal:Vec::new(),tip:None,head:None,conflict:None}
    }
    fn count(&self)->Result<u64,String>{
        u64::try_from(self.journal.len()).map_err(|_|"board journal count overflow".into())
    }
    fn report(&self,status:&'static str)->Result<BoardReport,String>{
        let max=self.head
            .map(|i|self.journal[i].transfer.view.signed_observation.observation.spent_count)
            .unwrap_or(0);
        Ok(BoardReport{
            status,journal_count:self.count()?,journal_tip_sha256:self.tip.clone(),
            highest_published_count:max,quarantined:self.conflict.is_some(),
            evidence_observations:self.conflict.as_ref().map(|x|
                (x.left_observation_sha256.clone(),x.right_observation_sha256.clone())),
            human_authority_verified:false,canonical_writeback:false,authority_transfer:false,
        })
    }
    fn transition(&mut self,transfer:&PublicationTransfer,policy:&ObserverPolicy)
        ->Result<&'static str,String>{
        if self.conflict.is_some(){
            return Err("signed split view quarantined: no further writes".into())
        }
        let published=verify_publication(&transfer.view,policy)?;
        if self.journal.is_empty(){
            if transfer.extension.is_some()||
                published.count!=policy.witness_anchor.minimum_spent_count||
                published.tip_sha256!=policy.witness_anchor.floor_tip_sha256{
                return Err("first board publication must equal independently pinned root checkpoint".into())
            }
            return Ok("PUBLICATION_ACCEPTED_SCRATCH_ONLY")
        }
        // Any previously published count can reveal a split view, even
        // if the latest head has advanced beyond that height.
        for entry in &self.journal{
            let old=&entry.transfer.view;
            if old.signed_observation.observation.spent_count==published.count{
                let comparison=compare_publications(old,&transfer.view,policy)?;
                match comparison.kind {
                    ComparisonKind::ConflictingSignedState=>{
                        if transfer.extension.is_some(){
                            return Err("conflicting signed view cannot smuggle an extension".into())
                        }
                        self.conflict=Some(SplitViewEvidence{
                            format:FORMAT,count:published.count,
                            left:old.clone(),right:transfer.view.clone(),
                            left_observation_sha256:comparison.left_observation_sha256,
                            right_observation_sha256:comparison.right_observation_sha256,
                            canonical_writeback:false,human_authority_verified:false,
                            authority_transfer:false,
                        });
                        return Ok("SPLIT_VIEW_EVIDENCE_QUARANTINED");
                    }
                    ComparisonKind::SameSignedState=>{
                        return Ok("ALREADY_PUBLISHED_NO_WRITE")
                    }
                    _=>return Err("invalid same-height comparison".into())
                }
            }
        }
        let head=self.head.ok_or("board missing last confirmed publication")?;
        let last=&self.journal[head].transfer.view;
        if published.count<=last.signed_observation.observation.spent_count{
            return Err("out-of-order publication without earlier matching height".into())
        }
        let proof=transfer.extension.as_ref().ok_or("forward publication requires complete signed witness extension")?;
        let comparison=verify_publication_extension(last,&transfer.view,policy,policy,proof)?;
        if comparison.kind!=ComparisonKind::VerifiedSignedExtension{
            return Err("forward witness extension remains unproven".into())
        }
        Ok("PUBLICATION_ACCEPTED_SCRATCH_ONLY")
    }
    fn apply(&mut self,entry:BoardEntry,policy:&ObserverPolicy)->Result<(),String>{
        if entry.format!=FORMAT||
            entry.index!=self.count()?.checked_add(1).ok_or("board count overflow")?||
            entry.previous_entry_sha256!=self.tip{
            return Err("board index/hash-chain mismatch".into())
        }
        // transition is pure w.r.t. published data, except setting conflict.
        let status=self.transition(&entry.transfer,policy)?;
        if status=="ALREADY_PUBLISHED_NO_WRITE"{
            return Err("duplicate publication journal entry".into())
        }
        if status=="PUBLICATION_ACCEPTED_SCRATCH_ONLY"{
            self.head=Some(self.journal.len())
        }
        let raw=canonical(&entry)?;
        self.tip=Some(sha256(&raw));
        self.journal.push(entry);
        Ok(())
    }
}
struct Guard(File);
impl Drop for Guard{fn drop(&mut self){let _=FileExt::unlock(&self.0);}}
#[derive(Clone,Debug)]
pub struct DurableTransparencyBoard{
    root:PathBuf,
    policy:ObserverPolicy,
}
impl DurableTransparencyBoard{
    /// Callers must pin the entire policy independently of the scratch files.
    /// Rejects any preexisting path; does not create or modify canonical data.
    pub fn initialize_new(root:impl AsRef<Path>,policy:ObserverPolicy)->Result<Self,String>{
        policy.validate()?;
        let root=root.as_ref();
        if fs::symlink_metadata(root).is_ok(){return Err("scratch board already exists".into())}
        fs::create_dir(root).map_err(|e|e.to_string())?;
        #[cfg(unix)]{
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root,fs::Permissions::from_mode(0o700))
                .map_err(|e|e.to_string())?;
        }
        create_new(&root.join(MARKER),&canonical(&policy)?)?;
        fs::create_dir(root.join(JOURNAL)).map_err(|e|e.to_string())?;
        create_new(&root.join(LOCK),b"")?;
        sync_dir(root)?;
        Self::open(root,policy)
    }
    pub fn open(root:impl AsRef<Path>,policy:ObserverPolicy)->Result<Self,String>{
        policy.validate()?;
        let path=root.as_ref();
        dir(path)?;dir(&path.join(JOURNAL))?;
        regular(&path.join(LOCK))?;
        if read(&path.join(MARKER))?!=canonical(&policy)?{
            return Err("scratch board's policy differs from independently supplied policy".into())
        }
        let root=fs::canonicalize(path).map_err(|e|e.to_string())?;
        let board=Self{root,policy};
        let _guard=board.lock()?;
        let _=board.replay()?;
        Ok(board)
    }
    fn lock(&self)->Result<Guard,String>{
        regular(&self.root.join(LOCK))?;
        let f=OpenOptions::new().read(true).write(true).open(self.root.join(LOCK))
            .map_err(|e|e.to_string())?;
        FileExt::lock_exclusive(&f).map_err(|e|e.to_string())?;
        if read(&self.root.join(MARKER))?!=canonical(&self.policy)?{
            return Err("board policy tampered after opening".into())
        }
        Ok(Guard(f))
    }
    fn replay(&self)->Result<State,String>{
        let path=self.root.join(JOURNAL);
        dir(&path)?;
        let mut names=Vec::new();
        for item in fs::read_dir(&path).map_err(|e|e.to_string())?{
            let item=item.map_err(|e|e.to_string())?;
            regular(&item.path())?;
            let name=item.file_name().into_string().map_err(|_|"nonUTF8 board entry")?;
            names.push((name,item.path()));
        }
        names.sort_by(|a,b|a.0.cmp(&b.0));
        let mut state=State::blank();
        for (i,(name,path)) in names.into_iter().enumerate(){
            let index=u64::try_from(i).map_err(|_|"entry index overflow")?
                .checked_add(1).ok_or("entry overflow")?;
            if name!=format!("{index:020}.json"){
                return Err("board journal gap, inserted file or undeclared filename".into())
            }
            let raw=read(&path)?;
            let parsed:BoardEntry=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
            if canonical(&parsed)?!=raw{return Err("noncanonical board entry".into())}
            state.apply(parsed,&self.policy)?;
        }
        Ok(state)
    }
    /// Retain a verifiable signed publication; on conflicting same-height
    /// observations, commit both evidence views and quarantine without rollback.
    pub fn publish(&self,view:PublishedWitnessView,
        extension:Option<WitnessContinuityRequest>)->Result<BoardReport,String>{
        let _guard=self.lock()?;
        let mut state=self.replay()?;
        let transfer=PublicationTransfer{view,extension};
        let disposition=state.transition(&transfer,&self.policy)?;
        if disposition=="ALREADY_PUBLISHED_NO_WRITE"{
            return state.report(disposition)
        }
        // Determine the exact journal entry expected before mutation.
        // Do not use mutated state from transition() for the durable result.
        let mut prior=self.replay()?;
        let entry=BoardEntry{
            format:FORMAT.into(),
            index:prior.count()?.checked_add(1).ok_or("entry count overflow")?,
            previous_entry_sha256:prior.tip.clone(),
            transfer,
        };
        prior.apply(entry.clone(),&self.policy)?;
        let raw=canonical(&entry)?;
        create_new(&self.root.join(JOURNAL).join(format!("{:020}.json",entry.index)),&raw)?;
        sync_dir(&self.root.join(JOURNAL))?;
        prior.report(disposition)
    }
    /// Offline exchange: exported envelopes are verified again by the peer
    /// board's separately pinned policy before local append.
    pub fn export(&self)->Result<Vec<PublicationTransfer>,String>{
        let _guard=self.lock()?;
        let state=self.replay()?;
        Ok(state.journal.into_iter().map(|e|e.transfer).collect())
    }
    pub fn checkpoint(&self)->Result<BoardCheckpoint,String>{
        let _guard=self.lock()?;
        let state=self.replay()?;
        Ok(BoardCheckpoint{
            journal_count:state.count()?,
            journal_tip_sha256:state.tip,
            quarantined:state.conflict.is_some(),
        })
    }
    /// Compare exact bytes/count against an independently retained checkpoint.
    /// A checkpoint supplied from the mutable scratch directory has no authority.
    pub fn verify_checkpoint(&self,pinned:&BoardCheckpoint)->Result<(),String>{
        let now=self.checkpoint()?;
        if now.journal_count!=pinned.journal_count||
            now.journal_tip_sha256!=pinned.journal_tip_sha256||
            now.quarantined!=pinned.quarantined{
            return Err("external board checkpoint mismatch / possible truncation".into())
        }
        Ok(())
    }
    pub fn evidence(&self)->Result<Option<SplitViewEvidence>,String>{
        let _guard=self.lock()?;
        Ok(self.replay()?.conflict)
    }
    pub fn inspect(&self)->Result<BoardReport,String>{
        let _guard=self.lock()?;
        self.replay()?.report("BOARD_REPLAY_VERIFIED_NONCANONICAL_ONLY")
    }
}
