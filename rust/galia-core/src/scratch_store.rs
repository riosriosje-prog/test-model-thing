//! Opt-in, noncanonical scratch-only generation store.
//! WARNING: this is NOT production P7. No authenticated human approval,
//! external witness, multi-host fencing, canonical authority, or rollback adjudication.
//! Every mutation requires a specially initialized scratch root.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use fs2::FileExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use crate::persistence::{GenerationBytes, GenerationManifest, HeadPointer, VerificationRequest, verify_request};
use crate::audit::{AuditReceipt,AuditOperation,Checkpoint,sha256,next_receipt,verify_receipts};

const MARKER: &str = ".GALIA_NONCANONICAL_SCRATCH_V1";
const MARKER_BYTES: &[u8] = b"GALIA_NONCANONICAL_SCRATCH_ONLY_V1\n";
const LOCK_NAME: &str = ".scratch.lock";

fn digest(data: &[u8]) -> String { format!("{:x}", Sha256::digest(data)) }
fn fail(message: &str) -> String { message.into() }
fn io_err(context: &str, e: std::io::Error) -> String { format!("{context}: {e}") }
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let val = serde_json::to_value(value).map_err(|e| e.to_string())?;
    serde_json::to_vec(&val).map_err(|e| e.to_string())
}
fn sync_dir(dir: &Path) -> Result<(), String> {
    File::open(dir).map_err(|e| io_err("open directory",e))?
        .sync_all().map_err(|e| io_err("fsync directory",e))
}
fn require_real_dir(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e|io_err("inspect directory",e))?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(fail("scratch directory must not be symlink"));
    }
    Ok(())
}
fn require_real_file(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e|io_err("inspect file",e))?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err(fail("scratch file must be a regular non-symlink file"));
    }
    Ok(())
}
fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    require_real_file(path)?;
    fs::read(path).map_err(|e|io_err("read file",e))
}
fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new().write(true).create_new(true)
        .open(path).map_err(|e|io_err("create immutable file",e))?;
    file.write_all(data).map_err(|e|io_err("write file",e))?;
    file.sync_all().map_err(|e|io_err("fsync file",e))
}
fn validate_commit_component(commit: &str) -> Result<(), String> {
    if commit.is_empty() || commit=="." || commit==".." || commit.chars().any(|c| {
        matches!(c,'/'|'\\'|':'|'\0')
    }) {
        return Err(fail("unsafe generation identifier"));
    }
    Ok(())
}
fn all_files(root: &Path, dir: &Path, out: &mut BTreeSet<String>) -> Result<(), String> {
    require_real_dir(dir)?;
    for ent in fs::read_dir(dir).map_err(|e|io_err("read scratch tree",e))? {
        let ent=ent.map_err(|e|io_err("read entry",e))?;
        let path=ent.path();
        let meta=fs::symlink_metadata(&path).map_err(|e|io_err("stat entry",e))?;
        if meta.file_type().is_symlink() { return Err(fail("scratch snapshot symlink rejected")); }
        if meta.is_dir() { all_files(root,&path,out)?; }
        else if meta.is_file() {
            let rel=path.strip_prefix(root).map_err(|_|fail("scratch path escaped root"))?
                .to_str().ok_or("non-UTF8 scratch filename")?.replace('\\',"/");
            out.insert(rel);
        } else { return Err(fail("unsupported scratch filesystem node")); }
    }
    Ok(())
}
fn bundle_from_dir(dir: &Path) -> Result<GenerationBytes, String> {
    require_real_dir(dir)?;
    let m=read_file(&dir.join("manifest.json"))?;
    let p=read_file(&dir.join("promotion.json"))?;
    let manifest: GenerationManifest=serde_json::from_slice(&m)
        .map_err(|e|format!("invalid manifest: {e}"))?;
    validate_commit_component(&manifest.commit_id)?;
    let mut declared=BTreeSet::from(["manifest.json".to_string(),"promotion.json".to_string()]);
    let mut payloads_hex=BTreeMap::new();
    for entry in &manifest.payloads {
        if entry.path.split('/').any(|x|x=="."||x==".."||x.is_empty()) ||
            entry.path.starts_with('/') || entry.path.contains('\\') {
            return Err(fail("unsafe payload path"));
        }
        let rel=format!("payload/{}",entry.path);
        let pth=dir.join(&rel);
        let raw=read_file(&pth)?;
        payloads_hex.insert(entry.path.clone(),hex::encode(raw));
        declared.insert(rel);
    }
    let mut actual=BTreeSet::new();
    all_files(dir,dir,&mut actual)?;
    if actual!=declared {return Err(fail("undeclared/missing scratch files"));}
    let head=HeadPointer {
        commit_id:manifest.commit_id, seq:manifest.seq,
        manifest_hash:digest(&m), promotion_hash:digest(&p),
    };
    let mut head_bytes=canonical(&head)?;
    head_bytes.push(b'\n');
    let snap=GenerationBytes {
        manifest_hex:hex::encode(m),promotion_hex:hex::encode(p),
        head_hex:hex::encode(head_bytes),payloads_hex,
    };
    verify_request(&VerificationRequest{generation:snap.clone(),parent:None})?;
    Ok(snap)
}
fn checked_head(root: &Path) -> Result<Option<(HeadPointer,Vec<u8>,GenerationBytes)>,String> {
    let head_path=root.join("HEAD");
    if !head_path.exists() {
        if fs::symlink_metadata(&head_path).is_ok() {
            return Err(fail("invalid HEAD node"));
        }
        return Ok(None);
    }
    let raw=read_file(&head_path)?;
    let head:HeadPointer=serde_json::from_slice(&raw).map_err(|e|format!("invalid HEAD: {e}"))?;
    validate_commit_component(&head.commit_id)?;
    let snapshot=bundle_from_dir(&root.join("generations").join(&head.commit_id))?;
    if raw != hex::decode(&snapshot.head_hex).map_err(|e|e.to_string())? {
        return Err(fail("HEAD does not match durable referenced generation"));
    }
    Ok(Some((head,raw,snapshot)))
}
struct Locked(File);
impl Drop for Locked {
    fn drop(&mut self) { let _=FileExt::unlock(&self.0); }
}

#[derive(Clone, Debug)]
pub struct ScratchStore { root:PathBuf }

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecoveryReport {
    pub head:Option<String>,
    pub reachable:Vec<String>,
    pub staged:Vec<String>,
    pub orphaned:Vec<String>,
    pub corrupt_orphans:Vec<String>,
    pub canonical_writeback:bool,
    pub authority_transfer:bool,
}

impl ScratchStore {
    /// Initializes ONLY a new, non-existing root. Refuses any existing directory.
    pub fn initialize_new(root: impl AsRef<Path>) -> Result<Self,String> {
        let root=root.as_ref();
        if root.exists() || fs::symlink_metadata(root).is_ok() {
            return Err(fail("scratch root must not exist before initialization"));
        }
        fs::create_dir(root).map_err(|e|io_err("create scratch root",e))?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root,fs::Permissions::from_mode(0o700))
                .map_err(|e|io_err("set scratch permissions",e))?;
        }
        write_new(&root.join(MARKER),MARKER_BYTES)?;
        fs::create_dir(root.join("staging")).map_err(|e|io_err("mkdir staging",e))?;
        fs::create_dir(root.join("generations")).map_err(|e|io_err("mkdir generations",e))?;
        fs::create_dir(root.join("audit")).map_err(|e|io_err("mkdir audit",e))?;
        write_new(&root.join(LOCK_NAME),b"")?;
        sync_dir(root)?;
        Self::open(root)
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self,String> {
        let root=root.as_ref();
        require_real_dir(root)?;
        let marker=read_file(&root.join(MARKER))?;
        if marker!=MARKER_BYTES {return Err(fail("invalid scratch-only marker"));}
        require_real_dir(&root.join("staging"))?;
        require_real_dir(&root.join("generations"))?;
        require_real_dir(&root.join("audit"))?;
        require_real_file(&root.join(LOCK_NAME))?;
        let canonical=fs::canonicalize(root).map_err(|e|io_err("canonical scratch root",e))?;
        Ok(Self {root:canonical})
    }
    fn locked(&self) -> Result<Locked,String> {
        // No new lock file may be synthesized in an existing store.
        self.validate_marker()?;
        let p=self.root.join(LOCK_NAME);
        require_real_file(&p)?;
        let lock=OpenOptions::new().read(true).write(true).open(p)
            .map_err(|e|io_err("open lock",e))?;
        FileExt::lock_exclusive(&lock).map_err(|e|io_err("lock scratch store",e))?;
        Ok(Locked(lock))
    }
    fn validate_marker(&self) -> Result<(),String> {
        if read_file(&self.root.join(MARKER))? != MARKER_BYTES {
            return Err(fail("scratch marker mismatch"));
        }
        Ok(())
    }

    fn read_audit_checked(&self,expected_head:Option<&str>)->Result<Vec<AuditReceipt>,String>{
        require_real_dir(&self.root.join("audit"))?;
        let mut files=Vec::new();
        for entry in fs::read_dir(self.root.join("audit"))
            .map_err(|e|io_err("scan audit",e))? {
            let entry=entry.map_err(|e|io_err("audit entry",e))?;
            require_real_file(&entry.path())?;
            let name=entry.file_name().into_string().map_err(|_|fail("non-UTF8 audit filename"))?;
            files.push((name,entry.path()));
        }
        files.sort_by(|a,b|a.0.cmp(&b.0));
        let mut receipts=Vec::new();
        for (i,(name,path)) in files.into_iter().enumerate(){
            let expected=format!("{:020}.json",i+1);
            if name!=expected {return Err(fail("audit receipt gap or undeclared filename"));}
            let raw=read_file(&path)?;
            let receipt:AuditReceipt=serde_json::from_slice(&raw)
                .map_err(|e|format!("invalid audit JSON: {e}"))?;
            if receipt.canonical_bytes()?!=raw {
                return Err(fail("noncanonical audit receipt bytes"));
            }
            receipts.push(receipt);
        }
        let report=verify_receipts(&receipts,None)?;
        if report.head_sha256.as_deref()!=expected_head{
            return Err(fail("scratch HEAD and audit chain disagree"));
        }
        Ok(receipts)
    }
    fn append_audit_locked(&self,receipt:AuditReceipt)->Result<(),String>{
        let path=self.root.join("audit").join(format!("{:020}.json",receipt.index));
        write_new(&path,&receipt.canonical_bytes()?)?;
        sync_dir(&self.root.join("audit"))?;
        Ok(())
    }
    /// A checkpoint is only trusted when independently retained OUTSIDE this
    /// mutable scratch tree. It is NOT a signature or an authority approval.
    pub fn audit_checkpoint(&self)->Result<Option<Checkpoint>,String>{
        let _lock=self.locked()?;
        let current=checked_head(&self.root)?.map(|(_,raw,_)|sha256(&raw));
        let records=self.read_audit_checked(current.as_deref())?;
        let report=verify_receipts(&records,None)?;
        Ok(report.tip_sha256.map(|tip|Checkpoint{
            count:report.count,tip_sha256:tip,
            last_head_sha256:report.head_sha256
        }))
    }
    /// Compare against caller-supplied out-of-band checkpoint; cannot establish
    /// whether that checkpoint itself is authentic or current.
    pub fn verify_audit_checkpoint(&self,checkpoint:&Checkpoint)->Result<(),String>{
        let _lock=self.locked()?;
        let current=checked_head(&self.root)?.map(|(_,raw,_)|sha256(&raw));
        let records=self.read_audit_checked(current.as_deref())?;
        verify_receipts(&records,Some(checkpoint))?;
        Ok(())
    }

    fn stage_inner(&self, snap:&GenerationBytes) -> Result<String,String> {
        let report=verify_request(&VerificationRequest{
            generation:snap.clone(),parent:None
        })?;
        validate_commit_component(&report.commit_id)?;
        let commit=report.commit_id;
        if self.root.join("staging").join(&commit).exists()
            || self.root.join("generations").join(&commit).exists() {
            return Err(fail("immutable generation already exists"));
        }
        let temporary=tempfile::Builder::new().prefix(".incomplete-")
            .tempdir_in(self.root.join("staging")).map_err(|e|io_err("create temp stage",e))?;
        let manifest=hex::decode(&snap.manifest_hex).map_err(|e|e.to_string())?;
        let promotion=hex::decode(&snap.promotion_hex).map_err(|e|e.to_string())?;
        let obj:GenerationManifest=serde_json::from_slice(&manifest).map_err(|e|e.to_string())?;
        fs::create_dir(temporary.path().join("payload"))
            .map_err(|e|io_err("create payload directory",e))?;
        for entry in &obj.payloads {
            let target=temporary.path().join("payload").join(&entry.path);
            let parent=target.parent().ok_or("invalid payload parent")?;
            fs::create_dir_all(parent).map_err(|e|io_err("create payload parent",e))?;
            let data=hex::decode(&snap.payloads_hex[&entry.path]).map_err(|e|e.to_string())?;
            write_new(&target,&data)?;
            sync_dir(parent)?;
        }
        write_new(&temporary.path().join("manifest.json"),&manifest)?;
        write_new(&temporary.path().join("promotion.json"),&promotion)?;
        sync_dir(&temporary.path().join("payload"))?;
        sync_dir(temporary.path())?;
        fs::rename(temporary.path(),self.root.join("staging").join(&commit))
            .map_err(|e|io_err("materialize immutable staging directory",e))?;
        sync_dir(&self.root.join("staging"))?;
        Ok(commit)
    }
    /// Stages self-consistent supplied test fixture bytes; never advances HEAD.
    pub fn stage_snapshot(&self,snap:&GenerationBytes)->Result<String,String>{
        let _lock=self.locked()?;
        let old=checked_head(&self.root)?.map(|(_,raw,_)|sha256(&raw));
        let records=self.read_audit_checked(old.as_deref())?;
        let commit=self.stage_inner(snap)?;
        let manifest_bytes=hex::decode(&snap.manifest_hex).map_err(|e|e.to_string())?;
        let receipt=next_receipt(&records,AuditOperation::Staged,&commit,
            &sha256(&manifest_bytes),old.clone(),old)?;
        self.append_audit_locked(receipt)?;
        Ok(commit)
    }
    fn publish_inner(&self,commit:&str,expected_head_hash:Option<&str>,failpoint:bool)
        -> Result<String,String> {
        validate_commit_component(commit)?;
        let _lock=self.locked()?;
        let prior=checked_head(&self.root)?;
        let old_raw=prior.as_ref().map(|(_,raw,_)|digest(raw));
        let records=self.read_audit_checked(old_raw.as_deref())?;
        if old_raw.as_deref()!=expected_head_hash {
            return Err(fail("scratch HEAD compare-and-swap precondition failed"));
        }
        let staged=self.root.join("staging").join(commit);
        let dst=self.root.join("generations").join(commit);
        if dst.exists() {return Err(fail("immutable generation exists"));}
        let snap=bundle_from_dir(&staged)?;
        let child=verify_request(&VerificationRequest{generation:snap.clone(),parent:None})?;
        if child.commit_id!=commit {return Err(fail("staged commit path mismatch"));}
        let child_manifest_hash=child.manifest_hash.clone();
        let child_manifest:GenerationManifest=
            serde_json::from_slice(&hex::decode(&snap.manifest_hex).map_err(|e|e.to_string())?)
            .map_err(|e|e.to_string())?;
        if let Some((head,_,parent_snap))=&prior {
            // Verify real parent with the anchored HEAD and require consecutive sequence.
            verify_request(&VerificationRequest{
                generation:snap.clone(),parent:Some(parent_snap.clone())
            })?;
            if child_manifest.parent_commit!=head.commit_id ||
                child_manifest.seq!=head.seq.checked_add(1).ok_or("sequence overflow")? {
                return Err(fail("parent/sequence mismatch"));
            }
        } else if child_manifest.seq!=1 || child_manifest.parent_commit!="GENESIS" {
            return Err(fail("first scratch generation must have seq=1 parent=GENESIS"));
        }
        fs::rename(&staged,&dst).map_err(|e|io_err("materialize generation",e))?;
        sync_dir(&self.root.join("generations"))?;
        if failpoint {
            return Err(fail("INJECTED_FAILURE_AFTER_MATERIALIZATION_BEFORE_HEAD"));
        }
        let raw=hex::decode(&snap.head_hex).map_err(|e|e.to_string())?;
        let mut temp=tempfile::NamedTempFile::new_in(&self.root)
            .map_err(|e|io_err("create HEAD temporary",e))?;
        temp.write_all(&raw).map_err(|e|io_err("write HEAD temporary",e))?;
        temp.as_file().sync_all().map_err(|e|io_err("fsync HEAD temporary",e))?;
        temp.persist(self.root.join("HEAD"))
            .map_err(|e|format!("atomic scratch HEAD rename: {}",e.error))?;
        sync_dir(&self.root)?;
        let next=next_receipt(&records,AuditOperation::Published,commit,&child_manifest_hash,
            old_raw,Some(sha256(&raw)))?;
        self.append_audit_locked(next)?;
        Ok(digest(&raw))
    }
    /// Advisory scratch HEAD advance. Requires exact expected hash of prior HEAD bytes.
    /// No authenticated promotion; must never be wired to GALIA canonical authority.
    pub fn publish_staged(&self,commit:&str,expected_head_hash:Option<&str>)
        -> Result<String,String> {
        self.publish_inner(commit,expected_head_hash,false)
    }
    /// Returns hash of actual scratch HEAD bytes, not a canonical authority token.
    pub fn read_head_token(&self)->Result<Option<String>,String>{
        let _lock=self.locked()?;
        let old=checked_head(&self.root)?.map(|(_,raw,_)|digest(&raw));
        self.read_audit_checked(old.as_deref())?;
        Ok(old)
    }
    /// Recoverability inspection only: never rewrites HEAD, deletes or promotes orphans.
    pub fn inspect_recovery(&self)->Result<RecoveryReport,String>{
        let _lock=self.locked()?;
        let prior=checked_head(&self.root)?;
        let observed_head=prior.as_ref().map(|(_,raw,_)|sha256(raw));
        self.read_audit_checked(observed_head.as_deref())?;
        let mut reachable=BTreeSet::new();
        let mut current=prior.as_ref().map(|(h,_,_)|h.commit_id.clone());
        while let Some(commit)=current {
            if !reachable.insert(commit.clone()) {return Err(fail("cyclic scratch generation history"));}
            let snap=bundle_from_dir(&self.root.join("generations").join(&commit))?;
            let m:GenerationManifest=serde_json::from_slice(
                &hex::decode(&snap.manifest_hex).map_err(|e|e.to_string())?)
                .map_err(|e|e.to_string())?;
            if m.seq==1 {
                if m.parent_commit!="GENESIS" {return Err(fail("invalid genesis parent"));}
                current=None;
            } else {
                let parent=bundle_from_dir(&self.root.join("generations").join(&m.parent_commit))?;
                verify_request(&VerificationRequest{generation:snap,parent:Some(parent)})?;
                current=Some(m.parent_commit);
            }
        }
        let mut orphaned=vec![];
        let mut corrupt_orphans=vec![];
        for p in fs::read_dir(self.root.join("generations")).map_err(|e|io_err("scan generations",e))? {
            let path=p.map_err(|e|e.to_string())?.path();
            require_real_dir(&path)?;
            let name=path.file_name().and_then(|s|s.to_str()).ok_or("invalid generation name")?.to_owned();
            if !reachable.contains(&name) {
                if bundle_from_dir(&path).is_ok() {orphaned.push(name);}
                else {corrupt_orphans.push(name);}
            }
        }
        let mut staged=vec![];
        for p in fs::read_dir(self.root.join("staging")).map_err(|e|io_err("scan staging",e))? {
            let path=p.map_err(|e|e.to_string())?.path();
            require_real_dir(&path)?;
            staged.push(path.file_name().and_then(|s|s.to_str())
                .ok_or("invalid staging name")?.to_owned());
        }
        orphaned.sort();corrupt_orphans.sort();staged.sort();
        Ok(RecoveryReport{
            head:prior.map(|(h,_,_)|h.commit_id),
            reachable:reachable.into_iter().collect(),
            staged,orphaned,corrupt_orphans,
            canonical_writeback:false,authority_transfer:false
        })
    }
    #[cfg(test)]
    fn inject_failure_after_materialize(&self,commit:&str,expected:Option<&str>)
        -> Result<String,String> {
        self.publish_inner(commit,expected,true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn data(commit:&str,parent:&str,seq:u64) -> GenerationBytes {
        let bytes=b"historic source\n";
        let mh_payload=digest(bytes);
        let m=json!({
            "authority_decision_id":"decision-1","case_id":"case-1",
            "commit_id":commit,"created_at":"2026-10-15T12:00:00+00:00",
            "parent_commit":parent,"payloads":[
                {"byte_size":bytes.len(),"path":"sources/a.txt","sha256":mh_payload}
            ],
            "persistence_policy_version":"p7","schema_version":"galia2-core-v1","seq":seq
        });
        let mraw=canonical(&m).unwrap();let mh=digest(&mraw);
        let p=json!({
            "authority_decision_id":"decision-1","authorization_id":"auth-1",
            "authorization_policy_version":"p5","case_id":"case-1",
            "commit_id":commit,"manifest_hash":mh,
            "persistence_policy_version":"p7","preflight_receipt_id":"r1",
            "published_at":"2026-10-15T12:00:00+00:00"
        });
        let praw=canonical(&p).unwrap();
        let h=json!({
            "commit_id":commit,"seq":seq,
            "manifest_hash":digest(&mraw),"promotion_hash":digest(&praw)
        });
        let mut hraw=canonical(&h).unwrap();hraw.push(b'\n');
        GenerationBytes{
            manifest_hex:hex::encode(mraw),promotion_hex:hex::encode(praw),
            head_hex:hex::encode(hraw),
            payloads_hex:BTreeMap::from([("sources/a.txt".into(),hex::encode(bytes))]),
        }
    }
    fn scratch() -> (tempfile::TempDir,ScratchStore) {
        let parent=tempfile::tempdir().unwrap();
        let scratch=ScratchStore::initialize_new(parent.path().join("scratch")).unwrap();
        (parent,scratch)
    }
    #[test]
    fn scratch_only_marker_and_init_are_mandatory() {
        let p=tempfile::tempdir().unwrap();
        assert!(ScratchStore::open(p.path()).is_err());
        assert!(ScratchStore::initialize_new(p.path()).is_err());
        let (d,s)=scratch();
        assert!(ScratchStore::initialize_new(d.path().join("scratch")).is_err());
        assert!(ScratchStore::open(s.root.join("generations")).is_err());
    }
    #[test]
    fn genesis_and_second_stage_are_cas_serialized() {
        let (_d,s)=scratch();
        let first=data("g1","GENESIS",1);
        assert_eq!(s.stage_snapshot(&first).unwrap(),"g1");
        assert!(s.read_head_token().unwrap().is_none());
        assert!(s.publish_staged("g1",Some("stale")).is_err());
        let token1=s.publish_staged("g1",None).unwrap();
        assert_eq!(s.read_head_token().unwrap(),Some(token1.clone()));
        assert!(s.stage_snapshot(&first).is_err());
        let second=data("g2","g1",2);
        s.stage_snapshot(&second).unwrap();
        assert!(s.publish_staged("g2",None).is_err());
        assert!(s.publish_staged("g2",Some("stale")).is_err());
        let token2=s.publish_staged("g2",Some(&token1)).unwrap();
        assert_ne!(token1,token2);
        assert_eq!(s.inspect_recovery().unwrap().reachable,["g1","g2"]);
    }
    #[test]
    fn injected_crash_preserves_old_head_and_reports_orphan() {
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let old=s.publish_staged("g1",None).unwrap();
        s.stage_snapshot(&data("g2","g1",2)).unwrap();
        let err=s.inject_failure_after_materialize("g2",Some(&old)).unwrap_err();
        assert!(err.contains("INJECTED_FAILURE"));
        assert_eq!(s.read_head_token().unwrap(),Some(old));
        let r=s.inspect_recovery().unwrap();
        assert_eq!(r.orphaned,["g2"]);
        assert_eq!(r.reachable,["g1"]);
        assert!(r.staged.is_empty());
        assert!(!r.canonical_writeback);
    }
    #[test]
    fn corrupted_parent_fails_before_head_advance() {
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let old=s.publish_staged("g1",None).unwrap();
        s.stage_snapshot(&data("g2","g1",2)).unwrap();
        fs::write(s.root.join("generations/g1/payload/sources/a.txt"),b"tamper").unwrap();
        assert!(s.publish_staged("g2",Some(&old)).is_err());
        assert!(s.read_head_token().is_err());
    }
    #[test]
    fn undeclared_staging_file_blocks_publishing() {
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        fs::write(s.root.join("staging/g1/extra.txt"),b"x").unwrap();
        assert!(s.publish_staged("g1",None).is_err());
        assert!(s.read_head_token().unwrap().is_none());
    }
    #[test]
    fn concurrency_exactly_one_winner_for_same_parent() {
        use std::sync::{Arc,Barrier};
        use std::thread;
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let old=s.publish_staged("g1",None).unwrap();
        s.stage_snapshot(&data("g2a","g1",2)).unwrap();
        s.stage_snapshot(&data("g2b","g1",2)).unwrap();
        let shared=Arc::new(s);
        let barrier=Arc::new(Barrier::new(3));
        let threads=["g2a","g2b"].into_iter().map(|commit|{
            let store=shared.clone();let barrier=barrier.clone();let token=old.clone();
            thread::spawn(move||{barrier.wait();store.publish_staged(commit,Some(&token)).is_ok()})
        }).collect::<Vec<_>>();
        barrier.wait();
        let wins=threads.into_iter().map(|j|j.join().unwrap()).filter(|won|*won).count();
        assert_eq!(wins,1,"serialized compare-and-swap must elect exactly one winner");
        assert_eq!(shared.inspect_recovery().unwrap().reachable.len(),2);
        assert_eq!(shared.inspect_recovery().unwrap().staged.len(),1);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_payload_is_rejected() {
        use std::os::unix::fs::symlink;
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let victim=s.root.join("staging/g1/payload/sources/a.txt");
        fs::remove_file(&victim).unwrap();
        symlink(s.root.join(".GALIA_NONCANONICAL_SCRATCH_V1"),&victim).unwrap();
        assert!(s.publish_staged("g1",None).is_err());
    }
    #[test]
    fn audit_checkpoint_tracks_stage_and_publish(){
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let staged_cp=s.audit_checkpoint().unwrap().unwrap();
        assert_eq!(staged_cp.count,1);
        assert!(staged_cp.last_head_sha256.is_none());
        let h=s.publish_staged("g1",None).unwrap();
        let published_cp=s.audit_checkpoint().unwrap().unwrap();
        assert_eq!(published_cp.count,2);
        assert_eq!(published_cp.last_head_sha256,Some(h));
        assert!(s.verify_audit_checkpoint(&published_cp).is_ok());
        assert!(s.verify_audit_checkpoint(&staged_cp).is_err());
    }
    #[test]
    fn audit_tampering_blocks_all_new_mutations(){
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let entry=s.root.join("audit/00000000000000000001.json");
        let mut value:serde_json::Value=serde_json::from_slice(&fs::read(&entry).unwrap()).unwrap();
        value["commit_id"]=serde_json::json!("forged");
        fs::write(&entry,serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(s.publish_staged("g1",None).is_err());
        assert!(s.stage_snapshot(&data("g2","GENESIS",1)).is_err());
        assert!(s.inspect_recovery().is_err());
    }
    #[test]
    fn audit_truncation_after_published_head_is_detected(){
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        s.publish_staged("g1",None).unwrap();
        fs::remove_file(s.root.join("audit/00000000000000000002.json")).unwrap();
        assert!(s.read_head_token().is_err());
        assert!(s.inspect_recovery().is_err());
    }
    #[test]
    fn staged_audit_truncation_needs_external_checkpoint(){
        let (_d,s)=scratch();
        s.stage_snapshot(&data("g1","GENESIS",1)).unwrap();
        let cp=s.audit_checkpoint().unwrap().unwrap();
        fs::remove_file(s.root.join("audit/00000000000000000001.json")).unwrap();
        assert!(s.audit_checkpoint().unwrap().is_none());
        assert!(s.verify_audit_checkpoint(&cp).is_err());
    }

}
