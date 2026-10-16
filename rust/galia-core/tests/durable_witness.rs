#![cfg(feature="scratch-store")]
//! Adversarial durable single-filesystem witness tests; not remote security claims.
use std::sync::{Arc,Barrier};
use std::thread;
use galia_core_shadow::durable_witness::DurableScratchWitness;
use galia_core_shadow::witness::{
    MonotonicWitness,WitnessConfig,WitnessConsume,FORMAT,
};
fn h(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn cfg()->WitnessConfig{
    WitnessConfig{
        namespace:"tenant".into(),case_id:"case".into(),
        pinned_root_public_key_hex:h('a'),initial_registry_epoch:7,
    }
}
fn request(id:&str,nonce:char,tip:Option<String>,epoch:u64)->WitnessConsume{
    WitnessConsume{
        format:FORMAT.into(),namespace:"tenant".into(),case_id:"case".into(),
        pinned_root_public_key_hex:h('a'),registry_epoch:epoch,
        authorization_id:id.into(),nonce_sha256:h(nonce),
        signed_decision_sha256:h('f'),expected_tip_sha256:tip,
    }
}
#[test]fn survives_close_and_reopen_and_records_receipt(){
    let dir=tempfile::tempdir().unwrap();
    let path=dir.path().join("witness");
    let first;
    {
        let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
        first=w.consume(&request("first",'1',None,7)).unwrap();
        assert_eq!(w.lookup("first").unwrap().unwrap().tip_sha256,first.tip_sha256);
        assert_eq!(w.observe().unwrap().spent_count,1);
    }
    let w=DurableScratchWitness::open(&path).unwrap();
    let observation=w.observe().unwrap();
    assert_eq!(observation.spent_count,1);
    assert_eq!(observation.tip_sha256,Some(first.tip_sha256.clone()));
    assert!(w.consume(&request("first",'2',observation.tip_sha256.clone(),7)).is_err());
    assert!(w.consume(&request("second",'1',observation.tip_sha256.clone(),7)).is_err());
    assert!(w.consume(&request("second",'2',None,7)).is_err());
    assert_eq!(w.consume(&request("second",'2',observation.tip_sha256,7)).unwrap().spent_count,2);
    assert_eq!(DurableScratchWitness::open(&path).unwrap().observe().unwrap().spent_count,2);
}
#[test]fn separate_handles_concurrent_same_tip_only_one_wins(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let owner=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    let independent=DurableScratchWitness::open(&path).unwrap();
    let barrier=Arc::new(Barrier::new(3));
    let jobs=[(owner,"a",'1'),(independent,"b",'2')].into_iter().map(|(w,id,nonce)|{
        let b=Arc::clone(&barrier);
        thread::spawn(move||{b.wait();w.consume(&request(id,nonce,None,7)).is_ok()})
    }).collect::<Vec<_>>();
    barrier.wait();
    assert_eq!(jobs.into_iter().map(|j|j.join().unwrap()).filter(|success|*success).count(),1);
    assert_eq!(DurableScratchWitness::open(&path).unwrap().observe().unwrap().spent_count,1);
}
#[test]fn registry_epoch_does_not_rollback_after_restart(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    let first=w.consume(&request("a",'1',None,11)).unwrap();
    drop(w);
    let new=DurableScratchWitness::open(&path).unwrap();
    assert_eq!(new.observe().unwrap().registry_epoch,11);
    assert!(new.consume(&request("b",'2',Some(first.tip_sha256.clone()),10)).is_err());
    assert!(new.consume(&request("b",'2',Some(first.tip_sha256),11)).is_ok());
}
#[test]fn tampered_bytes_and_missing_files_fail_closed(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    let first=w.consume(&request("a",'1',None,7)).unwrap();
    w.consume(&request("b",'2',Some(first.tip_sha256),7)).unwrap();
    let second=path.join("journal/00000000000000000002.json");
    let mut data=std::fs::read(&second).unwrap();
    data[0]=b' ';
    std::fs::write(&second,&data).unwrap();
    assert!(w.observe().is_err());
    assert!(DurableScratchWitness::open(&path).is_err());
}
#[test]fn undetected_full_rollback_requires_independent_witness_anchor(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    let cp=w.consume(&request("a",'1',None,7)).unwrap();
    std::fs::remove_file(path.join("journal/00000000000000000001.json")).unwrap();
    // This test documents a production blocker, not acceptable production behavior:
    assert_eq!(DurableScratchWitness::open(&path).unwrap().observe().unwrap().spent_count,0);
    assert_ne!(w.observe().unwrap().tip_sha256,Some(cp.tip_sha256));
}
#[test]fn witness_duplicate_nonce_denied_with_changed_authorization(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    let first=w.consume(&request("a",'1',None,7)).unwrap();
    assert!(w.consume(&request("b",'1',Some(first.tip_sha256),7)).is_err());
    assert!(w.find_spend("b").unwrap().is_none());
}
#[cfg(unix)]
#[test]fn symlink_substitution_is_rejected(){
    use std::os::unix::fs::symlink;
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    w.consume(&request("a",'1',None,7)).unwrap();
    let entry=path.join("journal/00000000000000000001.json");
    std::fs::remove_file(&entry).unwrap();
    symlink(path.join(".GALIA_NONCANONICAL_DURABLE_WITNESS_V1"),&entry).unwrap();
    assert!(w.observe().is_err());
    assert!(DurableScratchWitness::open(&path).is_err());
}
#[test]fn witness_stays_unusable_on_partial_unparseable_record(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("witness");
    let w=DurableScratchWitness::initialize_new(&path,cfg()).unwrap();
    std::fs::write(path.join("journal/00000000000000000001.json"),b"{")
        .unwrap();
    assert!(w.consume(&request("a",'1',None,7)).is_err());
    assert!(w.observe().is_err());
}
