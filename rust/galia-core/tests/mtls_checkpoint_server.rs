#![cfg(feature="tls-transport")]
//! v0.20 mandatory-client-cert TLS 1.3 service tests, synthetic in-memory keys.
//! These tests DO NOT establish a real independent remote checkpoint authority.
use std::net::{TcpListener,SocketAddr,TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::external_checkpoint::*;
use galia_core_shadow::external_transport::*;
use galia_core_shadow::mtls_checkpoint_server::*;
use galia_core_shadow::tls_checkpoint::PinnedMtlsClient;
use galia_core_shadow::transparency::*;
use galia_core_shadow::transparency_board::*;
use galia_core_shadow::witness::*;
use galia_core_shadow::witness_proof::*;
use rcgen::generate_simple_self_signed;
use rustls::{RootCertStore,ClientConfig,ClientConnection};
use rustls::pki_types::{CertificateDer,PrivatePkcs8KeyDer};

fn sk(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn pk(seed:u8)->String{hex::encode(sk(seed).verifying_key().to_bytes())}
fn sign<T:serde::Serialize>(seed:u8,domain:&[u8],value:&T)->String{
    hex::encode(sk(seed).sign(&signing_preimage(domain,value).unwrap()).to_bytes())
}
fn canon<T:serde::Serialize>(v:&T)->Vec<u8>{
    serde_json::to_value(v).and_then(|v|serde_json::to_vec(&v)).unwrap()
}
fn hexhash(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn policy()->ObserverPolicy{
    ObserverPolicy{
        witness_anchor:WitnessTrustAnchor{
            signer_key_id:"witness".into(),pinned_witness_public_key_hex:pk(33),
            pinned_review_root_public_key_hex:pk(7),
            expected_namespace:"tenant".into(),expected_case_id:"cangrejos".into(),
            minimum_registry_epoch:10,minimum_spent_count:0,floor_tip_sha256:None,
        },roster_epoch:3,required_quorum:2,
        observers:vec![
            TrustedObserver{observer_id:"a".into(),public_key_hex:pk(51),revoked:false},
            TrustedObserver{observer_id:"b".into(),public_key_hex:pk(52),revoked:false},
        ]
    }
}
fn publication()->PublishedWitnessView{
    let observation=WitnessObservation{
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        registry_epoch:10,spent_count:0,tip_sha256:None,
    };
    let signed=SignedWitnessObservation{
        signer_key_id:"witness".into(),
        signature_hex:sign(33,OBSERVATION_DOMAIN,&observation),observation,
    };
    let hash=sha256(&canon(&signed));
    let endorsements=[("a",51),("b",52)].into_iter().map(|(id,seed)|{
        let payload=GossipEndorsementPayload{
            format:GOSSIP_FORMAT.into(),roster_epoch:3,
            observer_id:id.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
            witness_observation_sha256:hash.clone(),spent_count:0,
            tip_sha256:None,registry_epoch:10,
        };
        SignedGossipEndorsement{signature_hex:sign(seed,GOSSIP_DOMAIN,&payload),payload}
    }).collect();
    PublishedWitnessView{signed_observation:signed,endorsements}
}
fn external_trust(pin:String)->ExternalServiceTrust{
    let p=policy();
    ExternalServiceTrust{
        checkpoint:CheckpointAnchorTrust{
            external_signer_id:"auditor".into(),
            external_signer_public_key_hex:pk(91),
            stream_id:"signed-checkpoint-stream".into(),
            namespace:"tenant".into(),case_id:"cangrejos".into(),
            pinned_observer_policy_sha256:policy_digest(&p).unwrap(),
            floor_sequence:0,floor_envelope_sha256:None,
            floor_board:BoardCheckpoint{
                journal_count:0,journal_tip_sha256:None,quarantined:false
            },
        },
        service_id:"checkpoint-service".into(),
        response_signer_id:"checkpoint-server-key".into(),
        response_signer_public_key_hex:pk(92),
        pinned_tls_peer_spki_sha256:pin,
        max_challenge_seconds:60,
    }
}
struct TestContext{
    dir:tempfile::TempDir,
    board:DurableTransparencyBoard,
    store:Arc<ScratchCheckpointServiceStore>,
    client:PinnedMtlsClient,
    server:Arc<MandatoryMtlsCheckpointServer>,
    policy:ObserverPolicy,
    trust:ExternalServiceTrust,
    roots:RootCertStore,
}
fn build()->TestContext{
    let d=tempfile::tempdir().unwrap();
    let p=policy();
    let server_cert=generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let client_cert=generate_simple_self_signed(vec!["client.local".into()]).unwrap();
    let (_,parsed)=x509_parser::parse_x509_certificate(server_cert.cert.der().as_ref()).unwrap();
    let pin=sha256(parsed.public_key().raw);
    let trust=external_trust(pin);
    let mut server_roots=RootCertStore::empty();
    server_roots.add(client_cert.cert.der().clone()).unwrap();
    let mut client_roots=RootCertStore::empty();
    client_roots.add(server_cert.cert.der().clone()).unwrap();
    let client=PinnedMtlsClient::new(
        client_roots.clone(),vec![client_cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(client_cert.signing_key.serialize_der()).into(),
        "localhost",Duration::from_secs(5),
    ).unwrap();
    let board=DurableTransparencyBoard::initialize_new(
        d.path().join("board"),p.clone()).unwrap();
    board.publish(publication(),None).unwrap();
    let store=Arc::new(ScratchCheckpointServiceStore::initialize_new(
        d.path().join("service"),trust.clone(),p.clone()).unwrap());
    let payload=ExternalBoardCheckpointPayload{
        format:CHECKPOINT_FORMAT.into(),
        external_signer_id:"auditor".into(),
        stream_id:trust.checkpoint.stream_id.clone(),
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        observer_policy_sha256:policy_digest(&p).unwrap(),
        sequence:1,previous_envelope_sha256:None,
        board:board.checkpoint().unwrap(),quarantined_evidence_sha256:None,
    };
    let signed=SignedExternalBoardCheckpoint{
        signature_hex:sign(91,CHECKPOINT_DOMAIN,&payload),payload,
    };
    assert_eq!(store.append_signed(signed).unwrap(),1);
    let signer=Arc::new(|p:&RemoteCheckpointPayload|Ok(sign(92,RESPONSE_DOMAIN,p)));
    let server=Arc::new(MandatoryMtlsCheckpointServer::new(
        server_roots,vec![server_cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(server_cert.signing_key.serialize_der()).into(),
        Arc::clone(&store),signer,Duration::from_secs(5),
    ).unwrap());
    TestContext{dir:d,board,store,client,server,policy:p,trust,roots:client_roots}
}
fn spawn(server:Arc<MandatoryMtlsCheckpointServer>,now:u64)
    ->(SocketAddr,thread::JoinHandle<Result<(),String>>){
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let address=listener.local_addr().unwrap();
    let join=thread::spawn(move||{
        let (socket,_)=listener.accept().map_err(|e|e.to_string())?;
        server.serve_one(socket,now)
    });
    (address,join)
}
#[test]fn authenticated_client_and_pinned_server_roundtrip_with_durable_checkpoint(){
    let x=build();
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_030);
    let (challenge,peer,response)=x.client.exchange(addr,&x.trust,&x.policy,
        &hexhash('1'),1_800_000_000,1_800_000_060).unwrap();
    assert!(join.join().unwrap().is_ok());
    let report=verify_remote_exchange(&x.board,&x.policy,&x.trust,
        &challenge,&peer,&response,1_800_000_040).unwrap();
    assert_eq!(report.checkpoint_count,1);
    assert!(!report.human_authority_verified&&!report.canonical_writeback);
    assert_eq!(x.store.inspect().unwrap(),(1,1));
}
#[test]fn duplicate_nonce_rejected_after_reopening_durable_server_store(){
    let x=build();
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_030);
    assert!(x.client.exchange(addr,&x.trust,&x.policy,
        &hexhash('1'),1_800_000_000,1_800_000_060).is_ok());
    assert!(join.join().unwrap().is_ok());
    let reopened=ScratchCheckpointServiceStore::open(
        x.dir.path().join("service"),x.trust.clone(),x.policy.clone()).unwrap();
    assert_eq!(reopened.inspect().unwrap(),(1,1));
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_035);
    assert!(x.client.exchange(addr,&x.trust,&x.policy,
        &hexhash('1'),1_800_000_000,1_800_000_060).is_err());
    assert!(join.join().unwrap().is_err());
    assert_eq!(reopened.inspect().unwrap(),(1,1));
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_040);
    assert!(x.client.exchange(addr,&x.trust,&x.policy,
        &hexhash('2'),1_800_000_000,1_800_000_060).is_ok());
    assert!(join.join().unwrap().is_ok());
    assert_eq!(reopened.inspect().unwrap(),(1,2));
}
#[test]fn concurrently_competing_same_nonce_has_exactly_one_success(){
    let x=build();
    let (a,j1)=spawn(Arc::clone(&x.server),1_800_000_030);
    let (b,j2)=spawn(Arc::clone(&x.server),1_800_000_030);
    // True concurrency: both clients initiate separate TLS handshakes and
    // compete for the same durable nonce under the service's file lock.
    let client=Arc::new(x.client);
    let trust=x.trust.clone();
    let policy=x.policy.clone();
    let barrier=Arc::new(std::sync::Barrier::new(3));
    let clients=[a,b].into_iter().map(|addr|{
        let client=Arc::clone(&client);
        let trust=trust.clone();
        let policy=policy.clone();
        let ready=Arc::clone(&barrier);
        thread::spawn(move||{
            ready.wait();
            client.exchange(addr,&trust,&policy,
                &hexhash('3'),1_800_000_000,1_800_000_060).is_ok()
        })
    }).collect::<Vec<_>>();
    barrier.wait();
    assert_eq!(clients.into_iter().map(|j|j.join().unwrap()).filter(|won|*won).count(),1);
    assert_eq!(usize::from(j1.join().unwrap().is_ok())+
        usize::from(j2.join().unwrap().is_ok()),1);
    assert_eq!(x.store.inspect().unwrap(),(1,1));
}
#[test]fn checkpoint_duplication_and_forgery_fail_closed(){
    let x=build();
    let chain=x.store.checkpoint_suffix(0,None).unwrap();
    assert_eq!(chain.len(),1);
    assert!(x.store.append_signed(chain[0].clone()).is_err());
    let mut forged=chain[0].clone();
    forged.signature_hex=sign(99,CHECKPOINT_DOMAIN,&forged.payload);
    assert!(x.store.append_signed(forged).is_err());
    assert_eq!(x.store.inspect().unwrap(),(1,0));
}
#[test]fn wrong_client_floor_and_missing_checkpoint_are_rejected(){
    let x=build();
    assert!(x.store.checkpoint_suffix(0,Some(&hexhash('f'))).is_err());
    assert!(x.store.checkpoint_suffix(2,None).is_err());
    let chain=x.store.checkpoint_suffix(0,None).unwrap();
    let digest=sha256(&canon(&chain[0]));
    assert!(x.store.checkpoint_suffix(1,Some(&digest)).is_err());
    assert_eq!(x.store.inspect().unwrap(),(1,0));
}
#[test]fn corrupted_durable_checkpoint_file_blocks_reopen_and_service(){
    let x=build();
    let target=x.dir.path().join("service/checkpoints/00000000000000000001.json");
    std::fs::write(target,b"{").unwrap();
    assert!(x.store.inspect().is_err());
    assert!(ScratchCheckpointServiceStore::open(
        x.dir.path().join("service"),x.trust.clone(),x.policy.clone()).is_err());
}
#[test]fn corrupted_nonce_history_blocks_reopen(){
    let x=build();
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_030);
    assert!(x.client.exchange(addr,&x.trust,&x.policy,
        &hexhash('5'),1_800_000_000,1_800_000_060).is_ok());
    assert!(join.join().unwrap().is_ok());
    std::fs::write(x.dir.path().join("service/nonce_claims/00000000000000000001.json"),b"{").unwrap();
    assert!(x.store.inspect().is_err());
    assert!(ScratchCheckpointServiceStore::open(
        x.dir.path().join("service"),x.trust.clone(),x.policy.clone()).is_err());
}
#[test]fn pinned_policy_and_existing_directory_cannot_be_substituted(){
    let x=build();
    let mut t=x.trust.clone();
    t.service_id="other-service".into();
    assert!(ScratchCheckpointServiceStore::open(
        x.dir.path().join("service"),t,x.policy.clone()).is_err());
    assert!(ScratchCheckpointServiceStore::initialize_new(
        x.dir.path().join("service"),x.trust.clone(),x.policy.clone()).is_err());
}
#[test]fn real_mtls_server_rejects_clients_without_certificate(){
    let x=build();
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_030);
    // This client has a trusted server CA but intentionally NO client identity.
    let config=ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(x.roots.clone())
        .with_no_client_auth();
    let mut socket=TcpStream::connect(addr).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let dns=rustls::pki_types::ServerName::try_from("localhost").unwrap().to_owned();
    let mut conn=ClientConnection::new(Arc::new(config),dns).unwrap();
    let mut result=Ok(());
    while conn.is_handshaking(){
        if let Err(e)=conn.complete_io(&mut socket){result=Err(e);break;}
    }
    // Server MUST reject handshake or subsequent request without client cert.
    let rejected=join.join().unwrap().is_err();
    assert!(rejected);
    assert_eq!(x.store.inspect().unwrap(),(1,0));
    let _=result;
}
#[test]fn wrong_server_spki_pin_refused_before_nonce_claim(){
    let x=build();
    let mut t=x.trust.clone();
    t.pinned_tls_peer_spki_sha256=hexhash('f');
    let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_030);
    assert!(x.client.exchange(addr,&t,&x.policy,
        &hexhash('6'),1_800_000_000,1_800_000_060).is_err());
    let _=join.join();
    assert_eq!(x.store.inspect().unwrap(),(1,0));
}

#[test]fn complete_local_journal_rollback_remains_undetectable_without_external_anchor(){
    let x=build();
    assert_eq!(x.store.inspect().unwrap(),(1,0));
    // Signed checkpoint hash is lost with the single mutable directory.
    // This intentionally demonstrates the unresolved external high-water gate.
    std::fs::remove_file(x.dir.path()
        .join("service/checkpoints/00000000000000000001.json")).unwrap();
    assert_eq!(x.store.inspect().unwrap(),(0,0));
}


// v0.21: TWO physically separate scratch roots and offline signed observers.
// Synthetic keys and local directories do not confer actual host independence.
mod recovery_tests{
    use super::*;
    use galia_core_shadow::service_recovery::*;
    fn pin(x:&TestContext,host:&str,seed:u8,
        floor:Option<ServiceSnapshot>)->ServicePeerTrust{
        ServicePeerTrust{
            host_id:host.into(),
            signer_key_id:format!("observer-{}",host),
            signer_public_key_hex:pk(seed),
            service_id:x.trust.service_id.clone(),
            namespace:x.trust.checkpoint.namespace.clone(),
            case_id:x.trust.checkpoint.case_id.clone(),
            service_trust_sha256:sha256(&canon(&x.trust)),
            observer_policy_sha256:policy_digest(&x.policy).unwrap(),
            floor,
        }
    }
    fn signed(x:&TestContext,p:&ServicePeerTrust,seed:u8)->SignedServicePeerView{
        let payload=ServicePeerViewPayload{
            format:SERVICE_VIEW_FORMAT.into(),host_id:p.host_id.clone(),
            signer_key_id:p.signer_key_id.clone(),
            service_id:p.service_id.clone(),namespace:p.namespace.clone(),
            case_id:p.case_id.clone(),
            service_trust_sha256:p.service_trust_sha256.clone(),
            observer_policy_sha256:p.observer_policy_sha256.clone(),
            snapshot:x.store.snapshot().unwrap(),
        };
        SignedServicePeerView{
            signature_hex:sign(seed,SERVICE_VIEW_DOMAIN,&payload),payload,
        }
    }
    fn consume(x:&TestContext,nonce:char){
        let (addr,join)=spawn(Arc::clone(&x.server),1_800_000_030);
        let result=x.client.exchange(addr,&x.trust,&x.policy,
            &hexhash(nonce),1_800_000_000,1_800_000_060);
        assert!(result.is_ok(),"synthetic mTLS consume failed: {:?}",result.err());
        assert!(join.join().unwrap().is_ok());
    }
    #[test]fn two_signed_empty_peers_agree_but_do_not_establish_consensus(){
        let a=build();let b=build();
        let pa=pin(&a,"host-a",101,None);let pb=pin(&b,"host-b",102,None);
        let sa=signed(&a,&pa,101);let sb=signed(&b,&pb,102);
        inspect_local_peer(&a.store,&sa,&pa,&a.trust,&a.policy).unwrap();
        inspect_local_peer(&b.store,&sb,&pb,&b.trust,&b.policy).unwrap();
        let r=compare_peer_views(&sa,&pa,&a.trust,&sb,&pb,&b.trust,&a.policy).unwrap();
        assert_eq!(r.kind,PeerComparisonKind::IdenticalSignedState);
        assert!(!r.automatic_recovery_permitted&&!r.cross_host_consensus_verified);
        assert!(!r.real_host_independence_verified&&!r.canonical_writeback);
    }
    #[test]fn one_isolated_service_advances_but_extension_is_unproven(){
        let a=build();let b=build();
        consume(&a,'1');
        let pa=pin(&a,"host-a",101,None);let pb=pin(&b,"host-b",102,None);
        let r=compare_peer_views(&signed(&a,&pa,101),&pa,&a.trust,
            &signed(&b,&pb,102),&pb,&b.trust,&a.policy).unwrap();
        assert_eq!(r.kind,PeerComparisonKind::DifferentHeightsConsistencyUnproven);
        assert!(!r.signed_divergence_evidence&&!r.automatic_recovery_permitted);
    }
    #[test]fn two_partitions_accept_distinct_nonces_at_same_height_and_diverge(){
        let a=build();let b=build();
        consume(&a,'1');consume(&b,'2');
        let pa=pin(&a,"host-a",101,None);let pb=pin(&b,"host-b",102,None);
        let sa=signed(&a,&pa,101);let sb=signed(&b,&pb,102);
        let r=compare_peer_views(&sa,&pa,&a.trust,&sb,&pb,&b.trust,&a.policy).unwrap();
        assert_eq!(r.kind,PeerComparisonKind::SignedStateDivergence);
        assert!(r.signed_divergence_evidence);
        assert!(r.exact_checkpoint_match&&!r.exact_nonce_history_match);
        assert_ne!(r.left_signed_view_sha256,r.right_signed_view_sha256);
        assert!(!r.automatic_recovery_permitted&&!r.authority_transfer);
    }
    #[test]fn duplicate_nonce_can_succeed_on_two_separate_roots_global_gap(){
        let a=build();let b=build();
        consume(&a,'3');consume(&b,'3');
        // Both isolated journals accepted the same logical nonce. This is a
        // deliberate non-production counterexample to global replay safety.
        assert_eq!(a.store.inspect().unwrap(),(1,1));
        assert_eq!(b.store.inspect().unwrap(),(1,1));
        let pa=pin(&a,"host-a",101,None);let pb=pin(&b,"host-b",102,None);
        let r=compare_peer_views(&signed(&a,&pa,101),&pa,&a.trust,
            &signed(&b,&pb,102),&pb,&b.trust,&a.policy).unwrap();
        // Different TLS exporter/channel hashes also diverge in the journals,
        // but BOTH stores accepted the same nonce: no distributed uniqueness.
        assert_eq!(r.kind,PeerComparisonKind::SignedStateDivergence);
        assert!(!r.cross_host_consensus_verified);
    }
    #[test]fn out_of_band_signed_highwater_detects_local_nonce_rollback(){
        let a=build();consume(&a,'4');
        let pa=pin(&a,"host-a",101,None);
        let prior=signed(&a,&pa,101);
        let pinned=pin(&a,"host-a",101,Some(prior.payload.snapshot.clone()));
        std::fs::remove_file(a.dir.path()
            .join("service/nonce_claims/00000000000000000001.json")).unwrap();
        assert_eq!(a.store.snapshot().unwrap().nonce_count,0);
        assert!(inspect_local_peer(&a.store,&prior,&pinned,&a.trust,&a.policy).is_err());
        assert!(a.store.verify_external_floor(&prior.payload.snapshot).is_err());
    }
    #[test]fn independently_retained_prior_floor_verifies_after_later_growth(){
        let a=build();consume(&a,'5');
        let floor=a.store.snapshot().unwrap();
        let pa=pin(&a,"host-a",101,Some(floor.clone()));
        consume(&a,'6');
        let later=signed(&a,&pa,101);
        assert_eq!(later.payload.snapshot.nonce_count,2);
        let checked=inspect_local_peer(&a.store,&later,&pa,&a.trust,&a.policy).unwrap();
        assert_eq!(checked.nonce_count,2);
        assert_eq!(a.store.verify_external_floor(&floor).unwrap().nonce_count,2);
    }
    #[test]fn signed_but_false_local_snapshot_is_detected_on_direct_inspection(){
        let a=build();let pa=pin(&a,"host-a",101,None);
        let mut reported=signed(&a,&pa,101);
        reported.payload.snapshot.nonce_count=1;
        reported.payload.snapshot.nonce_tip_sha256=Some(hexhash('f'));
        reported.signature_hex=sign(101,SERVICE_VIEW_DOMAIN,&reported.payload);
        assert!(verify_peer_view(&reported,&pa,&a.trust,&a.policy).is_ok());
        assert!(inspect_local_peer(&a.store,&reported,&pa,&a.trust,&a.policy).is_err());
    }
    #[test]fn forged_peer_signature_and_key_substitution_are_rejected(){
        let a=build();let pa=pin(&a,"host-a",101,None);
        let mut v=signed(&a,&pa,101);
        v.signature_hex=sign(103,SERVICE_VIEW_DOMAIN,&v.payload);
        assert!(verify_peer_view(&v,&pa,&a.trust,&a.policy).is_err());
        let mut bad=pa.clone();bad.signer_public_key_hex=pk(92);
        assert!(bad.validate(&a.trust,&a.policy).is_err());
        let mut bad=pa.clone();bad.signer_public_key_hex=pk(91);
        assert!(bad.validate(&a.trust,&a.policy).is_err());
    }
    #[test]fn host_scope_and_policy_digest_confusion_fail_closed(){
        let a=build();let pa=pin(&a,"host-a",101,None);
        let v=signed(&a,&pa,101);
        let mut wrong=pa.clone();wrong.host_id="host-z".into();
        assert!(verify_peer_view(&v,&wrong,&a.trust,&a.policy).is_err());
        let mut wrong=pa.clone();wrong.service_trust_sha256=hexhash('f');
        assert!(verify_peer_view(&v,&wrong,&a.trust,&a.policy).is_err());
        let mut wrong=pa.clone();wrong.case_id="wrong".into();
        assert!(verify_peer_view(&v,&wrong,&a.trust,&a.policy).is_err());
    }
    #[test]fn two_pins_for_same_signer_cannot_be_misreported_as_independent(){
        let a=build();let b=build();
        let pa=pin(&a,"host-a",101,None);let pb=pin(&b,"host-b",101,None);
        assert!(compare_peer_views(&signed(&a,&pa,101),&pa,&a.trust,
            &signed(&b,&pb,101),&pb,&b.trust,&a.policy).is_err());
    }
    #[test]fn signed_floor_at_equal_count_cannot_change_digest(){
        let a=build();consume(&a,'7');
        let mut f=a.store.snapshot().unwrap();
        f.nonce_tip_sha256=Some(hexhash('a'));
        let p=pin(&a,"host-a",101,Some(f));
        assert!(verify_peer_view(&signed(&a,&p,101),&p,&a.trust,&a.policy).is_err());
    }
    #[test]fn corrupt_journal_blocks_trusted_recovery_not_auto_repaired(){
        let a=build();consume(&a,'8');
        let pa=pin(&a,"host-a",101,None);
        let view=signed(&a,&pa,101);
        std::fs::write(a.dir.path()
            .join("service/nonce_claims/00000000000000000001.json"),b"{").unwrap();
        assert!(inspect_local_peer(&a.store,&view,&pa,&a.trust,&a.policy).is_err());
        assert!(a.store.snapshot().is_err());
    }
    #[test]fn unknown_authority_fields_are_rejected_by_strict_schema(){
        let a=build();let pa=pin(&a,"host-a",101,None);
        let mut v=serde_json::to_value(signed(&a,&pa,101)).unwrap();
        v["payload"]["canonical_promotion"]=serde_json::json!(true);
        assert!(serde_json::from_value::<SignedServicePeerView>(v).is_err());
    }
}


// GALIA v0.22 — test-only cross-host boundary: real TLS to two local server
// instances, but a single cooperative local filesystem is the coordinator.
// No distributed consensus or externally deployed linearizable witness.
mod fencing_tests{
    use super::*;
    use std::sync::{Barrier};
    use galia_core_shadow::fenced_coordinator::*;

    fn scope(x:&TestContext)->FencingScope{
        FencingScope{
            namespace:x.trust.checkpoint.namespace.clone(),
            case_id:x.trust.checkpoint.case_id.clone(),
            service_id:x.trust.service_id.clone(),
            pinned_observer_policy_sha256:policy_digest(&x.policy).unwrap(),
            pinned_response_signer_public_key_hex:x.trust.response_signer_public_key_hex.clone(),
        }
    }
    fn coordinator(x:&TestContext)->(tempfile::TempDir,Arc<DurableFencingCoordinator>){
        let d=tempfile::tempdir().unwrap();
        let c=DurableFencingCoordinator::initialize_new(
            d.path().join("central-scratch"),scope(x)).unwrap();
        (d,Arc::new(c))
    }
    fn fenced_server(
        server:Arc<MandatoryMtlsCheckpointServer>,authority:Arc<dyn FencingAuthority>,
        grant:EpochGrant,now:u64
    )->(SocketAddr,thread::JoinHandle<Result<(),String>>){
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let addr=listener.local_addr().unwrap();
        let worker=thread::spawn(move||{
            let (socket,_)=listener.accept().map_err(|e|e.to_string())?;
            server.serve_one_fenced(socket,now,authority.as_ref(),&grant)
        });
        (addr,worker)
    }
    fn call(x:&TestContext,c:Arc<dyn FencingAuthority>,g:EpochGrant,
        nonce:char)->(bool,bool){
        let (addr,j)=fenced_server(Arc::clone(&x.server),c,g,1_800_000_030);
        let ok=x.client.exchange(addr,&x.trust,&x.policy,&hexhash(nonce),
            1_800_000_000,1_800_000_060).is_ok();
        (ok,j.join().unwrap().is_ok())
    }
    struct Partitioned{
        scope:FencingScope,
    }
    impl FencingAuthority for Partitioned{
        fn scope(&self)->Result<FencingScope,String>{Ok(self.scope.clone())}
        fn claim(&self,_:&EpochGrant,_:&str)->Result<FencingCheckpoint,String>{
            Err("simulated coordinator network partition".into())
        }
    }
    #[test]fn single_epoch_and_shared_nonce_uniqueness(){
        let x=build();let (_dir,c)=coordinator(&x);
        let grant=c.advance_epoch(0,"worker-a").unwrap();
        let one=c.claim(&grant,&hexhash('1')).unwrap();
        assert_eq!(one.nonce_claim_count,1);
        assert_eq!(one.active_grant,Some(grant.clone()));
        assert!(c.claim(&grant,&hexhash('1')).is_err());
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,1);
        assert_eq!(c.claim(&grant,&hexhash('2')).unwrap().nonce_claim_count,2);
    }
    #[test]fn stale_holder_fenced_after_explicit_epoch_cas_failover(){
        let x=build();let (_dir,c)=coordinator(&x);
        let a=c.advance_epoch(0,"worker-a").unwrap();
        assert!(c.advance_epoch(0,"worker-z").is_err());
        let b=c.advance_epoch(1,"worker-b").unwrap();
        assert_eq!(b.epoch,2);
        assert!(c.claim(&a,&hexhash('1')).is_err());
        assert!(c.claim(&EpochGrant{host_id:"worker-z".into(),epoch:2},&hexhash('1')).is_err());
        assert_eq!(c.claim(&b,&hexhash('1')).unwrap().nonce_claim_count,1);
    }
    #[test]fn two_local_coordinator_handles_race_and_only_one_nonce_wins(){
        let x=build();let (dir,c)=coordinator(&x);
        let grant=c.advance_epoch(0,"worker-a").unwrap();
        let right=DurableFencingCoordinator::open(dir.path().join("central-scratch"),
            scope(&x)).unwrap();
        let barrier=Arc::new(Barrier::new(3));
        let jobs=[(*c).clone(),right].into_iter().map(|one|{
            let b=Arc::clone(&barrier);let token=grant.clone();
            thread::spawn(move||{b.wait();one.claim(&token,&hexhash('3')).is_ok()})
        }).collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(jobs.into_iter().map(|j|j.join().unwrap()).filter(|v|*v).count(),1);
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn coordinator_replay_persists_grants_nonce_uniqueness_across_reopen(){
        let x=build();let (dir,c)=coordinator(&x);
        let grant=c.advance_epoch(0,"worker-a").unwrap();
        c.claim(&grant,&hexhash('4')).unwrap();
        let saved=c.checkpoint().unwrap();
        drop(c);
        let reopened=DurableFencingCoordinator::open(dir.path().join("central-scratch"),scope(&x)).unwrap();
        assert_eq!(reopened.checkpoint().unwrap(),saved);
        assert!(reopened.claim(&grant,&hexhash('4')).is_err());
        assert_eq!(reopened.advance_epoch(1,"worker-b").unwrap().epoch,2);
        assert!(reopened.claim(&grant,&hexhash('5')).is_err());
    }
    #[test]fn independently_preserved_highwater_detects_whole_local_coordinator_rollback(){
        let x=build();let (dir,c)=coordinator(&x);
        let grant=c.advance_epoch(0,"worker-a").unwrap();
        c.claim(&grant,&hexhash('6')).unwrap();
        let independently_pinned=c.checkpoint().unwrap();
        std::fs::remove_file(dir.path()
            .join("central-scratch/journal/00000000000000000002.json")).unwrap();
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,0);
        assert!(c.verify_floor(&independently_pinned).is_err());
        // Unanchored scratch-only replay would forget that nonce.
        assert_eq!(c.claim(&grant,&hexhash('6')).unwrap().nonce_claim_count,1);
    }
    #[test]fn corrupt_fencing_log_rejects_open_and_claim_without_repair(){
        let x=build();let (dir,c)=coordinator(&x);
        let grant=c.advance_epoch(0,"worker-a").unwrap();
        std::fs::write(dir.path()
            .join("central-scratch/journal/00000000000000000001.json"),b"{").unwrap();
        assert!(c.checkpoint().is_err());
        assert!(c.claim(&grant,&hexhash('7')).is_err());
        assert!(DurableFencingCoordinator::open(dir.path().join("central-scratch"),
            scope(&x)).is_err());
    }
    #[test]fn coordinator_does_not_accept_wrong_case_or_policy_or_existing_root(){
        let x=build();let (dir,c)=coordinator(&x);
        let mut mismatch=scope(&x);mismatch.case_id="other-case".into();
        assert!(DurableFencingCoordinator::open(dir.path().join("central-scratch"),
            mismatch).is_err());
        let mut mismatch=scope(&x);mismatch.pinned_observer_policy_sha256=hexhash('f');
        assert!(DurableFencingCoordinator::open(dir.path().join("central-scratch"),
            mismatch).is_err());
        assert!(DurableFencingCoordinator::initialize_new(dir.path().join("central-scratch"),
            scope(&x)).is_err());
        assert_eq!(c.checkpoint().unwrap().record_count,0);
    }
    #[test]fn real_tls_two_separate_service_roots_share_one_nonce_fence(){
        let a=build();let b=build();
        let (_dir,c)=coordinator(&a);
        let ga=c.advance_epoch(0,"worker-a").unwrap();
        let ca:Arc<dyn FencingAuthority>=c.clone();
        assert_eq!(call(&a,ca,ga.clone(),'1'),(true,true));
        assert_eq!(a.store.inspect().unwrap(),(1,1));
        let gb=c.advance_epoch(1,"worker-b").unwrap();
        let cb:Arc<dyn FencingAuthority>=c.clone();
        assert_eq!(call(&b,Arc::clone(&cb),gb.clone(),'1'),(false,false));
        assert_eq!(b.store.inspect().unwrap(),(1,0));
        assert_eq!(call(&b,cb,gb,'2'),(true,true));
        assert_eq!(b.store.inspect().unwrap(),(1,1));
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,2);
    }
    #[test]fn real_tls_two_replica_race_duplicate_nonce_has_one_success(){
        let a=Arc::new(build());let b=Arc::new(build());
        let (_dir,c)=coordinator(&a);
        let grant=c.advance_epoch(0,"shared-test-token").unwrap();
        let auth:Arc<dyn FencingAuthority>=c.clone();
        let barrier=Arc::new(Barrier::new(3));
        let jobs=[Arc::clone(&a),Arc::clone(&b)].into_iter().map(|fixture|{
            let authority=Arc::clone(&auth);
            let token=grant.clone();
            let ready=Arc::clone(&barrier);
            thread::spawn(move||{
                ready.wait();
                call(&fixture,authority,token,'3')
            })
        }).collect::<Vec<_>>();
        barrier.wait();
        let res=jobs.into_iter().map(|j|j.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(res.iter().filter(|(c,s)|*c&&*s).count(),1);
        assert_eq!(res.iter().filter(|(c,s)|!*c&&!*s).count(),1);
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn simulated_coordinator_partition_fails_closed_before_local_nonce_claim(){
        let a=build();
        let root:Arc<dyn FencingAuthority>=Arc::new(Partitioned{scope:scope(&a)});
        let grant=EpochGrant{host_id:"host-a".into(),epoch:1};
        assert_eq!(call(&a,root,grant,'4'),(false,false));
        assert_eq!(a.store.inspect().unwrap(),(1,0));
    }
    #[test]fn wrongly_scoped_coordinator_fails_before_network_auth_and_local_write(){
        let a=build();
        let mut wrong=scope(&a);wrong.case_id="different".into();
        let root:Arc<dyn FencingAuthority>=Arc::new(Partitioned{scope:wrong});
        let grant=EpochGrant{host_id:"host-a".into(),epoch:1};
        assert_eq!(call(&a,root,grant,'5'),(false,false));
        assert_eq!(a.store.inspect().unwrap(),(1,0));
    }
    #[test]fn blocked_coordinator_does_not_prevent_unguarded_legacy_path_counterexample(){
        let a=build();let b=build();
        let (_dir,c)=coordinator(&a);
        let token=c.advance_epoch(0,"host-a").unwrap();
        let ca:Arc<dyn FencingAuthority>=c.clone();
        assert_eq!(call(&a,ca,token,'6'),(true,true));
        // EXPLICIT LIMIT: retained v0.20 serve_one bypasses this opt-in fence;
        // an unguarded service can still accept the same nonce on another root.
        let (addr,j)=spawn(Arc::clone(&b.server),1_800_000_030);
        assert!(b.client.exchange(addr,&b.trust,&b.policy,&hexhash('6'),
            1_800_000_000,1_800_000_060).is_ok());
        assert!(j.join().unwrap().is_ok());
        assert_eq!(b.store.inspect().unwrap(),(1,1));
    }
    #[test]fn corrupt_unknown_fencing_file_is_fail_closed(){
        let a=build();let (dir,c)=coordinator(&a);
        std::fs::write(dir.path().join("central-scratch/journal/injected.json"),b"{}").unwrap();
        assert!(c.checkpoint().is_err());
    }
    #[cfg(unix)]
    #[test]fn symlinked_coordinator_entry_fails_closed(){
        use std::os::unix::fs::symlink;
        let a=build();let (dir,c)=coordinator(&a);
        symlink(dir.path().join("central-scratch/.GALIA_NONCANONICAL_EPOCH_FENCING_V1"),
            dir.path().join("central-scratch/journal/00000000000000000001.json")).unwrap();
        assert!(c.checkpoint().is_err());
    }

    // v0.23: both nonce and canonical signed response are atomically recorded
    // in ONE local coordinator entry after verifying the epoch and signature.
    fn reply(x:&TestContext,nonce:char)->String{
        let payload=RemoteCheckpointPayload{
            format:RESPONSE_FORMAT.into(),service_id:x.trust.service_id.clone(),
            signer_id:x.trust.response_signer_id.clone(),
            challenge_sha256:hexhash('a'),
            nonce_sha256:hexhash(nonce),tls_exporter_sha256:hexhash('b'),
            signed_at_unix_seconds:1_800_000_030,
            checkpoint_chain:x.store.checkpoint_suffix(0,None).unwrap(),
        };
        let r=SignedRemoteCheckpointResponse{
            signature_hex:sign(92,RESPONSE_DOMAIN,&payload),payload,
        };
        String::from_utf8(canon(&r)).unwrap()
    }
    fn guarded_server(
        server:Arc<MandatoryMtlsCheckpointServer>,authority:Arc<dyn FencingAuthority>,
        grant:EpochGrant,now:u64
    )->(SocketAddr,thread::JoinHandle<Result<(),String>>){
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let addr=listener.local_addr().unwrap();
        let join=thread::spawn(move||{
            let (socket,_)=listener.accept().map_err(|e|e.to_string())?;
            server.serve_one_commit_guarded(socket,now,authority.as_ref(),&grant)
        });
        (addr,join)
    }
    fn guarded_call(x:&TestContext,auth:Arc<dyn FencingAuthority>,
        grant:EpochGrant,nonce:char)->(bool,bool){
        let (addr,j)=guarded_server(Arc::clone(&x.server),auth,grant,1_800_000_030);
        let ok=x.client.exchange(addr,&x.trust,&x.policy,&hexhash(nonce),
            1_800_000_000,1_800_000_060).is_ok();
        (ok,j.join().unwrap().is_ok())
    }
    #[test]fn commit_point_same_record_binds_nonce_epoch_and_signed_content(){
        let x=build();let (_dir,c)=coordinator(&x);
        let grant=c.advance_epoch(0,"host-a").unwrap();
        let content=reply(&x,'1');
        let done=c.commit_response(&grant,&hexhash('1'),&content).unwrap();
        assert!(done.durable_scratch_record_committed);
        assert_eq!(done.checkpoint.nonce_claim_count,1);
        assert_eq!(c.committed_response(&hexhash('1')).unwrap(),Some(content));
        assert!(!done.human_authority_verified&&!done.canonical_writeback);
        assert!(!done.cross_host_consensus_verified&&!done.authority_transfer);
        assert_eq!(x.store.inspect().unwrap(),(1,0));
    }
    #[test]fn prepared_signed_content_with_stale_epoch_rejected_at_commit(){
        let x=build();let (_dir,c)=coordinator(&x);
        let a=c.advance_epoch(0,"host-a").unwrap();
        let prepared=reply(&x,'2');
        let b=c.advance_epoch(1,"host-b").unwrap();
        assert!(c.commit_response(&a,&hexhash('2'),&prepared).is_err());
        assert_eq!(c.committed_response(&hexhash('2')).unwrap(),None);
        assert_eq!(c.commit_response(&b,&hexhash('2'),&prepared).unwrap().grant,b);
    }
    #[test]fn duplicate_commit_even_with_different_valid_signed_reply_is_rejected(){
        let x=build();let (_dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        c.commit_response(&token,&hexhash('3'),&reply(&x,'3')).unwrap();
        assert!(c.commit_response(&token,&hexhash('3'),&reply(&x,'3')).is_err());
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn forged_signed_payload_is_rejected_inside_coordinator_at_commit(){
        let x=build();let (_dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        let mut value:SignedRemoteCheckpointResponse=
            serde_json::from_str(&reply(&x,'4')).unwrap();
        value.signature_hex=sign(99,RESPONSE_DOMAIN,&value.payload);
        assert!(c.commit_response(&token,&hexhash('4'),
            &String::from_utf8(canon(&value)).unwrap()).is_err());
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn signed_response_cannot_claim_a_different_nonce_or_service(){
        let x=build();let (_dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        let content=reply(&x,'5');
        assert!(c.commit_response(&token,&hexhash('f'),&content).is_err());
        let mut r:SignedRemoteCheckpointResponse=serde_json::from_str(&content).unwrap();
        r.payload.service_id="other-service".into();
        r.signature_hex=sign(92,RESPONSE_DOMAIN,&r.payload);
        assert!(c.commit_response(&token,&hexhash('5'),
            &String::from_utf8(canon(&r)).unwrap()).is_err());
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn claimed_nonce_cannot_be_committed_as_new_storage_record(){
        let x=build();let (_dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        c.claim(&token,&hexhash('6')).unwrap();
        assert!(c.commit_response(&token,&hexhash('6'),&reply(&x,'6')).is_err());
        assert_eq!(c.committed_response(&hexhash('6')).unwrap(),None);
    }
    #[test]fn restart_replays_exact_signed_response_and_denies_duplicate(){
        let x=build();let (dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        let content=reply(&x,'7');
        c.commit_response(&token,&hexhash('7'),&content).unwrap();
        drop(c);
        let reopened=DurableFencingCoordinator::open(
            dir.path().join("central-scratch"),scope(&x)).unwrap();
        assert_eq!(reopened.committed_response(&hexhash('7')).unwrap(),Some(content.clone()));
        assert!(reopened.commit_response(&token,&hexhash('7'),&content).is_err());
    }
    #[test]fn committed_response_tampering_blocks_recovery_and_future_writes(){
        let x=build();let (dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        c.commit_response(&token,&hexhash('8'),&reply(&x,'8')).unwrap();
        std::fs::write(dir.path()
            .join("central-scratch/journal/00000000000000000002.json"),b"{").unwrap();
        assert!(c.committed_response(&hexhash('8')).is_err());
        assert!(c.commit_response(&token,&hexhash('9'),&reply(&x,'9')).is_err());
        assert!(DurableFencingCoordinator::open(
            dir.path().join("central-scratch"),scope(&x)).is_err());
    }
    #[test]fn simultaneous_storage_commits_only_one_wins_shared_nonce(){
        let x=build();let (_dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        let ready=Arc::new(Barrier::new(3));
        let content=reply(&x,'a');
        let jobs=(0..2).map(|_|{
            let coordinator=Arc::clone(&c);
            let token=token.clone();let content=content.clone();
            let ready=Arc::clone(&ready);
            thread::spawn(move||{
                ready.wait();
                coordinator.commit_response(&token,&hexhash('a'),&content).is_ok()
            })
        }).collect::<Vec<_>>();
        ready.wait();
        assert_eq!(jobs.into_iter().map(|j|j.join().unwrap()).filter(|ok|*ok).count(),1);
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn real_tls_two_replicas_guarded_commit_one_nonce_success(){
        let a=build();let b=build();let (_dir,c)=coordinator(&a);
        let token=c.advance_epoch(0,"shared-holder").unwrap();
        let auth:Arc<dyn FencingAuthority>=c.clone();
        assert_eq!(guarded_call(&a,Arc::clone(&auth),token.clone(),'b'),(true,true));
        assert_eq!(guarded_call(&b,auth,token,'b'),(false,false));
        assert_eq!(a.store.inspect().unwrap(),(1,0));
        assert_eq!(b.store.inspect().unwrap(),(1,0));
        assert!(c.committed_response(&hexhash('b')).unwrap().is_some());
        assert_eq!(c.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn guarded_tls_two_replicas_simultaneous_same_nonce_race(){
        let a=Arc::new(build());let b=Arc::new(build());
        let (_dir,c)=coordinator(&a);
        let token=c.advance_epoch(0,"shared-holder").unwrap();
        let auth:Arc<dyn FencingAuthority>=c.clone();
        let barrier=Arc::new(Barrier::new(3));
        let jobs=[Arc::clone(&a),Arc::clone(&b)].into_iter().map(|fixture|{
            let token=token.clone();let auth=Arc::clone(&auth);
            let b=Arc::clone(&barrier);
            thread::spawn(move||{b.wait();guarded_call(&fixture,auth,token,'c')})
        }).collect::<Vec<_>>();
        barrier.wait();
        let result=jobs.into_iter().map(|j|j.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(result.iter().filter(|(c,s)|*c&&*s).count(),1);
        assert_eq!(result.iter().filter(|(c,s)|!*c&&!*s).count(),1);
        assert!(c.committed_response(&hexhash('c')).unwrap().is_some());
    }
    #[test]fn unavailable_commit_capability_rejects_without_local_fallback(){
        let x=build();let partition:Arc<dyn FencingAuthority>=
            Arc::new(Partitioned{scope:scope(&x)});
        assert_eq!(guarded_call(&x,partition,
            EpochGrant{host_id:"host-a".into(),epoch:1},'d'),(false,false));
        assert_eq!(x.store.inspect().unwrap(),(1,0));
    }
    #[test]fn commit_rejects_wrong_scope_before_any_tls_response(){
        let x=build();let mut incorrect=scope(&x);
        incorrect.pinned_response_signer_public_key_hex=pk(99);
        let partition:Arc<dyn FencingAuthority>=
            Arc::new(Partitioned{scope:incorrect});
        assert_eq!(guarded_call(&x,partition,
            EpochGrant{host_id:"host-a".into(),epoch:1},'e'),(false,false));
        assert_eq!(x.store.inspect().unwrap(),(1,0));
    }
    #[test]fn out_of_band_checkpoint_can_detect_local_commit_rollback(){
        let x=build();let (dir,c)=coordinator(&x);
        let token=c.advance_epoch(0,"host-a").unwrap();
        c.commit_response(&token,&hexhash('f'),&reply(&x,'f')).unwrap();
        let highwater=c.checkpoint().unwrap();
        std::fs::remove_file(dir.path()
            .join("central-scratch/journal/00000000000000000002.json")).unwrap();
        assert!(c.verify_floor(&highwater).is_err());
        assert_eq!(c.committed_response(&hexhash('f')).unwrap(),None);
    }
}


// v0.24 real loopback TLS/mTLS coordinator RPC with host-bound SPKI pins.
// Two clients have distinct X.509 keys. No independent deployed host, quorum,
// HSM custody, or canonical writes are claimed by these tests.
#[cfg(feature="tls-transport")]
mod network_fencing_tests{
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Barrier;
    use galia_core_shadow::fenced_coordinator::*;
    use galia_core_shadow::network_fencing::*;

    type Credential=(CertificateDer<'static>,Vec<u8>);
    struct Network{
        _temp:tempfile::TempDir,
        coordinator:Arc<DurableFencingCoordinator>,
        server:Arc<TlsFencingRpcServer>,
        server_root:RootCertStore,
        server_spki:String,
        scope:FencingScope,
        host_a:Credential,
        host_b:Credential,
        rogue:Credential,
    }
    fn credential(name:&str)->Credential{
        let item=generate_simple_self_signed(vec![name.into()]).unwrap();
        (item.cert.der().clone(),item.signing_key.serialize_der())
    }
    fn spki(cert:&CertificateDer<'_>)->String{
        let (_,parsed)=x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        sha256(parsed.public_key().raw)
    }
    fn net(x:&TestContext)->Network{
        let temp=tempfile::tempdir().unwrap();
        let scope=FencingScope{
            namespace:x.trust.checkpoint.namespace.clone(),
            case_id:x.trust.checkpoint.case_id.clone(),
            service_id:x.trust.service_id.clone(),
            pinned_observer_policy_sha256:policy_digest(&x.policy).unwrap(),
            pinned_response_signer_public_key_hex:x.trust.response_signer_public_key_hex.clone(),
        };
        let coordinator=Arc::new(DurableFencingCoordinator::initialize_new(
            temp.path().join("rpc-coordinator"),scope.clone()).unwrap());
        let server_cert=credential("localhost");
        let a=credential("host-a.local");
        let b=credential("host-b.local");
        let rogue=credential("rogue.local");
        let mut clients=RootCertStore::empty();
        for cert in [&a.0,&b.0,&rogue.0]{clients.add((*cert).clone()).unwrap();}
        let mut roots=RootCertStore::empty();
        roots.add(server_cert.0.clone()).unwrap();
        let mut pins=BTreeMap::new();
        pins.insert("host-a".into(),spki(&a.0));
        pins.insert("host-b".into(),spki(&b.0));
        let server=Arc::new(TlsFencingRpcServer::new(
            Arc::clone(&coordinator),
            vec![server_cert.0.clone()],
            PrivatePkcs8KeyDer::from(server_cert.1).into(),
            clients,pins,Duration::from_secs(5)).unwrap());
        Network{_temp:temp,coordinator,server,server_root:roots,
            server_spki:spki(&server_cert.0),
            scope,host_a:a,host_b:b,rogue}
    }
    fn start_rpc(server:Arc<TlsFencingRpcServer>,count:usize)
        ->(SocketAddr,thread::JoinHandle<Vec<Result<(),String>>>){
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let addr=listener.local_addr().unwrap();
        let join=thread::spawn(move||{
            let workers=(0..count).map(|_|{
                let (socket,_)=listener.accept().unwrap();
                let server=Arc::clone(&server);
                thread::spawn(move||server.serve_one(socket))
            }).collect::<Vec<_>>();
            workers.into_iter().map(|w|w.join().unwrap()).collect()
        });
        (addr,join)
    }
    fn remote(n:&Network,addr:SocketAddr,id:&str,cred:&Credential,
        pin:Option<&str>,scope:Option<FencingScope>)->RemoteTlsFencingAuthority{
        RemoteTlsFencingAuthority::new(
            addr,"localhost",n.server_root.clone(),vec![cred.0.clone()],
            PrivatePkcs8KeyDer::from(cred.1.clone()).into(),
            pin.unwrap_or(&n.server_spki).into(),
            scope.unwrap_or_else(||n.scope.clone()),id,Duration::from_secs(5)
        ).unwrap()
    }
    fn signed_response(x:&TestContext,nonce:char)->String{
        let payload=RemoteCheckpointPayload{
            format:RESPONSE_FORMAT.into(),service_id:x.trust.service_id.clone(),
            signer_id:x.trust.response_signer_id.clone(),
            challenge_sha256:hexhash('a'),nonce_sha256:hexhash(nonce),
            tls_exporter_sha256:hexhash('b'),
            signed_at_unix_seconds:1_800_000_030,
            checkpoint_chain:x.store.checkpoint_suffix(0,None).unwrap(),
        };
        String::from_utf8(canon(&SignedRemoteCheckpointResponse{
            signature_hex:sign(92,RESPONSE_DOMAIN,&payload),payload,
        })).unwrap()
    }
    #[test]fn remote_tls_host_a_authenticated_commit_and_durable_readback(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert_eq!(client.scope().unwrap(),n.scope);
        let record=signed_response(&x,'1');
        let commit=client.commit_response(&token,&hexhash('1'),&record).unwrap();
        assert!(commit.durable_scratch_record_committed);
        assert!(!commit.cross_host_consensus_verified);
        assert!(!commit.canonical_writeback&&!commit.human_authority_verified);
        assert!(done.join().unwrap().iter().all(|x|x.is_ok()));
        assert_eq!(n.coordinator.committed_response(&hexhash('1')).unwrap(),Some(record));
    }
    #[test]fn certificate_for_b_cannot_impersonate_epoch_holder_a(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        // Locally claim host-a but PRESENT host-b certificate to the TLS server.
        // This must reach server-side pin enforcement rather than short-circuit locally.
        let b=remote(&n,addr,"host-a",&n.host_b,None,None);
        assert!(b.commit_response(&token,&hexhash('2'),&signed_response(&x,'2')).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn certificate_trusted_by_ca_but_not_on_host_allowlist_is_denied(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let rogue=remote(&n,addr,"host-a",&n.rogue,None,None);
        assert!(rogue.commit_response(&token,&hexhash('3'),&signed_response(&x,'3')).is_err());
        assert!(done.join().unwrap().iter().any(|r|r.is_err()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn authenticated_server_certificate_with_wrong_spki_pin_is_rejected(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,Some(&hexhash('f')),None);
        assert!(client.commit_response(&token,&hexhash('4'),&signed_response(&x,'4')).is_err());
        let _=done.join().unwrap();
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn bad_remote_scope_is_rejected_and_never_commits(){
        let x=build();let n=net(&x);
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let mut wrong=n.scope.clone();wrong.case_id="different".into();
        let client=remote(&n,addr,"host-a",&n.host_a,None,Some(wrong));
        assert!(client.scope().is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().record_count,0);
    }
    #[test]fn disconnected_coordinator_must_fail_without_a_local_claim_fallback(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let addr=listener.local_addr().unwrap();
        drop(listener);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert!(client.scope().is_err());
        assert!(client.commit_response(&token,&hexhash('5'),&signed_response(&x,'5')).is_err());
        assert!(client.claim(&token,&hexhash('5')).is_err());
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn remote_commit_rejects_prepared_old_epoch_after_owner_change(){
        let x=build();let n=net(&x);
        let old=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let prepared=signed_response(&x,'6');
        let _new=n.coordinator.advance_epoch(1,"host-b").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let a=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert!(a.commit_response(&old,&hexhash('6'),&prepared).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert!(n.coordinator.committed_response(&hexhash('6')).unwrap().is_none());
    }
    #[test]fn two_simultaneous_authenticated_clients_same_holder_nonce_one_wins(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let barrier=Arc::new(Barrier::new(3));
        let jobs=(0..2).map(|_|{
            let client=remote(&n,addr,"host-a",&n.host_a,None,None);
            let token=token.clone();let b=Arc::clone(&barrier);
            let response=signed_response(&x,'7');
            thread::spawn(move||{
                b.wait();
                client.commit_response(&token,&hexhash('7'),&response).is_ok()
            })
        }).collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(jobs.into_iter().map(|j|j.join().unwrap()).filter(|won|*won).count(),1);
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn remote_claim_only_is_disabled_even_when_server_is_reachable(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let unused=TcpListener::bind("127.0.0.1:0").unwrap();
        let client=remote(&n,unused.local_addr().unwrap(),"host-a",&n.host_a,None,None);
        assert!(client.claim(&token,&hexhash('8')).is_err());
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn remote_adapter_drives_real_tls_checkpoint_service_guarded_mode(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (rpc_addr,done)=start_rpc(Arc::clone(&n.server),2);
        let authority:Arc<dyn FencingAuthority>=Arc::new(
            remote(&n,rpc_addr,"host-a",&n.host_a,None,None));
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let checkpoint_addr=listener.local_addr().unwrap();
        let service=Arc::clone(&x.server);
        let joined=thread::spawn(move||{
            let (socket,_)=listener.accept().unwrap();
            service.serve_one_commit_guarded(socket,1_800_000_030,
                authority.as_ref(),&token)
        });
        let (challenge,peer,response)=x.client.exchange(checkpoint_addr,
            &x.trust,&x.policy,&hexhash('9'),1_800_000_000,1_800_000_060).unwrap();
        assert!(joined.join().unwrap().is_ok());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert!(verify_remote_exchange(&x.board,&x.policy,&x.trust,
            &challenge,&peer,&response,1_800_000_040).is_ok());
        assert_eq!(x.store.inspect().unwrap(),(1,0));
        assert!(n.coordinator.committed_response(&hexhash('9')).unwrap().is_some());
    }

    // v0.25: authenticated, host-scoped read-only recovery after an
    // ambiguous/forgotten commit acknowledgement, never a new nonce spend.
    #[test]fn authenticated_origin_recovers_original_response_without_new_commit(){
        let x=build();let n=net(&x);
        let grant=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'a');
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        let _forgotten_ack=client.commit_response(&grant,&hexhash('a'),&response).unwrap();
        let before=n.coordinator.checkpoint().unwrap();
        let recovered=client.recover_committed(
            &hexhash('a'),&sha256(response.as_bytes())).unwrap();
        assert_eq!(recovered,response);
        assert_eq!(n.coordinator.checkpoint().unwrap(),before);
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
    }
    #[test]fn old_owner_can_only_read_its_prior_commit_after_epoch_rotation(){
        let x=build();let n=net(&x);
        let a=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'b');
        n.coordinator.commit_response(&a,&hexhash('b'),&response).unwrap();
        let _b=n.coordinator.advance_epoch(1,"host-b").unwrap();
        let previous=n.coordinator.checkpoint().unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert_eq!(client.recover_committed(
            &hexhash('b'),&sha256(response.as_bytes())).unwrap(),response);
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap(),previous);
    }
    #[test]fn different_authenticated_host_cannot_read_origins_receipt(){
        let x=build();let n=net(&x);
        let a=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'c');
        n.coordinator.commit_response(&a,&hexhash('c'),&response).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let other=remote(&n,addr,"host-b",&n.host_b,None,None);
        assert!(other.recover_committed(&hexhash('c'),&sha256(response.as_bytes())).is_err());
        let actual=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert_eq!(actual.recover_committed(
            &hexhash('c'),&sha256(response.as_bytes())).unwrap(),response);
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn unpinned_tls_client_cannot_recover_receipt_even_with_digest(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'d');
        n.coordinator.commit_response(&token,&hexhash('d'),&response).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let rogue=remote(&n,addr,"host-a",&n.rogue,None,None);
        assert!(rogue.recover_committed(&hexhash('d'),&sha256(response.as_bytes())).is_err());
        assert!(done.join().unwrap().iter().any(|r|r.is_err()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn original_response_digest_is_mandatory_and_must_match(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'e');
        n.coordinator.commit_response(&token,&hexhash('e'),&response).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert!(client.recover_committed(&hexhash('e'),&hexhash('f')).is_err());
        // Invalid hashes reject before any connection; one real RPC above.
        assert!(client.recover_committed("bad",&sha256(response.as_bytes())).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn unknown_or_claim_only_nonce_never_recovered_or_recommitted(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        n.coordinator.claim(&token,&hexhash('f')).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert!(client.recover_committed(&hexhash('f'),&hexhash('a')).is_err());
        assert!(client.recover_committed(&hexhash('9'),&hexhash('a')).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn coordinator_network_partition_prevents_read_only_recovery(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'1');
        n.coordinator.commit_response(&token,&hexhash('1'),&response).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let address=listener.local_addr().unwrap();drop(listener);
        let client=remote(&n,address,"host-a",&n.host_a,None,None);
        assert!(client.recover_committed(
            &hexhash('1'),&sha256(response.as_bytes())).is_err());
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn wrong_server_spki_refuses_recovery_after_handshake(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'2');
        n.coordinator.commit_response(&token,&hexhash('2'),&response).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,Some(&hexhash('f')),None);
        assert!(client.recover_committed(
            &hexhash('2'),&sha256(response.as_bytes())).is_err());
        let _=done.join().unwrap();
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn different_pinned_service_verification_key_rejects_recovery(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'3');
        n.coordinator.commit_response(&token,&hexhash('3'),&response).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let mut invalid=n.scope.clone();
        invalid.pinned_response_signer_public_key_hex=pk(99);
        let client=remote(&n,addr,"host-a",&n.host_a,None,Some(invalid));
        assert!(client.recover_committed(
            &hexhash('3'),&sha256(response.as_bytes())).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn damaged_commit_record_blocks_read_only_recovery(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'4');
        n.coordinator.commit_response(&token,&hexhash('4'),&response).unwrap();
        std::fs::write(n._temp.path()
            .join("rpc-coordinator/journal/00000000000000000002.json"),b"{").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None);
        assert!(client.recover_committed(
            &hexhash('4'),&sha256(response.as_bytes())).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert!(n.coordinator.checkpoint().is_err());
    }
    #[test]fn two_simultaneous_origin_lookups_are_read_only(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'5');
        n.coordinator.commit_response(&token,&hexhash('5'),&response).unwrap();
        let checkpoint=n.coordinator.checkpoint().unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let barrier=Arc::new(Barrier::new(3));
        let jobs=(0..2).map(|_|{
            let client=remote(&n,addr,"host-a",&n.host_a,None,None);
            let digest=sha256(response.as_bytes());
            let expected=response.clone();
            let ready=Arc::clone(&barrier);
            thread::spawn(move||{
                ready.wait();
                client.recover_committed(&hexhash('5'),&digest).map(|s|s==expected).unwrap_or(false)
            })
        }).collect::<Vec<_>>();
        barrier.wait();
        assert!(jobs.into_iter().all(|j|j.join().unwrap()));
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap(),checkpoint);
    }
    #[test]fn explicit_full_scratch_rollback_still_needs_external_anchor(){
        let x=build();let n=net(&x);
        let grant=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let response=signed_response(&x,'6');
        n.coordinator.commit_response(&grant,&hexhash('6'),&response).unwrap();
        let highwater=n.coordinator.checkpoint().unwrap();
        std::fs::remove_file(n._temp.path()
            .join("rpc-coordinator/journal/00000000000000000002.json")).unwrap();
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
        assert!(n.coordinator.verify_floor(&highwater).is_err());
    }

    // v0.26: synthetic high-water store held OUTSIDE the coordinator's
    // attackable filesystem, but only in memory in these tests. This tests
    // the CAS contract; it does NOT deploy independent durable custody.
    struct MemoryAnchor{
        scope:FencingScope,
        current:std::sync::Mutex<FencingCheckpoint>,
        blocked:std::sync::Mutex<bool>,
    }
    impl MemoryAnchor{
        fn new(n:&Network)->Self{
            Self{
                scope:n.scope.clone(),
                current:std::sync::Mutex::new(n.coordinator.checkpoint().unwrap()),
                blocked:std::sync::Mutex::new(false),
            }
        }
        fn block(&self){*self.blocked.lock().unwrap()=true;}
        fn snapshot(&self)->FencingCheckpoint{self.current.lock().unwrap().clone()}
    }
    impl IndependentMonotonicFencingAnchor for MemoryAnchor{
        fn current(&self,scope:&FencingScope)->Result<FencingCheckpoint,String>{
            if scope!=&self.scope||*self.blocked.lock().unwrap(){
                return Err("independently held checkpoint unavailable/mismatched".into())
            }
            Ok(self.snapshot())
        }
        fn advance(&self,scope:&FencingScope,old:&FencingCheckpoint,
            next:&FencingCheckpoint)->Result<(),String>{
            if scope!=&self.scope||*self.blocked.lock().unwrap(){
                return Err("independent highwater CAS partitioned".into())
            }
            let mut floor=self.current.lock().unwrap();
            if *floor!=*old||next.record_count!=old.record_count+1||
                next.journal_tip_sha256==old.journal_tip_sha256{
                return Err("independent highwater mismatch/rollback/invalid successor".into())
            }
            *floor=next.clone();
            Ok(())
        }
    }
    fn enable(n:&Network)->Arc<MemoryAnchor>{
        let a=Arc::new(MemoryAnchor::new(n));
        let pinned:Arc<dyn IndependentMonotonicFencingAnchor>=a.clone();
        n.server.enable_strict_external_anchor(pinned).unwrap();
        a
    }
    #[test]fn strict_external_anchor_server_commit_advances_both_cas_and_local_log(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let grant=n.coordinator.advance_epoch_anchored(0,"host-a",anchor.as_ref()).unwrap();
        assert_eq!(anchor.snapshot(),n.coordinator.checkpoint().unwrap());
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None).require_external_anchor();
        let record=signed_response(&x,'a');
        let receipt=client.commit_response(&grant,&hexhash('a'),&record).unwrap();
        assert_eq!(receipt.status,"EXTERNALLY_CAS_ACKNOWLEDGED_SCRATCH_COMMIT_ONLY");
        assert!(!receipt.canonical_writeback&&!receipt.human_authority_verified);
        assert_eq!(client.recover_committed(&hexhash('a'),&sha256(record.as_bytes())).unwrap(),record);
        assert!(done.join().unwrap().iter().all(|v|v.is_ok()));
        assert_eq!(anchor.snapshot(),n.coordinator.checkpoint().unwrap());
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
    #[test]fn strict_server_rejects_snapshot_rollback_before_serving_recovery(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let grant=n.coordinator.advance_epoch_anchored(0,"host-a",anchor.as_ref()).unwrap();
        let response=signed_response(&x,'b');
        n.coordinator.commit_response_anchored(&grant,&hexhash('b'),&response,
            anchor.as_ref()).unwrap();
        let highwater=anchor.snapshot();
        std::fs::remove_file(n._temp.path()
            .join("rpc-coordinator/journal/00000000000000000002.json")).unwrap();
        assert!(n.coordinator.verify_floor(&highwater).is_err());
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None).require_external_anchor();
        assert!(client.recover_committed(&hexhash('b'),&sha256(response.as_bytes())).is_err());
        assert!(done.join().unwrap().iter().any(|v|v.is_err()));
        assert_eq!(anchor.snapshot(),highwater);
    }
    #[test]fn external_anchor_partition_denies_prepared_signed_commit_without_local_write(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let grant=n.coordinator.advance_epoch_anchored(0,"host-a",anchor.as_ref()).unwrap();
        anchor.block();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None).require_external_anchor();
        assert!(client.commit_response(&grant,&hexhash('c'),&signed_response(&x,'c')).is_err());
        assert!(done.join().unwrap().iter().any(|v|v.is_err()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn non_anchored_legacy_mutation_blocks_all_strict_rpc_requests(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let grant=n.coordinator.advance_epoch(0,"host-a").unwrap();
        assert_ne!(anchor.snapshot(),n.coordinator.checkpoint().unwrap());
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None).require_external_anchor();
        assert!(client.commit_response(&grant,&hexhash('d'),&signed_response(&x,'d')).is_err());
        assert!(done.join().unwrap().iter().any(|v|v.is_err()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,0);
    }
    #[test]fn strict_mode_activation_rejects_stale_or_wrongly_scoped_floor(){
        let x=build();let n=net(&x);
        n.coordinator.advance_epoch(0,"host-a").unwrap();
        let mut wrong=MemoryAnchor::new(&n);
        wrong.scope.case_id="wrong".into();
        let pin:Arc<dyn IndependentMonotonicFencingAnchor>=Arc::new(wrong);
        assert!(n.server.enable_strict_external_anchor(pin).is_err());
        let a=Arc::new(MemoryAnchor::new(&n));
        let p:Arc<dyn IndependentMonotonicFencingAnchor>=a.clone();
        n.server.enable_strict_external_anchor(p).unwrap();
        let p:Arc<dyn IndependentMonotonicFencingAnchor>=a;
        assert!(n.server.enable_strict_external_anchor(p).is_err());
    }
    #[test]fn two_clients_one_nonce_one_external_highwater_advance(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let token=n.coordinator.advance_epoch_anchored(0,"host-a",anchor.as_ref()).unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),2);
        let barrier=Arc::new(Barrier::new(3));
        let attempts=(0..2).map(|_|{
            let client=remote(&n,addr,"host-a",&n.host_a,None,None).require_external_anchor();
            let grant=token.clone();let body=signed_response(&x,'e');
            let barrier=Arc::clone(&barrier);
            thread::spawn(move||{barrier.wait();
                client.commit_response(&grant,&hexhash('e'),&body).is_ok()
            })
        }).collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(attempts.into_iter().map(|j|j.join().unwrap()).filter(|v|*v).count(),1);
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap(),anchor.snapshot());
        assert_eq!(anchor.snapshot().nonce_claim_count,1);
    }
    #[test]fn anchor_advanced_but_local_write_missing_requires_manual_repair(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let grant=n.coordinator.advance_epoch_anchored(0,"host-a",anchor.as_ref()).unwrap();
        let old=anchor.snapshot();
        let mut promised=old.clone();
        promised.record_count+=1;promised.nonce_claim_count+=1;
        promised.journal_tip_sha256=Some(hexhash('f'));
        // This simulates external CAS durably succeeding before a crash stops
        // local create_new/fsync. Automatic retry MUST NOT clear the pin.
        anchor.advance(&n.scope,&old,&promised).unwrap();
        let current=n.coordinator.checkpoint().unwrap();
        assert_eq!(current,old);
        assert!(n.coordinator.commit_response_anchored(
            &grant,&hexhash('f'),&signed_response(&x,'f'),anchor.as_ref()).is_err());
        assert_eq!(n.coordinator.checkpoint().unwrap(),current);
        assert_eq!(anchor.snapshot(),promised);
    }
    #[test]fn strict_anchor_after_two_epochs_stale_grant_rejected_at_commit_boundary(){
        let x=build();let n=net(&x);
        let anchor=enable(&n);
        let old=n.coordinator.advance_epoch_anchored(0,"host-a",anchor.as_ref()).unwrap();
        let content=signed_response(&x,'1');
        let _new=n.coordinator.advance_epoch_anchored(1,"host-b",anchor.as_ref()).unwrap();
        assert!(n.coordinator.commit_response_anchored(
            &old,&hexhash('1'),&content,anchor.as_ref()).is_err());
        assert_eq!(anchor.snapshot(),n.coordinator.checkpoint().unwrap());
    }
    #[test]fn client_can_demand_anchor_receipt_and_reject_legacy_server_commit(){
        let x=build();let n=net(&x);
        let token=n.coordinator.advance_epoch(0,"host-a").unwrap();
        let (addr,done)=start_rpc(Arc::clone(&n.server),1);
        let client=remote(&n,addr,"host-a",&n.host_a,None,None).require_external_anchor();
        // Legacy server STILL writes in this test: this proves a strict
        // client-side status rejection is NOT the same as server enforcement.
        assert!(client.commit_response(&token,&hexhash('2'),&signed_response(&x,'2')).is_err());
        assert!(done.join().unwrap().iter().all(|r|r.is_ok()));
        assert_eq!(n.coordinator.checkpoint().unwrap().nonce_claim_count,1);
    }
}
