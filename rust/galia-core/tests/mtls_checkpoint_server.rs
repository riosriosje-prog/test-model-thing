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
    let r1=x.client.exchange(a,&x.trust,&x.policy,
        &hexhash('3'),1_800_000_000,1_800_000_060);
    let r2=x.client.exchange(b,&x.trust,&x.policy,
        &hexhash('3'),1_800_000_000,1_800_000_060);
    assert_eq!(usize::from(r1.is_ok())+usize::from(r2.is_ok()),1);
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
