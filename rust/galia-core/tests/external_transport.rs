#![cfg(feature="scratch-store")]
//! v0.16 boundary simulations. The peer evidence is an *input* in these
//! fixtures and cannot establish that TLS, mTLS, KMS or a remote host exists.
use ed25519_dalek::{Signer,SigningKey};
use galia_core_shadow::attestation::signing_preimage;
use galia_core_shadow::audit::sha256;
use galia_core_shadow::external_checkpoint::*;
use galia_core_shadow::external_transport::*;
use galia_core_shadow::transparency::*;
use galia_core_shadow::transparency_board::*;
use galia_core_shadow::witness::*;
use galia_core_shadow::witness_proof::*;
fn signing_key(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
fn pubkey(seed:u8)->String{hex::encode(signing_key(seed).verifying_key().to_bytes())}
fn sign<T:serde::Serialize>(seed:u8,domain:&[u8],v:&T)->String{
    hex::encode(signing_key(seed).sign(&signing_preimage(domain,v).unwrap()).to_bytes())
}
fn h(c:char)->String{std::iter::repeat(c).take(64).collect()}
fn canonical<T:serde::Serialize>(v:&T)->Vec<u8>{
    serde_json::to_value(v).and_then(|x|serde_json::to_vec(&x)).unwrap()
}
fn roster()->ObserverPolicy{
    ObserverPolicy{
        witness_anchor:WitnessTrustAnchor{
            signer_key_id:"w1".into(),pinned_witness_public_key_hex:pubkey(33),
            pinned_review_root_public_key_hex:pubkey(7),
            expected_namespace:"tenant".into(),expected_case_id:"cangrejos".into(),
            minimum_registry_epoch:10,minimum_spent_count:0,floor_tip_sha256:None
        },
        roster_epoch:3,required_quorum:2,
        observers:vec![
            TrustedObserver{observer_id:"a".into(),public_key_hex:pubkey(51),revoked:false},
            TrustedObserver{observer_id:"b".into(),public_key_hex:pubkey(52),revoked:false},
        ]
    }
}
fn publication()->PublishedWitnessView{
    let observation=WitnessObservation{
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        registry_epoch:10,spent_count:0,tip_sha256:None,
    };
    let signed=SignedWitnessObservation{
        signer_key_id:"w1".into(),
        signature_hex:sign(33,OBSERVATION_DOMAIN,&observation),observation,
    };
    let hash=sha256(&canonical(&signed));
    let endorsements=[("a",51),("b",52)].into_iter().map(|(id,seed)|{
        let payload=GossipEndorsementPayload{
            format:GOSSIP_FORMAT.into(),roster_epoch:3,
            observer_id:id.into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
            witness_observation_sha256:hash.clone(),
            spent_count:0,tip_sha256:None,registry_epoch:10,
        };
        SignedGossipEndorsement{signature_hex:sign(seed,GOSSIP_DOMAIN,&payload),payload}
    }).collect();
    PublishedWitnessView{signed_observation:signed,endorsements}
}
struct Fixture{
    _temporary:tempfile::TempDir,
    board:DurableTransparencyBoard,
    policy:ObserverPolicy,
    trust:ExternalServiceTrust,
    challenge:RemoteCheckpointChallenge,
    peer:TransportPeerEvidence,
    response:SignedRemoteCheckpointResponse,
}
fn fixture()->Fixture{
    let directory=tempfile::tempdir().unwrap();
    let policy=roster();
    let board=DurableTransparencyBoard::initialize_new(
        directory.path().join("scratch-board"),policy.clone()).unwrap();
    board.publish(publication(),None).unwrap();
    let checkpoint_trust=CheckpointAnchorTrust{
        external_signer_id:"external-auditor".into(),
        external_signer_public_key_hex:pubkey(91),
        stream_id:"stream-galia".into(),
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        pinned_observer_policy_sha256:policy_digest(&policy).unwrap(),
        floor_sequence:0,floor_envelope_sha256:None,
        floor_board:BoardCheckpoint{
            journal_count:0,journal_tip_sha256:None,quarantined:false
        }
    };
    let checkpoint_payload=ExternalBoardCheckpointPayload{
        format:CHECKPOINT_FORMAT.into(),external_signer_id:"external-auditor".into(),
        stream_id:"stream-galia".into(),namespace:"tenant".into(),case_id:"cangrejos".into(),
        observer_policy_sha256:policy_digest(&policy).unwrap(),
        sequence:1,previous_envelope_sha256:None,
        board:board.checkpoint().unwrap(),quarantined_evidence_sha256:None,
    };
    let checkpoint=SignedExternalBoardCheckpoint{
        signature_hex:sign(91,CHECKPOINT_DOMAIN,&checkpoint_payload),
        payload:checkpoint_payload,
    };
    let trust=ExternalServiceTrust{
        checkpoint:checkpoint_trust,
        service_id:"checkpoint-service-a".into(),
        response_signer_id:"service-key-a".into(),
        response_signer_public_key_hex:pubkey(92),
        pinned_tls_peer_spki_sha256:h('a'),
        max_challenge_seconds:60,
    };
    let challenge=RemoteCheckpointChallenge{
        format:REQUEST_FORMAT.into(),service_id:trust.service_id.clone(),
        stream_id:trust.checkpoint.stream_id.clone(),
        namespace:"tenant".into(),case_id:"cangrejos".into(),
        nonce_sha256:h('c'),floor_sequence:0,
        floor_envelope_sha256:None,tls_exporter_sha256:h('b'),
        issued_at_unix_seconds:1_800_000_000,
        expires_at_unix_seconds:1_800_000_060,
    };
    let peer=TransportPeerEvidence{
        tls_peer_spki_sha256:h('a'),tls_exporter_sha256:h('b'),
        mutual_tls_client_authenticated:true,
    };
    let payload=RemoteCheckpointPayload{
        format:RESPONSE_FORMAT.into(),service_id:trust.service_id.clone(),
        signer_id:trust.response_signer_id.clone(),
        challenge_sha256:sha256(&canonical(&challenge)),
        nonce_sha256:challenge.nonce_sha256.clone(),
        tls_exporter_sha256:peer.tls_exporter_sha256.clone(),
        signed_at_unix_seconds:1_800_000_020,
        checkpoint_chain:vec![checkpoint],
    };
    let response=SignedRemoteCheckpointResponse{
        signature_hex:sign(92,RESPONSE_DOMAIN,&payload),payload,
    };
    Fixture{_temporary:directory,board,policy,trust,challenge,peer,response}
}
fn check(x:&Fixture)->Result<RemoteCheckpointAssessment,String>{
    verify_remote_exchange(&x.board,&x.policy,&x.trust,&x.challenge,
        &x.peer,&x.response,1_800_000_040)
}
fn resign(x:&mut Fixture){
    x.response.signature_hex=sign(92,RESPONSE_DOMAIN,&x.response.payload);
}
#[test]fn signed_response_bound_to_checkpoint_and_claimed_mtls_passes_advisory(){
    let x=fixture();let report=check(&x).unwrap();
    assert_eq!(report.checkpoint_count,1);
    assert_eq!(report.terminal_sequence,1);
    assert!(report.challenge_binding_verified&&report.claimed_tls_identity_matched);
    assert!(!report.external_service_deployed_verified);
    assert!(!report.independent_key_custody_verified);
    assert!(!report.real_human_identity_verified&&!report.human_authority_verified);
    assert!(!report.executable_guards_issued&&!report.authority_transfer&&!report.canonical_writeback);
}
#[test]fn signer_credential_substitution_and_role_confusion_fail_closed(){
    let mut x=fixture();
    x.response.signature_hex=sign(93,RESPONSE_DOMAIN,&x.response.payload);
    assert!(check(&x).is_err());
    let mut x=fixture();
    x.trust.response_signer_public_key_hex=x.trust.checkpoint.external_signer_public_key_hex.clone();
    assert!(check(&x).is_err());
    let mut x=fixture();
    x.trust.response_signer_public_key_hex=pubkey(51);
    assert!(check(&x).is_err());
}
#[test]fn peer_tls_spki_and_mutual_auth_are_required(){
    let mut x=fixture();x.peer.tls_peer_spki_sha256=h('f');
    assert!(check(&x).is_err());
    let mut x=fixture();x.peer.mutual_tls_client_authenticated=false;
    assert!(check(&x).is_err());
    let mut x=fixture();x.trust.pinned_tls_peer_spki_sha256=h('f');
    assert!(check(&x).is_err());
}
#[test]fn tls_exporter_channel_binding_rejects_replayed_connection(){
    let mut x=fixture();x.peer.tls_exporter_sha256=h('d');
    assert!(check(&x).is_err());
    let mut x=fixture();x.challenge.tls_exporter_sha256=h('d');
    assert!(check(&x).is_err());
    let mut x=fixture();x.response.payload.tls_exporter_sha256=h('d');
    resign(&mut x);assert!(check(&x).is_err());
}
#[test]fn challenge_nonce_and_request_digest_prevent_cross_request_replay(){
    let mut x=fixture();x.challenge.nonce_sha256=h('d');
    assert!(check(&x).is_err());
    let mut x=fixture();x.response.payload.nonce_sha256=h('d');
    resign(&mut x);assert!(check(&x).is_err());
    let mut x=fixture();x.response.payload.challenge_sha256=h('e');
    resign(&mut x);assert!(check(&x).is_err());
}
#[test]fn pinned_stream_namespace_case_and_service_are_immutable(){
    let mut x=fixture();x.challenge.service_id="another-service".into();
    assert!(check(&x).is_err());
    let mut x=fixture();x.response.payload.service_id="another-service".into();
    resign(&mut x);assert!(check(&x).is_err());
    let mut x=fixture();x.challenge.case_id="wrong".into();
    assert!(check(&x).is_err());
    let mut x=fixture();x.challenge.stream_id="other-stream".into();
    assert!(check(&x).is_err());
}
#[test]fn challenge_ttl_expiry_future_and_signed_time_rejected(){
    let mut x=fixture();x.challenge.expires_at_unix_seconds=1_800_000_400;
    assert!(check(&x).is_err());
    let mut x=fixture();x.challenge.issued_at_unix_seconds=1_800_000_045;
    assert!(check(&x).is_err());
    let mut x=fixture();x.response.payload.signed_at_unix_seconds=1_800_000_050;
    resign(&mut x);assert!(check(&x).is_err());
    let x=fixture();
    assert!(verify_remote_exchange(&x.board,&x.policy,&x.trust,&x.challenge,
        &x.peer,&x.response,1_800_000_061).is_err());
}
#[test]fn forged_checkpoint_inside_authentic_service_response_rejected(){
    let mut x=fixture();
    x.response.payload.checkpoint_chain[0].signature_hex=
        sign(99,CHECKPOINT_DOMAIN,&x.response.payload.checkpoint_chain[0].payload);
    resign(&mut x);
    assert!(check(&x).is_err());
    let mut x=fixture();
    x.response.payload.checkpoint_chain[0].payload.board.journal_tip_sha256=Some(h('f'));
    x.response.payload.checkpoint_chain[0].signature_hex=
        sign(91,CHECKPOINT_DOMAIN,&x.response.payload.checkpoint_chain[0].payload);
    resign(&mut x);
    assert!(check(&x).is_err());
}
#[test]fn missing_checkpoint_and_nonmatching_roster_rejected(){
    let mut x=fixture();
    x.response.payload.checkpoint_chain.clear();resign(&mut x);
    assert!(check(&x).is_err());
    let mut x=fixture();
    x.policy.roster_epoch=4;
    assert!(check(&x).is_err());
}
#[test]fn full_board_truncation_detected_despite_correct_remote_signatures(){
    let x=fixture();
    let filename=x._temporary.path()
        .join("scratch-board/publications/00000000000000000001.json");
    std::fs::remove_file(filename).unwrap();
    assert_eq!(x.board.inspect().unwrap().journal_count,0);
    assert!(check(&x).is_err());
}
struct MockRemote{
    evidence:TransportPeerEvidence,
    response:SignedRemoteCheckpointResponse,
    fail:bool,
}
impl RemoteCheckpointTransport for MockRemote{
    fn exchange(&self,_challenge:&RemoteCheckpointChallenge)
        ->Result<(TransportPeerEvidence,SignedRemoteCheckpointResponse),String>{
        if self.fail{return Err("simulated partition / no peer connection".into())}
        Ok((self.evidence.clone(),self.response.clone()))
    }
}
#[test]fn transport_partition_fails_without_promoting_or_writing(){
    let x=fixture();
    let mock=MockRemote{evidence:x.peer.clone(),response:x.response.clone(),fail:true};
    assert!(fetch_and_verify(&x.board,&x.policy,&x.trust,&x.challenge,
        &mock,1_800_000_040).is_err());
    assert_eq!(x.board.inspect().unwrap().journal_count,1);
    let mock=MockRemote{evidence:x.peer.clone(),response:x.response.clone(),fail:false};
    let result=fetch_and_verify(&x.board,&x.policy,&x.trust,&x.challenge,
        &mock,1_800_000_040).unwrap();
    assert!(!result.canonical_writeback);
}
#[test]fn serializing_injected_unknown_authority_field_rejected(){
    let x=fixture();
    let mut value=serde_json::to_value(&x.response).unwrap();
    value["payload"]["human_promoted"]=serde_json::json!(true);
    assert!(serde_json::from_value::<SignedRemoteCheckpointResponse>(value).is_err());
}
#[test]fn duplicate_valid_transcript_is_not_global_replay_protected(){
    let x=fixture();
    // Formal limitation: repeated verification within a still-open challenge
    // succeeds; independent nonce registry/monotonic host policy is mandatory.
    assert!(check(&x).is_ok());
    assert!(check(&x).is_ok());
}
