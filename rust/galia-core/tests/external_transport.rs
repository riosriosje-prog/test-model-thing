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


// v0.17 LOCAL SCRATCH-ONLY atomic replay fence: this is not distributed anti-replay.
mod durable_replay_tests {
    use super::*;
    use std::sync::{Arc,Barrier};
    use std::thread;
    use galia_core_shadow::replay_fence::DurableTranscriptReplayFence;

    fn open_new(x:&Fixture)->DurableTranscriptReplayFence{
        DurableTranscriptReplayFence::initialize_new(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).unwrap()
    }
    fn new_nonce(x:&mut Fixture,character:char){
        x.challenge.nonce_sha256=h(character);
        x.response.payload.nonce_sha256=x.challenge.nonce_sha256.clone();
        x.response.payload.challenge_sha256=sha256(&canonical(&x.challenge));
        resign(x);
    }
    #[test]fn same_valid_transcript_rejected_on_second_accept(){
        let x=fixture();let fence=open_new(&x);
        let one=fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).unwrap();
        assert_eq!(one.accepted_count,1);
        assert!(one.scratch_consumed);
        assert!(!one.real_transport_authenticated);
        assert!(!one.independently_trusted_clock_verified);
        assert!(!one.independently_pinned_rollback_anchor_verified);
        assert!(!one.human_authority_verified&&!one.canonical_writeback);
        assert!(!one.authority_transfer);
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_err());
        assert_eq!(fence.inspect().unwrap().0,1);
    }
    #[test]fn replay_is_denied_after_store_reopened_from_disk(){
        let x=fixture();let fence=open_new(&x);
        fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).unwrap();
        drop(fence);
        let reopened=DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).unwrap();
        assert!(reopened.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_err());
        assert_eq!(reopened.inspect().unwrap().0,1);
    }
    #[test]fn two_independent_handles_same_nonce_have_one_winner(){
        let x=Arc::new(fixture());let left=open_new(&x);
        let right=DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).unwrap();
        let b=Arc::new(Barrier::new(3));
        let tasks=[left,right].into_iter().map(|fence|{
            let xx=Arc::clone(&x);let barrier=Arc::clone(&b);
            thread::spawn(move||{
                barrier.wait();
                fence.accept_verified(&xx.board,&xx.policy,&xx.trust,&xx.challenge,
                    &xx.peer,&xx.response,1_800_000_040).is_ok()
            })
        }).collect::<Vec<_>>();
        b.wait();
        assert_eq!(tasks.into_iter().map(|job|job.join().unwrap()).filter(|won|*won).count(),1);
        let reopened=DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).unwrap();
        assert_eq!(reopened.inspect().unwrap().0,1);
    }
    #[test]fn independently_distinct_nonce_is_accepted_without_reusing_old_one(){
        let mut x=fixture();let fence=open_new(&x);
        fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).unwrap();
        new_nonce(&mut x,'d');
        let next=fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_045).unwrap();
        assert_eq!(next.accepted_count,2);
        assert_eq!(fence.inspect().unwrap().0,2);
    }
    #[test]fn failed_signature_and_bad_channel_do_not_consume_nonce(){
        let mut x=fixture();let fence=open_new(&x);
        x.response.signature_hex=sign(93,RESPONSE_DOMAIN,&x.response.payload);
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_err());
        assert_eq!(fence.inspect().unwrap().0,0);
        resign(&mut x);
        x.peer.tls_exporter_sha256=h('f');
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_err());
        assert_eq!(fence.inspect().unwrap().0,0);
        x.peer.tls_exporter_sha256=h('b');
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_ok());
    }
    #[test]fn transport_partition_does_not_consume_nonce(){
        let x=fixture();let fence=open_new(&x);
        let unavailable=MockRemote{evidence:x.peer.clone(),response:x.response.clone(),fail:true};
        assert!(fence.fetch_and_accept(&x.board,&x.policy,&x.trust,&x.challenge,
            &unavailable,1_800_000_040).is_err());
        assert_eq!(fence.inspect().unwrap().0,0);
        let restored=MockRemote{evidence:x.peer.clone(),response:x.response.clone(),fail:false};
        assert!(fence.fetch_and_accept(&x.board,&x.policy,&x.trust,&x.challenge,
            &restored,1_800_000_040).is_ok());
        assert_eq!(fence.inspect().unwrap().0,1);
    }
    #[test]fn independently_pinned_configuration_cannot_be_substituted(){
        let x=fixture();let fence=open_new(&x);
        let mut wrong=x.trust.clone();
        wrong.service_id="another-service".into();
        assert!(DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&wrong,&x.policy).is_err());
        let mut wrong=x.trust.clone();
        wrong.response_signer_public_key_hex=pubkey(93);
        assert!(DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&wrong,&x.policy).is_err());
        let mut policy=x.policy.clone();
        policy.roster_epoch=999;
        assert!(DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&x.trust,&policy).is_err());
        assert_eq!(fence.inspect().unwrap().0,0);
    }
    #[test]fn mutated_or_partial_replay_journal_fails_closed(){
        let x=fixture();let fence=open_new(&x);
        fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).unwrap();
        let path=x._temporary.path()
            .join("scratch-replay/accepted/00000000000000000001.json");
        std::fs::write(path,b"{").unwrap();
        assert!(fence.inspect().is_err());
        assert!(DurableTranscriptReplayFence::open(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).is_err());
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_err());
    }
    #[test]fn undeclared_journal_entries_are_fail_closed(){
        let x=fixture();let fence=open_new(&x);
        std::fs::write(
            x._temporary.path().join("scratch-replay/accepted/unexpected.bin"),b"no").unwrap();
        assert!(fence.inspect().is_err());
    }
    #[test]fn clock_rollback_after_accepted_valid_transcript_is_denied(){
        let mut x=fixture();let fence=open_new(&x);
        fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_050).unwrap();
        new_nonce(&mut x,'d');
        // Second message is valid for its challenge, but the supplied time
        // retreats relative to last accepted (a local consistency check).
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_045).is_err());
        assert_eq!(fence.inspect().unwrap().0,1);
    }
    #[test]fn loss_of_entire_log_requires_external_anti_rollback_anchor(){
        let x=fixture();let fence=open_new(&x);
        fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).unwrap();
        std::fs::remove_file(
            x._temporary.path().join("scratch-replay/accepted/00000000000000000001.json"))
            .unwrap();
        // Documents the remaining limitation: a local disk-only root can
        // be rolled back without an independently protected high-water mark.
        assert_eq!(fence.inspect().unwrap().0,0);
        assert!(fence.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).is_ok());
    }
    #[cfg(unix)]
    #[test]fn symlink_record_is_never_followed(){
        use std::os::unix::fs::symlink;
        let x=fixture();let fence=open_new(&x);
        let path=x._temporary.path()
            .join("scratch-replay/accepted/00000000000000000001.json");
        symlink(x._temporary.path()
            .join("scratch-replay/.GALIA_NONCANONICAL_REMOTE_REPLAY_FENCE_V1"),&path).unwrap();
        assert!(fence.inspect().is_err());
    }
    #[test]fn root_is_explicitly_new_not_an_existing_repository(){
        let x=fixture();
        assert!(DurableTranscriptReplayFence::initialize_new(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).is_ok());
        assert!(DurableTranscriptReplayFence::initialize_new(
            x._temporary.path().join("scratch-replay"),&x.trust,&x.policy).is_err());
        assert!(DurableTranscriptReplayFence::open(
            x._temporary.path(),&x.trust,&x.policy).is_err());
    }
}


// v0.18: externally signed *offline* journal high-water anchors.
// Every signer and TLS "identity" in this file is a deterministic test fixture.
mod replay_anchor_tests{
    use super::*;
    use std::sync::{Arc,Barrier};
    use std::thread;
    use galia_core_shadow::replay_fence::{DurableTranscriptReplayFence,ReplayJournalCheckpoint};
    use galia_core_shadow::replay_anchor::*;

    fn store(x:&Fixture)->DurableTranscriptReplayFence{
        DurableTranscriptReplayFence::initialize_new(
            x._temporary.path().join("anchored-replay"),&x.trust,&x.policy).unwrap()
    }
    fn trust(x:&Fixture)->ReplayAnchorTrust{
        ReplayAnchorTrust{
            signer_key_id:"replay-auditor-key".into(),
            signer_public_key_hex:pubkey(94),
            stream_id:"replay-anchor-stream-1".into(),
            service_id:x.trust.service_id.clone(),
            namespace:x.trust.checkpoint.namespace.clone(),
            case_id:x.trust.checkpoint.case_id.clone(),
            pinned_service_trust_sha256:sha256(&canonical(&x.trust)),
            pinned_observer_policy_sha256:policy_digest(&x.policy).unwrap(),
            floor_sequence:0,floor_envelope_sha256:None,
            floor_checkpoint:ReplayJournalCheckpoint{
                accepted_count:0,journal_tip_sha256:None,
            },
        }
    }
    fn anchor(t:&ReplayAnchorTrust,cp:ReplayJournalCheckpoint,seq:u64,
        prior:Option<String>)->SignedReplayAnchor{
        let payload=ReplayAnchorPayload{
            format:ANCHOR_FORMAT.into(),signer_key_id:t.signer_key_id.clone(),
            stream_id:t.stream_id.clone(),service_id:t.service_id.clone(),
            namespace:t.namespace.clone(),case_id:t.case_id.clone(),
            service_trust_sha256:t.pinned_service_trust_sha256.clone(),
            observer_policy_sha256:t.pinned_observer_policy_sha256.clone(),
            sequence:seq,previous_envelope_sha256:prior,checkpoint:cp,
        };
        SignedReplayAnchor{
            signature_hex:sign(94,ANCHOR_DOMAIN,&payload),payload,
        }
    }
    fn digest(v:&SignedReplayAnchor)->String{sha256(&canonical(v))}
    fn consume(x:&Fixture,f:&DurableTranscriptReplayFence){
        f.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040).unwrap();
    }
    fn new_nonce(x:&mut Fixture,c:char){
        x.challenge.nonce_sha256=h(c);
        x.response.payload.nonce_sha256=x.challenge.nonce_sha256.clone();
        x.response.payload.challenge_sha256=sha256(&canonical(&x.challenge));
        x.response.signature_hex=sign(92,RESPONSE_DOMAIN,&x.response.payload);
    }
    #[test]fn valid_signed_high_water_and_anchored_accept(){
        let mut x=fixture();let f=store(&x);consume(&x,&f);
        let a=anchor(&trust(&x),f.checkpoint().unwrap(),1,None);
        let report=verify_anchored_journal(&f,&x.trust,&x.policy,&trust(&x),&[a.clone()]).unwrap();
        assert_eq!(report.latest_checkpoint.accepted_count,1);
        assert!(report.signed_chain_matches_local_prefixes);
        assert!(!report.externally_operated_auditor_verified&&!report.canonical_writeback);
        new_nonce(&mut x,'d');
        let result=f.accept_anchored_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_045,&trust(&x),&[a]).unwrap();
        assert_eq!(result.accepted_count,2);
        assert!(!result.independently_pinned_rollback_anchor_verified);
        assert_eq!(f.checkpoint().unwrap().accepted_count,2);
    }
    #[test]fn a_complete_local_rollback_is_detected_if_signed_anchor_survives(){
        let mut x=fixture();let f=store(&x);consume(&x,&f);
        let signed=anchor(&trust(&x),f.checkpoint().unwrap(),1,None);
        std::fs::remove_file(x._temporary.path()
            .join("anchored-replay/accepted/00000000000000000001.json")).unwrap();
        assert_eq!(f.checkpoint().unwrap().accepted_count,0);
        assert!(verify_anchored_journal(&f,&x.trust,&x.policy,&trust(&x),&[signed.clone()]).is_err());
        new_nonce(&mut x,'d');
        assert!(f.accept_anchored_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_045,&trust(&x),&[signed]).is_err());
        assert_eq!(f.checkpoint().unwrap().accepted_count,0);
    }
    #[test]fn incremental_reanchoring_respects_retained_prior_high_water(){
        let mut x=fixture();let f=store(&x);consume(&x,&f);
        let original_cp=f.checkpoint().unwrap();
        let a=anchor(&trust(&x),original_cp.clone(),1,None);
        new_nonce(&mut x,'d');
        f.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_045).unwrap();
        let mut next_trust=trust(&x);
        next_trust.floor_sequence=1;
        next_trust.floor_envelope_sha256=Some(digest(&a));
        next_trust.floor_checkpoint=original_cp;
        let b=anchor(&next_trust,f.checkpoint().unwrap(),2,Some(digest(&a)));
        let result=verify_anchored_journal(&f,&x.trust,&x.policy,
            &next_trust,&[b]).unwrap();
        assert_eq!(result.latest_sequence,2);
        assert_eq!(result.latest_checkpoint.accepted_count,2);
    }
    #[test]fn forged_or_role_confused_anchor_keys_rejected(){
        let x=fixture();let f=store(&x);consume(&x,&f);
        let mut a=anchor(&trust(&x),f.checkpoint().unwrap(),1,None);
        a.signature_hex=sign(95,ANCHOR_DOMAIN,&a.payload);
        assert!(verify_anchored_journal(&f,&x.trust,&x.policy,&trust(&x),&[a]).is_err());
        let mut wrong=trust(&x);
        wrong.signer_public_key_hex=x.trust.response_signer_public_key_hex.clone();
        assert!(wrong.validate(&x.trust,&x.policy).is_err());
        let mut wrong=trust(&x);
        wrong.signer_public_key_hex=x.trust.checkpoint.external_signer_public_key_hex.clone();
        assert!(wrong.validate(&x.trust,&x.policy).is_err());
    }
    #[test]fn scope_and_policy_hash_substitution_rejected(){
        let x=fixture();let f=store(&x);consume(&x,&f);
        let a=anchor(&trust(&x),f.checkpoint().unwrap(),1,None);
        let mut t=trust(&x);t.stream_id="other-stream".into();
        assert!(galia_core_shadow::replay_anchor::verify_anchor_chain(&t,&x.trust,&x.policy,&[a.clone()]).is_err());
        let mut t=trust(&x);t.case_id="other-case".into();
        assert!(galia_core_shadow::replay_anchor::verify_anchor_chain(&t,&x.trust,&x.policy,&[a.clone()]).is_err());
        let mut t=trust(&x);t.pinned_service_trust_sha256=h('f');
        assert!(galia_core_shadow::replay_anchor::verify_anchor_chain(&t,&x.trust,&x.policy,&[a]).is_err());
    }
    #[test]fn skipped_sequence_or_altered_previous_digest_rejected(){
        let x=fixture();let f=store(&x);consume(&x,&f);
        let t=trust(&x);
        let first=anchor(&t,f.checkpoint().unwrap(),1,None);
        let second=anchor(&t,f.checkpoint().unwrap(),3,Some(digest(&first)));
        assert!(galia_core_shadow::replay_anchor::verify_anchor_chain(&t,&x.trust,&x.policy,&[first.clone(),second]).is_err());
        let second=anchor(&t,f.checkpoint().unwrap(),2,Some(h('f')));
        assert!(galia_core_shadow::replay_anchor::verify_anchor_chain(&t,&x.trust,&x.policy,&[first,second]).is_err());
    }
    #[test]fn same_height_different_digest_even_if_resigned_rejected(){
        let x=fixture();let f=store(&x);consume(&x,&f);
        let t=trust(&x);let a=anchor(&t,f.checkpoint().unwrap(),1,None);
        let mut altered=f.checkpoint().unwrap();
        altered.journal_tip_sha256=Some(h('f'));
        let b=anchor(&t,altered,2,Some(digest(&a)));
        assert!(galia_core_shadow::replay_anchor::verify_anchor_chain(&t,&x.trust,&x.policy,&[a,b]).is_err());
    }
    #[test]fn signed_but_invented_larger_journal_is_rejected(){
        let x=fixture();let f=store(&x);consume(&x,&f);
        let t=trust(&x);
        let fabricated=ReplayJournalCheckpoint{
            accepted_count:2,journal_tip_sha256:Some(h('f')),
        };
        let signed=anchor(&t,fabricated,1,None);
        assert!(verify_anchored_journal(&f,&x.trust,&x.policy,&t,&[signed]).is_err());
    }
    #[test]fn signed_historical_prefix_detects_modified_entry_below_later_head(){
        let mut x=fixture();let f=store(&x);consume(&x,&f);
        let t=trust(&x);
        let a=anchor(&t,f.checkpoint().unwrap(),1,None);
        new_nonce(&mut x,'d');
        f.accept_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_045).unwrap();
        // The original first entry must remain byte identical.
        std::fs::write(x._temporary.path()
            .join("anchored-replay/accepted/00000000000000000001.json"),b"{").unwrap();
        assert!(verify_anchored_journal(&f,&x.trust,&x.policy,&t,&[a]).is_err());
    }
    #[test]fn anchored_replay_race_has_one_winner(){
        let x=Arc::new(fixture());let first=store(&x);
        let second=DurableTranscriptReplayFence::open(
            x._temporary.path().join("anchored-replay"),&x.trust,&x.policy).unwrap();
        let t=trust(&x);
        let signed=anchor(&t,ReplayJournalCheckpoint{
            accepted_count:0,journal_tip_sha256:None,
        },1,None);
        let b=Arc::new(Barrier::new(3));
        let jobs=[first,second].into_iter().map(|f|{
            let x=Arc::clone(&x);let b=Arc::clone(&b);
            let t=trust(&x);let signed=signed.clone();
            thread::spawn(move||{
                b.wait();
                f.accept_anchored_verified(&x.board,&x.policy,&x.trust,&x.challenge,
                    &x.peer,&x.response,1_800_000_040,&t,&[signed]).is_ok()
            })
        }).collect::<Vec<_>>();
        b.wait();
        assert_eq!(jobs.into_iter().map(|j|j.join().unwrap()).filter(|won|*won).count(),1);
    }
    #[test]fn signed_checkpoint_does_not_grant_human_authority(){
        let x=fixture();let f=store(&x);
        let signed=anchor(&trust(&x),ReplayJournalCheckpoint{
            accepted_count:0,journal_tip_sha256:None,
        },1,None);
        let result=f.accept_anchored_verified(&x.board,&x.policy,&x.trust,&x.challenge,
            &x.peer,&x.response,1_800_000_040,&trust(&x),&[signed]).unwrap();
        assert!(!result.real_transport_authenticated);
        assert!(!result.independently_pinned_rollback_anchor_verified);
        assert!(!result.human_authority_verified);
        assert!(!result.canonical_writeback&&!result.authority_transfer);
    }
}


// v0.19: real rustls TLS 1.3 loopback handshakes with mandatory test-server
// client-certificate verification. NOT a deployed independent auditor.
#[cfg(feature="tls-transport")]
mod live_tls_tests{
    use super::*;
    use std::net::{TcpListener,SocketAddr};
    use std::io::{Read,Write};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use rcgen::generate_simple_self_signed;
    use rustls::{RootCertStore,ServerConfig,ServerConnection,StreamOwned,ProtocolVersion};
    use rustls::pki_types::{PrivatePkcs8KeyDer,CertificateDer};
    use rustls::server::WebPkiClientVerifier;
    use galia_core_shadow::tls_checkpoint::PinnedMtlsClient;

    fn tls_configs()->(PinnedMtlsClient,Arc<ServerConfig>,String){
        let server=generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client=generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let (_,cert)=x509_parser::parse_x509_certificate(server.cert.der().as_ref()).unwrap();
        let pin=sha256(cert.public_key().raw);
        let mut roots=RootCertStore::empty();
        roots.add(server.cert.der().clone()).unwrap();
        let client_tls= PinnedMtlsClient::new(
            roots,vec![client.cert.der().clone()],
            PrivatePkcs8KeyDer::from(client.signing_key.serialize_der()).into(),
            "localhost",Duration::from_secs(5)
        ).unwrap();
        let mut trusted_clients=RootCertStore::empty();
        trusted_clients.add(client.cert.der().clone()).unwrap();
        let verifier=WebPkiClientVerifier::builder(Arc::new(trusted_clients))
            .build().unwrap();
        let server_tls=ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server.cert.der().clone()],
                PrivatePkcs8KeyDer::from(server.signing_key.serialize_der()).into()).unwrap();
        (client_tls,Arc::new(server_tls),pin)
    }
    fn server_once(
        server_tls:Arc<ServerConfig>,
        template:SignedRemoteCheckpointResponse
    )->(SocketAddr,thread::JoinHandle<Result<bool,String>>){
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let addr=listener.local_addr().unwrap();
        let join=thread::spawn(move||->Result<bool,String>{
            let (mut socket,_)=listener.accept().map_err(|e|e.to_string())?;
            socket.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
            socket.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
            let mut conn=ServerConnection::new(server_tls).map_err(|e|e.to_string())?;
            while conn.is_handshaking(){
                conn.complete_io(&mut socket).map_err(|e|e.to_string())?;
            }
            if conn.protocol_version()!=Some(ProtocolVersion::TLSv1_3)||
               conn.peer_certificates().and_then(|v|v.first()).is_none() {
               return Err("test server did not authenticate mandatory TLS client certificate".into())
            }
            let mut exporter=[0u8;32];
            conn.export_keying_material(&mut exporter,
                b"EXPORTER-GALIA-CHECKPOINT-V0.19",
                Some(b"checkpoint-service-a")).map_err(|e|e.to_string())?;
            let exporter_hash=sha256(&exporter);
            let mut io=StreamOwned::new(conn,socket);
            let mut len=[0u8;4];io.read_exact(&mut len).map_err(|e|e.to_string())?;
            let n=u32::from_be_bytes(len) as usize;
            if n==0||n>1024*1024{return Err("oversized or empty TLS request".into())}
            let mut req=vec![0u8;n];io.read_exact(&mut req).map_err(|e|e.to_string())?;
            let challenge:RemoteCheckpointChallenge=serde_json::from_slice(&req)
                .map_err(|e|e.to_string())?;
            if challenge.tls_exporter_sha256!=exporter_hash {
                return Err("TLS 1.3 session exporter mismatch".into())
            }
            let payload=RemoteCheckpointPayload{
                format:RESPONSE_FORMAT.into(),
                service_id:challenge.service_id.clone(),
                signer_id:"service-key-a".into(),
                challenge_sha256:sha256(&canonical(&challenge)),
                nonce_sha256:challenge.nonce_sha256.clone(),
                tls_exporter_sha256:exporter_hash,
                signed_at_unix_seconds:1_800_000_020,
                checkpoint_chain:template.payload.checkpoint_chain,
            };
            let signed=SignedRemoteCheckpointResponse{
                signature_hex:sign(92,RESPONSE_DOMAIN,&payload),payload
            };
            let bytes=canonical(&signed);
            io.write_all(&(bytes.len() as u32).to_be_bytes()).map_err(|e|e.to_string())?;
            io.write_all(&bytes).map_err(|e|e.to_string())?;
            io.flush().map_err(|e|e.to_string())?;
            Ok(true)
        });
        (addr,join)
    }
    #[test]fn actual_tls13_mtls_checkpoint_exchange_roundtrip_end_to_end(){
        let mut x=fixture();
        let (client,server,pin)=tls_configs();
        x.trust.pinned_tls_peer_spki_sha256=pin;
        let (addr,server_thread)=server_once(server,x.response.clone());
        let (challenge,peer,signed)=client.exchange(
            addr,&x.trust,&x.policy,&h('c'),1_800_000_000,1_800_000_060).unwrap();
        assert!(server_thread.join().unwrap().unwrap());
        let report=verify_remote_exchange(&x.board,&x.policy,&x.trust,
            &challenge,&peer,&signed,1_800_000_040).unwrap();
        assert_eq!(report.checkpoint_count,1);
        assert!(report.claimed_tls_identity_matched);
        assert!(!report.external_service_deployed_verified);
        assert!(!report.human_authority_verified&&!report.canonical_writeback);
    }
    #[test]fn negotiated_certificate_valid_but_wrong_spki_pin_denied(){
        let mut x=fixture();
        let (client,server,_pin)=tls_configs();
        x.trust.pinned_tls_peer_spki_sha256=h('f');
        let (addr,server_thread)=server_once(server,x.response.clone());
        assert!(client.exchange(addr,&x.trust,&x.policy,
            &h('c'),1_800_000_000,1_800_000_060).is_err());
        let _=server_thread.join(); // no request is ever accepted
    }
    #[test]fn no_live_tls_listener_is_hard_failure_not_fake_peer_evidence(){
        let x=fixture();
        let (client,_server,_pin)=tls_configs();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let addr=listener.local_addr().unwrap();
        drop(listener);
        assert!(client.exchange(addr,&x.trust,&x.policy,
            &h('c'),1_800_000_000,1_800_000_060).is_err());
    }
}
