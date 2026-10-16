//! GALIA 2.0 Rust shadow core. No P5 human authority or canonical writes.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
pub mod audit;
pub mod attestation;
pub mod review;
#[cfg(feature="scratch-store")]
pub mod scratch_store;
#[cfg(feature="scratch-store")]
pub mod consumption;
#[cfg(feature="scratch-store")]
pub mod witness;
#[cfg(feature="scratch-store")]
pub mod durable_witness;
#[cfg(feature="scratch-store")]
pub mod witness_proof;
#[cfg(feature="scratch-store")]
pub mod witness_continuity;
#[cfg(feature="scratch-store")]
pub mod transparency;
#[cfg(feature="scratch-store")]
pub mod transparency_board;
#[cfg(feature="scratch-store")]
pub mod external_checkpoint;
#[cfg(feature="scratch-store")]
pub mod external_transport;

#[cfg(feature="scratch-store")]
pub mod replay_fence;

#[cfg(feature="scratch-store")]
pub mod replay_anchor;

#[cfg(feature="tls-transport")]
pub mod tls_checkpoint;

#[cfg(feature="tls-transport")]
pub mod mtls_checkpoint_server;

#[cfg(feature="tls-transport")]
pub mod service_recovery;

#[cfg(feature="tls-transport")]
pub mod fenced_coordinator;
