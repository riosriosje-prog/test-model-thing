//! GALIA 2.0 Rust shadow core.
//! Default build: pure evaluation; no canonical persistence writes or authority.
//! Optional scratch-store feature: local noncanonical test writes only.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
pub mod audit;
pub mod attestation;
#[cfg(feature = "scratch-store")]
pub mod scratch_store;
