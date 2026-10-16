//! GALIA 2.0 Rust shadow core.
//! Default build: read-only analysis. No canonical writes or human authority.
//! Optional scratch-store feature: noncanonical test-only local generation writes.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
pub mod audit;
pub mod attestation;
pub mod review;
#[cfg(feature = "scratch-store")]
pub mod scratch_store;
