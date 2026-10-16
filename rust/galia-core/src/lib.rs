//! GALIA 2.0 Rust shadow core.
//! Default build: pure verification, NO persistence writes or authority.
//! Optional scratch-store feature: isolated noncanonical test-store writes only.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
#[cfg(feature = "scratch-store")]
pub mod scratch_store;
