//! GALIA 2.0 Rust shadow core.
//! Default build: pure evaluation only. No canonical persistence writes or authority.
#![forbid(unsafe_code)]
pub mod core;
pub mod state_machine;
pub mod authority;
pub mod preflight;
pub mod persistence;
pub mod audit;
#[cfg(feature = "scratch-store")]
pub mod scratch_store;
