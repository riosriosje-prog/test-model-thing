//! GALIA Rust shadow core: no canonical writes, promotion guards or human authority.
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
#[cfg(feature = "scratch-store")]
pub mod consumption;
