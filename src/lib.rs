//! Minimal Plonk: a small but complete Plonk proof system built with Rust and arkworks.

pub mod cs;
pub mod curve;
pub mod domain;
pub mod error;
pub mod kzg;
pub mod mimc;
pub mod permutation;
pub mod prelude;
pub mod prover;
pub mod quotient;
pub mod transcript;
pub mod types;
pub mod validate;
pub mod verifier;
pub mod witness;
