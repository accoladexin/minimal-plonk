//! Minimal-Plonk：最小但完整的 Plonk 证明系统（Rust + arkworks）
//!
//! 当前处于 Phase 0：工程骨架阶段。

pub mod curve;
pub mod cs;
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
