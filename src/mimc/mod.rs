//! Step 2.2：MiMC（Feistel 变体）模块入口。
//!
//! 约束：
//! - `reference.rs` 只做纯算法
//! - `circuit.rs` 只做电路与约束映射

pub mod circuit;
pub mod constants;
pub mod reference;

pub use circuit::{
    MimcCircuitBuild, build_mimc_feistel_circuit, build_mimc_feistel_circuit_from_trace,
};
pub use constants::{DEFAULT_ROUNDS, MAX_ROUNDS, default_round_constants};
pub use reference::{FeistelRoundTrace, mimc_feistel, mimc_feistel_trace};
