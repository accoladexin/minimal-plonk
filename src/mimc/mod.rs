//! Step 2.2：MiMC（Feistel 变体）模块入口。
//!
//! 约束：
//! - `reference.rs` 只做纯算法
//! - `circuit.rs` 只做电路与约束映射

pub mod circuit;
pub mod constants;
pub mod reference;

pub use circuit::{
    build_mimc_feistel_circuit, build_mimc_feistel_circuit_from_trace, MimcCircuitBuild,
};
pub use constants::{default_round_constants, DEFAULT_ROUNDS, MAX_ROUNDS};
pub use reference::{mimc_feistel, mimc_feistel_trace, FeistelRoundTrace};
