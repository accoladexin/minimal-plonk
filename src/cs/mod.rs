//! Step 2.1：Plonk 约束系统（不含密码学）模块入口。
//!
//! 这里仅包含：
//! - 单行 gate 的字段与约束计算
//! - 电路行集合管理（add_gate / pad_to_domain / 约束检查）

pub mod circuit;
pub mod gate;

pub use circuit::Circuit;
pub use gate::GateRow;
