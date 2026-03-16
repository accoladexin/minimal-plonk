//! 共享导出入口（Step 0.3）。
//!
//! 目的：避免在各模块重复写导入路径。
//! 规则：只保留最小集合，按真实需求渐进扩展。

pub use crate::curve::{Fr, G1, G1Affine, G2, G2Affine};
pub use crate::error::{PlonkError, Result as PlonkResult};
pub use crate::types::{
    Commitment, DomainParams, OpeningProof, PlonkConfig, PlonkProof, ProofSkeleton,
    TranscriptHash,
};
pub use crate::validate::ensure;
