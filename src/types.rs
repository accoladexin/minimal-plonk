//! Step 0.2 的公共类型层。
//!
//! 这里先放最小版结构：
//! - `TranscriptHash`：记录 transcript 用哪种哈希
//! - `DomainParams`：记录后续 FFT domain 需要的基础参数
//! - `PlonkConfig`：记录协议级配置
//! - `Commitment` / `ProofSkeleton`：为后续 prover / verifier 预留稳定数据结构

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::curve::{Fr, G1, G1Affine};

/// Transcript 可选哈希。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptHash {
    Blake2b,
    Sha256,
}

impl TranscriptHash {
    /// 返回一个稳定的字节标签，便于做配置序列化和调试。
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Blake2b => 0,
            Self::Sha256 => 1,
        }
    }
}

impl Default for TranscriptHash {
    /// 默认选择 Blake2b，和当前 benchmark-oriented 的项目目标一致。
    fn default() -> Self {
        Self::Blake2b
    }
}

/// Domain 的基础参数。
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DomainParams {
    pub size: u64,
    pub log_size: u32,
    pub generator: Fr,
}

impl DomainParams {
    /// 构造最小版 domain 参数。
    pub fn new(size: u64, log_size: u32, generator: Fr) -> Self {
        Self {
            size,
            log_size,
            generator,
        }
    }
}

/// Plonk 的全局配置。
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkConfig {
    pub max_degree: u64,
    pub num_wire_columns: u32,
    pub transcript_hash_id: u8,
}

impl PlonkConfig {
    /// 构造一份最小配置，并把哈希算法编码成稳定的 `u8`。
    pub fn new(max_degree: u64, num_wire_columns: u32, transcript_hash: TranscriptHash) -> Self {
        Self {
            max_degree,
            num_wire_columns,
            transcript_hash_id: transcript_hash.as_byte(),
        }
    }
}

/// G1 承诺的最小包装。
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment {
    pub point: G1Affine,
}

impl Commitment {
    /// 用仿射点创建承诺。
    pub fn new(point: G1Affine) -> Self {
        Self { point }
    }

    /// 把 projective 点转换成更适合存储的 affine 点。
    pub fn from_projective(point: G1) -> Self {
        Self {
            point: point.into_affine(),
        }
    }
}

/// 证明对象的占位结构。
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofSkeleton {
    pub wire_commitments: Vec<Commitment>,
    pub quotient_commitment: Option<Commitment>,
    pub grand_product_commitment: Option<Commitment>,
    pub opening_proof: Option<Commitment>,
    pub public_inputs: Vec<Fr>,
    pub evaluations: Vec<Fr>,
}

impl ProofSkeleton {
    /// 构造一个空的 proof skeleton，后续 step 再逐步填满字段。
    pub fn empty() -> Self {
        Self {
            wire_commitments: Vec::new(),
            quotient_commitment: None,
            grand_product_commitment: None,
            opening_proof: None,
            public_inputs: Vec::new(),
            evaluations: Vec::new(),
        }
    }
}

