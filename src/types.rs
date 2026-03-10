//! Step 0.2 的公共类型层。
//!
//! 这里先放最小版结构：
//! - `TranscriptHash`：记录 transcript 用哪种哈希
//! - `DomainParams`：记录后续 FFT domain 需要的基础参数
//! - `PlonkConfig`：记录协议级配置
//! - `Commitment` / `ProofSkeleton`：为后续 prover / verifier 预留稳定数据结构

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    cs::SelectorColumns,
    curve::{Fr, G1, G1Affine},
    error::{PlonkError, Result as PlonkResult},
    permutation::{GrandProductEvaluations, SigmaMapping},
    witness::WitnessColumns,
};

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
    pub size: u64,     // 2^n，即电路中“行”的数量。
    pub log_size: u32, // n，即 size 的对数。
    pub generator: Fr, // 单位原根 ω。
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
    pub max_degree: u64,        // 这个电路支持的最大多项式阶数。
    pub num_wire_columns: u32,  // 寄存器列数（标准 Plonk 通常是 3 列：a, b, c）。
    pub transcript_hash_id: u8, // 用哪种哈希生成挑战值（0 代表 Blake2b）。
}

impl PlonkConfig {
    /// 构造一份最小配置，并把哈希算法编码成稳定的 `u8`。
    pub fn new(max_degree: u64, num_wire_columns: u32, transcript_hash: TranscriptHash) -> Self {
        Self {
            max_degree,
            num_wire_columns,
            transcript_hash_id: transcript_hash.as_byte(), // 这是自定义的一个函数
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
    // 1. a(x), b(x), c(x) 多项式的承诺
    pub wire_commitments: Vec<Commitment>,
    // 2. 商多项式 t(x) 的承诺（确保约束成立的核心）
    pub quotient_commitment: Option<Commitment>,
    // 3. 置换多项式 z(x) 的承诺（确保复制约束/连线正确）
    pub grand_product_commitment: Option<Commitment>,
    // 4. KZG 打开证明（证明多项式在某个点的值是对的）
    pub opening_proof: Option<Commitment>,
    // 5. 公开输入（电路里大家都能看到的数）
    pub public_inputs: Vec<Fr>,
    // 6. 各个多项式在挑战点 ζ 处的求值结果
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

/// Step 4.3 为 Step 5 准备的最小同域输入上下文。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotientInputs {
    pub domain_size: usize,
    pub witness_columns: WitnessColumns,
    pub selector_columns: SelectorColumns,
    pub sigma_mapping: SigmaMapping,
    pub grand_product_evaluations: GrandProductEvaluations,
}

impl QuotientInputs {
    /// 功能说明：把 Step 5 需要的散落输入收口到一个对象里，并校验同域一致性。
    /// 输入：witness、selector、sigma、grand product。
    /// 输出：合法时返回 `QuotientInputs`。
    /// 示例：当四者都对应同一个 size-n domain 时构造成功。
    pub fn new(
        witness_columns: WitnessColumns,
        selector_columns: SelectorColumns,
        sigma_mapping: SigmaMapping,
        grand_product_evaluations: GrandProductEvaluations,
    ) -> PlonkResult<Self> {
        let domain_size = witness_columns.domain_size();

        if selector_columns.domain_size() != domain_size {
            return Err(PlonkError::InconsistentLength(
                "selector domain_size must match witness domain_size",
            ));
        }
        if sigma_mapping.domain_size() != domain_size {
            return Err(PlonkError::InconsistentLength(
                "sigma domain_size must match witness domain_size",
            ));
        }
        if grand_product_evaluations.domain_size != domain_size {
            return Err(PlonkError::InconsistentLength(
                "grand product domain_size must match witness domain_size",
            ));
        }
        if grand_product_evaluations.grand_product_evaluations.len() != domain_size + 1 {
            return Err(PlonkError::InconsistentLength(
                "grand product evaluations length must equal domain_size + 1",
            ));
        }

        Ok(Self {
            domain_size,
            witness_columns,
            selector_columns,
            sigma_mapping,
            grand_product_evaluations,
        })
    }
}
