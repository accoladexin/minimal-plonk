//! Shared proof-related types.

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::curve::{Fr, G1, G1Affine};

/// Canonical G1 commitment wrapper shared by Plonk and KZG code.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment {
    pub point: G1Affine,
}

impl Commitment {
    /// 功能说明：把仿射 G1 点包装成项目统一的 commitment 类型。
    /// 输入：一个 `G1Affine` 点。
    /// 输出：一个 `Commitment`。
    /// 示例：`Commitment::new(point)`。
    pub fn new(point: G1Affine) -> Self {
        Self { point }
    }

    /// 功能说明：把 projective G1 点转换成存储用的仿射 commitment。
    /// 输入：一个 `G1` projective 点。
    /// 输出：一个 `Commitment`。
    /// 示例：`Commitment::from_projective(generator)`。
    pub fn from_projective(point: G1) -> Self {
        Self {
            point: point.into_affine(),
        }
    }
}

/// Minimal opening proof shared by Step 7 proof types and generic KZG APIs.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OpeningProof {
    pub witness_commitment: Commitment,
}

impl OpeningProof {
    /// 功能说明：用 witness commitment 构造最小 opening proof。
    /// 输入：一个 witness commitment。
    /// 输出：一个 `OpeningProof`。
    /// 示例：`OpeningProof::new(commitment)`。
    pub fn new(witness_commitment: Commitment) -> Self {
        Self { witness_commitment }
    }
}

/// Claimed evaluations at the main Plonk challenge point `zeta`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EvaluationsAtZeta {
    pub wire_a: Fr,
    pub wire_b: Fr,
    pub wire_c: Fr,
    pub grand_product: Fr,
    pub quotient: Fr,
}

impl EvaluationsAtZeta {
    /// 功能说明：构造在 `zeta` 点处的固定评估值包。
    /// 输入：`a(zeta)`、`b(zeta)`、`c(zeta)`、`Z(zeta)`、`t(zeta)`。
    /// 输出：一个固定顺序的 `EvaluationsAtZeta`。
    /// 示例：`EvaluationsAtZeta::new(a, b, c, z, t)`。
    pub fn new(
        wire_a: Fr,
        wire_b: Fr,
        wire_c: Fr,
        grand_product: Fr,
        quotient: Fr,
    ) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            grand_product,
            quotient,
        }
    }
}

/// Claimed evaluations at shifted points needed by the current opening plan.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShiftedEvaluations {
    pub grand_product_next: Fr,
}

impl ShiftedEvaluations {
    /// 功能说明：构造当前版本需要的 shifted evaluation 包。
    /// 输入：`Z(omega * zeta)`。
    /// 输出：一个 `ShiftedEvaluations`。
    /// 示例：`ShiftedEvaluations::new(z_shifted)`。
    pub fn new(grand_product_next: Fr) -> Self {
        Self { grand_product_next }
    }
}

/// Frozen minimal proof layout for Step 7.1 and Step 8 entry.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkProof {
    pub wire_commitments: [Commitment; 3],
    pub grand_product_commitment: Commitment,
    pub quotient_commitment: Commitment,
    /// prover 携带的 statement 副本；Step 8.2 verifier 仍需接收外部 public_inputs 并做一致性检查。
    pub public_inputs: Vec<Fr>,
    pub evaluations_at_zeta: EvaluationsAtZeta,
    pub shifted_evaluations: ShiftedEvaluations,
    pub opening_proof_at_zeta: OpeningProof,
    pub opening_proof_at_shifted_zeta: OpeningProof,
}

impl PlonkProof {
    /// 功能说明：构造 Step 7.1 冻结后的最小 proof 对象。
    /// 输入：固定顺序的 commitments、public inputs、claimed evaluations、以及两个 opening proof。
    /// 输出：一个稳定可序列化的 `PlonkProof`。
    /// 示例：`PlonkProof::new([...], z_commit, t_commit, public_inputs, evals, shifted, pi_z, pi_shift)`。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire_commitments: [Commitment; 3],
        grand_product_commitment: Commitment,
        quotient_commitment: Commitment,
        public_inputs: Vec<Fr>,
        evaluations_at_zeta: EvaluationsAtZeta,
        shifted_evaluations: ShiftedEvaluations,
        opening_proof_at_zeta: OpeningProof,
        opening_proof_at_shifted_zeta: OpeningProof,
    ) -> Self {
        Self {
            wire_commitments,
            grand_product_commitment,
            quotient_commitment,
            public_inputs,
            evaluations_at_zeta,
            shifted_evaluations,
            opening_proof_at_zeta,
            opening_proof_at_shifted_zeta,
        }
    }
}

/// Backward-compatible alias kept for earlier tests and imports.
pub type ProofSkeleton = PlonkProof;
