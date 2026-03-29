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
    /// Wrap an affine G1 point as the shared commitment type.
    pub fn new(point: G1Affine) -> Self {
        Self { point }
    }
    /// Convert a projective G1 point into a serializable commitment.
    pub fn from_projective(point: G1) -> Self {
        Self {
            point: point.into_affine(),
        }
    }
}
/// Minimal opening proof shared by generic KZG APIs.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OpeningProof {
    pub witness_commitment: Commitment,
}
impl OpeningProof {
    /// Build the minimal opening proof wrapper from a witness commitment.
    pub fn new(witness_commitment: Commitment) -> Self {
        Self { witness_commitment }
    }
}
/// Claimed evaluations at the main Plonk challenge point zeta.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EvaluationsAtZeta {
    pub wire_a: Fr,
    pub wire_b: Fr,
    pub wire_c: Fr,
    pub sigma_1: Fr,
    pub sigma_2: Fr,
}
impl EvaluationsAtZeta {
    /// Build the Phase 9 evaluation payload at zeta.
    pub fn new(wire_a: Fr, wire_b: Fr, wire_c: Fr, sigma_1: Fr, sigma_2: Fr) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            sigma_1,
            sigma_2,
        }
    }
}
/// Phase 9 quotient commitments [T_lo, T_mid, T_hi].
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct QuotientChunkCommitments {
    pub t_lo: Commitment,
    pub t_mid: Commitment,
    pub t_hi: Commitment,
}
impl QuotientChunkCommitments {
    /// Collect T_lo / T_mid / T_hi commitments in protocol order.
    pub fn new(t_lo: Commitment, t_mid: Commitment, t_hi: Commitment) -> Self {
        Self { t_lo, t_mid, t_hi }
    }
}
/// Phase 9 opening commitments [W_z] and [W_{z omega}].
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OpeningCommitments {
    pub at_zeta: Commitment,
    pub at_shifted_zeta: Commitment,
}
impl OpeningCommitments {
    /// Collect W_z / W_{z omega} commitments in protocol order.
    pub fn new(at_zeta: Commitment, at_shifted_zeta: Commitment) -> Self {
        Self {
            at_zeta,
            at_shifted_zeta,
        }
    }
}
/// Phase 9 proof layout frozen by Step 9.2.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkProof {
    // commit
    pub wire_commitments: [Commitment; 3],
    pub grand_product_commitment: Commitment,
    pub quotient_chunk_commitments: QuotientChunkCommitments,
    // 两个W
    pub opening_commitments: OpeningCommitments,
    // 第一组多项式的打开点
    pub evaluations_at_zeta: EvaluationsAtZeta,
    // 论文语义中的 Z(omega * zeta) 打开值
    pub grand_product_at_zeta_omega: Fr,
}
impl PlonkProof {
    /// Build the Phase 9 proof produced by the Step 9.3 prover.
    pub fn new(
        wire_commitments: [Commitment; 3],
        grand_product_commitment: Commitment,
        quotient_chunk_commitments: QuotientChunkCommitments,
        opening_commitments: OpeningCommitments,
        evaluations_at_zeta: EvaluationsAtZeta,
        grand_product_at_zeta_omega: Fr,
    ) -> Self {
        Self {
            wire_commitments,
            grand_product_commitment,
            quotient_chunk_commitments,
            opening_commitments,
            evaluations_at_zeta,
            grand_product_at_zeta_omega,
        }
    }
}
/// Backward-compatible alias kept for earlier imports.
pub type ProofSkeleton = PlonkProof;
