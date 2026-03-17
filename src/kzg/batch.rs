//! Step 6.2: multi-polynomial opening at one point.

use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};

use crate::{
    curve::{Fr, G1},
    error::Result,
    kzg::{
        open::{KzgOpeningProof, open_polynomial_at_point},
        srs::KzgSrs,
        verify::verify_opening,
    },
    types::Commitment,
    validate::ensure,
};

/// Opening bundle for multiple polynomials at one point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgBatchOpening {
    pub point: Fr,
    pub values: Vec<Fr>,
    pub proof: KzgOpeningProof,
}

/// Function: open many polynomials at the same point with one proof.
/// Input: polynomial slice, point, aggregation challenge, and SRS.
/// Output: all evaluations and one aggregated opening proof.
/// Example: used by Plonk to open a(z), b(z), c(z), t(z), Z(z) in one proof.
/// 这个是对于Prover侧来说的
pub fn open_polynomials_at_same_point(
    polynomials: &[DensePolynomial<Fr>],
    point: Fr,
    aggregation_challenge: Fr,
    srs: &KzgSrs,
) -> Result<KzgBatchOpening> {
    // Paper mapping: same-point batch opening aggregation used for A, B, C, Z, T at zeta.
    // 检查输入多项式列表非空。
    ensure(!polynomials.is_empty(), "polynomial list must be non-empty")?;

    let mut values = Vec::with_capacity(polynomials.len());
    for polynomial in polynomials {
        srs.validate_polynomial_degree(polynomial.degree())?;
        values.push(polynomial.evaluate(&point));
    }
    // 构建聚合多项式并生成一个 KZG opening 证明。
    let aggregated_polynomial = aggregate_polynomials(polynomials, aggregation_challenge);
    // 这里直接复用之前写的 open_polynomial_at_point 来生成证明，输入是聚合多项式。
    let aggregated_opening = open_polynomial_at_point(&aggregated_polynomial, point, srs)?;

    Ok(KzgBatchOpening {
        point,
        values,
        proof: aggregated_opening.proof,
    })
}

/// Function: verify many polynomial evaluations at one point with one proof.
/// Input: commitments, point, values, aggregation challenge, proof, and SRS.
/// Output: `true` if verification succeeds, otherwise `false`.
/// Example: verifier side for same-point multi-opening.
pub fn verify_polynomials_at_same_point(
    commitments: &[Commitment],
    point: Fr,
    values: &[Fr],
    aggregation_challenge: Fr,
    proof: &KzgOpeningProof,
    srs: &KzgSrs,
) -> Result<bool> {
    // Paper mapping: verifier-side check for the same batch opening aggregation.
    ensure(!commitments.is_empty(), "commitment list must be non-empty")?;
    ensure(
        commitments.len() == values.len(),
        "commitments and values length must match",
    )?;

    let aggregated_commitment = aggregate_commitments(commitments, aggregation_challenge);
    let aggregated_value = aggregate_values(values, aggregation_challenge);

    verify_opening(&aggregated_commitment, point, aggregated_value, proof, srs)
}

/// Function: aggregate polynomials with fixed input-slice order.
/// Input: polynomial slice and challenge `v`.
/// Output: `sum_i v^i * p_i(X)`.
/// Example: for `[p0, p1, p2]`, result is `p0 + v*p1 + v^2*p2`.
pub fn aggregate_polynomials(
    polynomials: &[DensePolynomial<Fr>],
    aggregation_challenge: Fr,
) -> DensePolynomial<Fr> {
    // Paper mapping: batch opening aggregation sum_i v^i * p_i(X).
    let mut aggregated = DensePolynomial::zero();
    let mut weight = Fr::from(1u64);
    for polynomial in polynomials {
        let scaled = scale_polynomial(polynomial, weight);
        aggregated = &aggregated + &scaled;
        weight *= aggregation_challenge;
    }
    aggregated
}

/// Function: aggregate commitments with fixed input-slice order.
/// Input: commitment slice and challenge `v`.
/// Output: `sum_i v^i * C_i`.
/// Example: order is exactly the input slice order.
pub fn aggregate_commitments(commitments: &[Commitment], aggregation_challenge: Fr) -> Commitment {
    // Paper mapping: commitment-side image of the same batch opening aggregation.
    let mut aggregated = G1::zero();
    let mut weight = Fr::from(1u64);
    for commitment in commitments {
        // Affine转换为Projective，Projective形式方便计算
        let mut term = commitment.point.into_group();
        term *= weight;
        aggregated += term;
        weight *= aggregation_challenge;
    }
    Commitment::from_projective(aggregated)
}

/// Function: aggregate scalar evaluations with fixed input-slice order.
/// Input: value slice and challenge `v`.
/// Output: `sum_i v^i * y_i`.
/// Example: order is exactly the input slice order.
pub fn aggregate_values(values: &[Fr], aggregation_challenge: Fr) -> Fr {
    // Paper mapping: evaluation-side image of the same batch opening aggregation.
    let mut aggregated = Fr::zero();
    let mut weight = Fr::from(1u64);
    for value in values {
        aggregated += weight * value;
        weight *= aggregation_challenge;
    }
    aggregated
}

/// Function: multiply all polynomial coefficients by one scalar.
/// Input: polynomial and scalar.
/// Output: scaled polynomial.
/// Example: `scale_polynomial(p, v^i)` when building aggregated polynomial.
fn scale_polynomial(polynomial: &DensePolynomial<Fr>, scalar: Fr) -> DensePolynomial<Fr> {
    if scalar.is_zero() || polynomial.is_zero() {
        return DensePolynomial::zero();
    }

    let scaled_coefficients = polynomial.coeffs.iter().map(|c| *c * scalar).collect();
    DensePolynomial::from_coefficients_vec(scaled_coefficients)
}
