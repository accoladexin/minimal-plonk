//! Step 6.2: KZG opening at one point.

use ark_ff::Zero;
use ark_poly::{
    DenseUVPolynomial, Polynomial, univariate::DenseOrSparsePolynomial, univariate::DensePolynomial,
};

use crate::{
    curve::Fr,
    error::{PlonkError, Result},
    kzg::{commit::commit_polynomial, srs::KzgSrs},
    types::Commitment,
    validate::ensure,
};

/// Opening proof for one polynomial at one point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgOpeningProof {
    pub witness_commitment: Commitment,
}

/// Opening output for one polynomial at one point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgOpening {
    pub point: Fr,
    pub value: Fr,
    pub proof: KzgOpeningProof,
}

/// Function: open one polynomial at one point. 
/// Input: polynomial, point and SRS.
/// Output: point/value/proof bundle.
/// Example: `let opening = open_polynomial_at_point(&poly, z, &srs)?;`.
pub fn open_polynomial_at_point(
    polynomial: &DensePolynomial<Fr>,
    point: Fr,
    srs: &KzgSrs,
) -> Result<KzgOpening> {
    // 检查多项式的度数是否超过 SRS 支持的最大度数。
    srs.validate_polynomial_degree(polynomial.degree())?;
    // 计算 p(z)。
    let value = polynomial.evaluate(&point);
    // 构建 witness 多项式 w(X) = (p(X) - p(z)) / (X - z)，并对 w 进行 KZG commitment 得到证明。
    let witness_polynomial = build_witness_polynomial(polynomial, point, value)?;
    let witness_commitment = commit_polynomial(&witness_polynomial, srs)?;

    Ok(KzgOpening {
        point,
        value,
        proof: KzgOpeningProof { witness_commitment },
    })
}

/// Function: build witness polynomial `w(X) = (p(X) - p(z)) / (X - z)`.
/// Input: polynomial `p`, point `z`, and value `p(z)`.
/// Output: witness polynomial `w`.
/// Example: used internally by KZG open.
fn build_witness_polynomial(
    polynomial: &DensePolynomial<Fr>,
    point: Fr,
    value: Fr,
) -> Result<DensePolynomial<Fr>> {
    // 构建常数多项式 `f(X) = 常数`。
    let constant_polynomial = DensePolynomial::from_coefficients_vec(vec![value]);
    // 构建分子多项式 ，直接在多项式上计算，相当于常数项相减。
    let numerator_polynomial = polynomial - &constant_polynomial;
    // 构建分母多项式 `g(X) = X - z`。也是多项式形式
    let divisor_polynomial = DensePolynomial::from_coefficients_vec(vec![-point, Fr::from(1u64)]);

    let (quotient, remainder) =
        DenseOrSparsePolynomial::from(&numerator_polynomial)
            .divide_with_q_and_r(&DenseOrSparsePolynomial::from(&divisor_polynomial))
            .ok_or(PlonkError::InvalidInput(
                "failed to divide by (X - z) while building kzg witness polynomial",
            ))?;

    ensure(
        remainder.is_zero(),
        "kzg witness polynomial division remainder must be zero",
    )?;

    Ok(quotient)
}
