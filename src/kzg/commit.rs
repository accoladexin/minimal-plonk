//! Step 6.1: KZG polynomial commitment.

use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_poly::{Polynomial, univariate::DensePolynomial};

use crate::{curve::G1, error::Result, kzg::srs::KzgSrs, types::Commitment};

/// Function: commit to a polynomial using KZG SRS.
/// Input: polynomial and SRS.
/// Output: `Commitment = [p(tau)]_1`.
/// Example: `let c = commit_polynomial(&poly, &srs)?;`.
pub fn commit_polynomial(
    polynomial: &DensePolynomial<crate::curve::Fr>,
    srs: &KzgSrs,
) -> Result<Commitment> {
    // 检查多项式的度数是否超过 SRS 支持的最大度数。
    srs.validate_polynomial_degree(polynomial.degree())?;

    let mut accumulator = G1::zero();
    // - zip：把多项式的系数和 SRS 里的幂次点一对一挂钩。
    // - mul_bigint：这是 `arkworks` 执行椭圆曲线点乘的函数。它把有限域元素（系数）转换成大整数，然后去“拉伸”曲线上的点。
    // - +=：这是曲线上的点加运算。
    for (coefficient, srs_power) in polynomial.coeffs.iter().zip(srs.g1_powers.iter()) {
        if coefficient.is_zero() {
            continue;
        }
        accumulator += srs_power.mul_bigint(coefficient.into_bigint());
    }

    // 最后把累加器里的点转换成 affine（适合存储） 形式，封装成 `Commitment`。
    Ok(Commitment::from_projective(accumulator))
}
