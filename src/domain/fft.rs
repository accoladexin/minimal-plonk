//! Step 1.1：FFT / IFFT 与“点值 <-> 系数”转换工具。

use ark_poly::{DenseUVPolynomial, EvaluationDomain, univariate::DensePolynomial};

use crate::{curve::Fr, error::Result, validate::ensure};

use super::radix2_domain::PlonkDomain;

/// 在给定 domain 上执行 FFT（系数 -> 点值）。
pub fn fft(domain: &PlonkDomain, coefficients: &[Fr]) -> Result<Vec<Fr>> {
    // 校验：系数的数量必须刚好填满 Domain（例如 2^n）
    ensure(
        coefficients.len() == domain.size(),
        "系数向量长度必须等于 domain 大小",
    )?;
    let mut values = coefficients.to_vec();
    // 执行原位 FFT，直接在 values 内存中修改结果
    domain.fft_in_place(&mut values);
    Ok(values)
}

/// 在给定 domain 上执行 IFFT（点值 -> 系数）。
pub fn ifft(domain: &PlonkDomain, evaluations: &[Fr]) -> Result<Vec<Fr>> {
    ensure(
        evaluations.len() == domain.size(),
        "evaluation vector length must equal domain size",
    )?;
    let mut coefficients = evaluations.to_vec();
    domain.ifft_in_place(&mut coefficients);
    Ok(coefficients)
}

/// 将 domain 上的点值插值为稠密多项式
/// （稠密多项式主要是为了可以快速计算，内存里所有有系数都存了，不会不存0）。
pub fn evaluations_to_polynomial(
    domain: &PlonkDomain,
    evaluations: &[Fr],
) -> Result<DensePolynomial<Fr>> {
    let coefficients = ifft(domain, evaluations)?;
    Ok(DensePolynomial::from_coefficients_vec(coefficients))
}

/// 将稠密多项式在 domain 上求值得到点值向量。
/// 系数 -->FFT -->点值
pub fn polynomial_to_evaluations(
    domain: &PlonkDomain,
    polynomial: &DensePolynomial<Fr>,
) -> Result<Vec<Fr>> {
    ensure(
        polynomial.coeffs.len() <= domain.size(),
        "polynomial degree exceeds domain capacity",
    )?;

    let mut padded_coefficients = polynomial.coeffs.clone();
    padded_coefficients.resize(domain.size(), Fr::from(0u64)); // 填充零直到长度等于 domain 大小
    fft(domain, &padded_coefficients)
}
