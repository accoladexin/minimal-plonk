//! Step 1.1 验收测试：
//! - FFT ∘ IFFT = identity
//! - L_i(g^j) = delta_ij
//! - Z_H(g^i) = 0
//! - 点值 <-> 多项式 插值一致

use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use minimal_plonk::{
    curve::Fr,
    domain::{
        build_domain_from_log_size, evaluations_to_polynomial, fft, ifft, lagrange_basis_value,
        polynomial_to_evaluations, vanishing_value,
    },
};

/// 构造一组稳定测试系数，避免随机性影响回归结果。
fn sample_coefficients(size: usize) -> Vec<Fr> {
    (1..=size).map(|index| Fr::from(index as u64)).collect()
}

/// 验证在同一个 domain 上，FFT 后再 IFFT 会回到原始系数。
#[test]
fn fft_then_ifft_is_identity() {
    let domain = build_domain_from_log_size(3).expect("domain construction should succeed");
    let coefficients = sample_coefficients(domain.size());
    let evaluations = fft(&domain, &coefficients).expect("fft should succeed");
    let recovered = ifft(&domain, &evaluations).expect("ifft should succeed");

    assert_eq!(coefficients, recovered);
}

/// 验证 Lagrange 基函数在群点上的 Kronecker delta 性质。
#[test]
fn lagrange_basis_is_kronecker_delta_on_domain_points() {
    let domain = build_domain_from_log_size(3).expect("domain construction should succeed");
    let n = domain.size();

    for row in 0..n {
        let point = domain.element(row);
        for column in 0..n {
            let value =
                lagrange_basis_value(&domain, column, point).expect("lagrange eval should work");
            if row == column {
                assert_eq!(value, Fr::from(1u64));
            } else {
                assert_eq!(value, Fr::zero());
            }
        }
    }
}

/// 验证 vanishing polynomial 在子群每个点上都为零。
#[test]
fn vanishing_polynomial_is_zero_on_domain_points() {
    let domain = build_domain_from_log_size(4).expect("domain construction should succeed");
    for point in domain.elements() {
        assert_eq!(vanishing_value(&domain, point), Fr::zero());
    }
}

/// 验证“点值 -> 多项式 -> 点值”在同一 domain 上保持一致。
#[test]
fn interpolation_round_trip_matches_original_evaluations() {
    let domain = build_domain_from_log_size(3).expect("domain construction should succeed");
    let coefficients = sample_coefficients(domain.size());
    let evaluations = fft(&domain, &coefficients).expect("fft should succeed");
    let polynomial =
        evaluations_to_polynomial(&domain, &evaluations).expect("interpolation should succeed");
    let recovered =
        polynomial_to_evaluations(&domain, &polynomial).expect("evaluation should succeed");

    assert_eq!(evaluations, recovered);
}
