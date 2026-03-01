//! Step 1.1 Lagrange 工具测试：
//! - `lagrange_values_at_point` 返回的向量长度与数值正确
//! - `lagrange_basis_value` 与全量结果一致，并满足群点上的 delta 性质

use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use minimal_plonk::{
    curve::Fr,
    domain::{build_domain_from_log_size, lagrange_basis_value, lagrange_values_at_point},
};

/// 在任意点 `x`，所有 Lagrange 基函数值之和应为 1。
#[test]
fn lagrange_values_vector_is_well_formed() {
    let domain = build_domain_from_log_size(3).expect("domain construction should succeed");
    // println!("domain size: {}, log_size: {}, generator: {:?}\n", domain.size(), domain.log_size_of_group(), domain.group_gen());
    let point = Fr::from(11u64);
    // println!("evaluating lagrange basis at point: {:?}\n", point);
    let values = lagrange_values_at_point(&domain, point);    println!("lagrange values at point: {:?}\n", values);
    assert_eq!(values.len(), domain.size());

    let sum = values
        .iter()
        .copied()
        .fold(Fr::zero(), |accumulator, value| accumulator + value);
    assert_eq!(sum, Fr::from(1u64));
}

/// 在群点 `g^j` 处，`L_i(g^j)` 应满足 Kronecker delta：i=j 时为 1，否则为 0。
#[test]
fn lagrange_basis_value_matches_delta_on_domain_points() {
    let domain = build_domain_from_log_size(3).expect("domain construction should succeed");
    let n = domain.size();

    for row in 0..n {
        let point = domain.element(row);
        let all_values = lagrange_values_at_point(&domain, point);

        for column in 0..n {
            let single = lagrange_basis_value(&domain, column, point)
                .expect("single lagrange value should succeed");
            assert_eq!(single, all_values[column]);

            if row == column {
                assert_eq!(single, Fr::from(1u64));
            } else {
                assert_eq!(single, Fr::zero());
            }
        }
    }
}

/// 索引越界时应返回错误，防止调用方读到非法位置。
#[test]
fn lagrange_basis_value_rejects_out_of_range_index() {
    let domain = build_domain_from_log_size(3).expect("domain construction should succeed");
    let point = Fr::from(9u64);

    let result = lagrange_basis_value(&domain, domain.size(), point);
    assert!(result.is_err());
}
