//! Step 1.1：vanishing polynomial 工具。

use ark_poly::EvaluationDomain;

use crate::curve::Fr;

use super::radix2_domain::PlonkDomain;

/// 计算 `Z_H(point)`，其中 `H` 是当前 domain 对应的乘法子群。
/// 也就是直接算小时多项式子的值
pub fn vanishing_value(domain: &PlonkDomain, point: Fr) -> Fr {
    domain.evaluate_vanishing_polynomial(point)
}
