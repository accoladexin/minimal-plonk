//! Step 1.1：Lagrange 基函数相关工具。
//! 主要是计算论文中的L_I(x)的值(拉格朗日基），既可以一次性计算全部基函数值，也可以单独计算某个基函数值。

use ark_poly::EvaluationDomain;

use crate::{curve::Fr, error::Result, validate::ensure};

use super::radix2_domain::PlonkDomain;

/// 计算给定点处的全部 Lagrange 基函数值：`[L_0(x), ..., L_{n-1}(x)]`。
/// 把结果的值相加起来为1，因为这是一条为y=1的常数多项式在点x处的评估结果。
pub fn lagrange_values_at_point(domain: &PlonkDomain, point: Fr) -> Vec<Fr> {
    domain.evaluate_all_lagrange_coefficients(point)
}

/// 计算给定索引的 Lagrange 基函数值：`L_index(point)`。
pub fn lagrange_basis_value(domain: &PlonkDomain, index: usize, point: Fr) -> Result<Fr> {
    ensure(index < domain.size(), "lagrange index out of range")?;
    let values = lagrange_values_at_point(domain, point);
    Ok(values[index])
}
