//! Step 3.1：Witness evaluations 到多项式的插值工具。
//!
//! 设计约束：
//! - 只做 evals -> poly（IFFT）纯函数
//! - 不引入任何电路数据提取逻辑

use ark_poly::{univariate::DensePolynomial, EvaluationDomain};

use crate::{
    domain::{evaluations_to_polynomial, PlonkDomain},
    error::{PlonkError, Result},
    witness::columns::WitnessColumns,
};

/// Witness 三列对应的多项式。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessPolynomials {
    pub wire_a_poly: DensePolynomial<crate::curve::Fr>,
    pub wire_b_poly: DensePolynomial<crate::curve::Fr>,
    pub wire_c_poly: DensePolynomial<crate::curve::Fr>,
}

/// 把单列 evaluations 插值为 `DensePolynomial`。
/// 示例：输入 domain=8 点、evaluations 长度=8；输出该列在 H 上对应的唯一低阶插值多项式。
/// ifft
pub fn interpolate_column_evaluations(
    domain: &PlonkDomain,
    evaluations: &[crate::curve::Fr],
) -> Result<DensePolynomial<crate::curve::Fr>> {
    evaluations_to_polynomial(domain, evaluations)
}

/// 把 `WitnessColumns` 的三列 evaluations 一次性插值为多项式。
/// 示例：输入 a/b/c 三列长度都等于 domain_size；输出 `wire_a_poly/wire_b_poly/wire_c_poly`。
pub fn interpolate_witness_column_polynomials(
    domain: &PlonkDomain,
    columns: &WitnessColumns,
) -> Result<WitnessPolynomials> {
    if domain.size() != columns.domain_size() {
        return Err(PlonkError::InconsistentLength(
            "domain size does not match witness column domain_size",
        ));
    }

    Ok(WitnessPolynomials {
        wire_a_poly: interpolate_column_evaluations(domain, &columns.wire_a_evaluations)?,
        wire_b_poly: interpolate_column_evaluations(domain, &columns.wire_b_evaluations)?,
        wire_c_poly: interpolate_column_evaluations(domain, &columns.wire_c_evaluations)?,
    })
}
