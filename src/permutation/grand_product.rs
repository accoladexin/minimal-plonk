//! Step 4.2: permutation argument 的 grand product evaluations。
//!
//! 关键约定：
//! - 输入是 a/b/c 的 evaluations、sigma、beta、gamma
//! - A/B/C 列因子固定为 1/2/3
//! - 行标签使用子群元素 `omega^i`
//! - `grand_product_evaluations` 的长度固定为 `n + 1`
//! - `grand_product_evaluations[0] = Z(1)`
//! - `grand_product_evaluations[n] = Z(omega^n)`，同时作为 closing value

use ark_ff::Field;
use ark_poly::EvaluationDomain;
use ark_poly::univariate::DensePolynomial;

use crate::{
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, evaluations_to_polynomial},
    error::{PlonkError, Result},
    permutation::{Column, Pos, SigmaMapping, pos_to_wire_id, validate_sigma_bijection},
    validate::ensure,
};

/// B 列的固定标签因子 `k1`。
pub const K1: u64 = 2;
/// C 列的固定标签因子 `k2`。
pub const K2: u64 = 3;

/// Step 4.2 的 canonical 输出：grand product 的 evaluations。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrandProductEvaluations {
    pub domain_size: usize,
    pub grand_product_evaluations: Vec<Fr>, // 连乘结果的 evaluations，长度为 n + 1
}

/// 功能说明：根据 witness evaluations、sigma、beta、gamma 计算 grand product evaluations。
/// 输入：`a_eval`、`b_eval`、`c_eval`、`sigma`、`beta`、`gamma`。
/// 输出：长度为 `n + 1` 的 `GrandProductEvaluations`。
/// 示例：`compute_grand_product_evaluations(&a, &b, &c, &sigma, beta, gamma)?;`
pub fn compute_grand_product_evaluations(
    a_eval: &[Fr],
    b_eval: &[Fr],
    c_eval: &[Fr],
    sigma: &SigmaMapping,
    beta: Fr,
    gamma: Fr,
) -> Result<GrandProductEvaluations> {
    // Paper mapping: Prover Round 2, build Z from the permutation recurrence.
    validate_inputs(a_eval, b_eval, c_eval, sigma)?;
    let domain_size = a_eval.len();
    let domain = build_domain_from_size(domain_size)?;

    let mut z_eval = Vec::with_capacity(domain_size + 1);
    // 初始化 Z(1) = 1，作为递推的起点。
    z_eval.push(Fr::from(1u64));
    // 递推计算 Z(omega^i) 直到 Z(omega^n)，共 n 步。
    for row_index in 0..domain_size {
        let previous_z = z_eval[row_index];
        // 对应round2中每行的 numerator/denominator 计算，构成递推关系的核心。
        let current_terms = row_terms(
            &domain,
            sigma, // 记录置换
            row_index,
            a_eval[row_index],
            b_eval[row_index],
            c_eval[row_index],
            beta,
            gamma,
        )?;

        // 分母求逆时需要检查是否为零，避免非法输入导致的 panic。
        let denominator_inverse = current_terms
            .denominator
            .inverse()
            .ok_or(PlonkError::InvalidInput("permutation denominator is zero"))?;
        // round2中的z_eval递推关系：Z(omega^(i+1)) = Z(omega^i) * numerator / denominator
        let next_z = previous_z * current_terms.numerator * denominator_inverse;
        z_eval.push(next_z);
    }

    Ok(GrandProductEvaluations {
        domain_size,
        grand_product_evaluations: z_eval,
    })
}

/// 功能说明：检查单行 grand product 递推是否成立。
/// 输入：前一项、后一项和这一行的 numerator/denominator。
/// 输出：`bool`。
/// 示例：若某行 witness 被篡改，通常会返回 `false`。
pub fn verify_single_grand_product_step(
    previous_z: Fr,
    next_z: Fr,
    terms: &RowTerms,
) -> Result<bool> {
    // Paper mapping: one recurrence step Z(next) = Z(cur) * numerator / denominator.
    let denominator_inverse = terms
        .denominator
        .inverse()
        .ok_or(PlonkError::InvalidInput("permutation denominator is zero"))?;
    let expected_next = previous_z * terms.numerator * denominator_inverse;
    Ok(next_z == expected_next)
}

/// 功能说明：检查整条 grand product 递推是否成立，不检查首尾边界。
/// 输入：`z_eval`、witness evaluations、sigma、beta、gamma。
/// 输出：`bool`。
/// 示例：给定错误 witness 或错误 sigma 时，会返回 `false` 或错误。
pub fn verify_grand_product_recurrence(
    z_eval: &[Fr],
    a_eval: &[Fr],
    b_eval: &[Fr],
    c_eval: &[Fr],
    sigma: &SigmaMapping,
    beta: Fr,
    gamma: Fr,
) -> Result<bool> {
    // Paper mapping: verifier-style check of the same Round 2 recurrence before quotient aggregation.
    validate_inputs(a_eval, b_eval, c_eval, sigma)?;
    let domain_size = a_eval.len();
    ensure(
        z_eval.len() == domain_size + 1,
        "grand product evaluations length must equal n + 1",
    )?;

    let domain = build_domain_from_size(domain_size)?;
    for row_index in 0..domain_size {
        let terms = row_terms(
            &domain,
            sigma,
            row_index,
            a_eval[row_index],
            b_eval[row_index],
            c_eval[row_index],
            beta,
            gamma,
        )?;
        let is_valid =
            verify_single_grand_product_step(z_eval[row_index], z_eval[row_index + 1], &terms)?;
        if !is_valid {
            return Ok(false);
        }
    }

    Ok(true)
}

/// 功能说明：检查 grand product 的边界条件。
/// 输入：`z_eval` 和 `domain_size`。
/// 输出：`bool`。
/// 示例：正确 copy 关系下应满足 `Z(1)=1` 且 `Z(omega^n)=1`。
pub fn verify_grand_product_boundary(z_eval: &[Fr], domain_size: usize) -> Result<bool> {
    // Paper mapping: permutation boundary checks Z(1)=1 and Z(omega^n)=1.
    ensure(
        z_eval.len() == domain_size + 1,
        "grand product evaluations length must equal n + 1",
    )?;
    let one = Fr::from(1u64);
    Ok(z_eval[0] == one && z_eval[domain_size] == one)
}

/// 功能说明：按需把 grand product evaluations 插值成多项式。
/// 输入：长度为 `n + 1` 的 `z_eval` 和 `domain_size`。
/// 输出：只使用前 `n` 项插值得到的稠密多项式。
/// 示例：`let z_poly = interpolate_grand_product_evaluations(&z_eval, 8)?;`
pub fn interpolate_grand_product_evaluations(
    z_eval: &[Fr],
    domain_size: usize,
) -> Result<DensePolynomial<Fr>> {
    // Paper mapping: recover the degree-<n polynomial Z(X) from its canonical H evaluations.
    ensure(
        z_eval.len() == domain_size + 1,
        "grand product evaluations length must equal n + 1",
    )?;
    let domain = build_domain_from_size(domain_size)?;
    evaluations_to_polynomial(&domain, &z_eval[..domain_size])
}

/// 单行递推所需的 numerator/denominator。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowTerms {
    pub numerator: Fr,
    pub denominator: Fr,
}

/// Step 5.1 在构造 sigma 多项式时需要的三列 sigma tag evaluations。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigmaTagEvaluations {
    pub sigma_a_evaluations: Vec<Fr>,
    pub sigma_b_evaluations: Vec<Fr>,
    pub sigma_c_evaluations: Vec<Fr>,
}

/// 功能说明：为 Step 5.1 暴露单行 permutation 的 numerator/denominator 计算。
/// 输入：domain、sigma、行索引、该行 a/b/c、beta、gamma。
/// 输出：该行对应的 `RowTerms`。
/// 示例：Step 5.1 可用它构造 `Z[i+1]*denominator_i - Z[i]*numerator_i`。
pub fn compute_row_terms_for_quotient(
    domain: &PlonkDomain,
    sigma: &SigmaMapping,
    row_index: usize,
    a_value: Fr,
    b_value: Fr,
    c_value: Fr,
    beta: Fr,
    gamma: Fr,
) -> Result<RowTerms> {
    // Paper mapping: expose the row numerator/denominator factors reused inside the quotient identity.
    row_terms(
        domain, sigma, row_index, a_value, b_value, c_value, beta, gamma,
    )
}

/// 功能说明：为 Step 5.1 构造三列 sigma tag 在原始 H-domain 上的 evaluations。
/// 输入：原始 domain 与 sigma。
/// 输出：`(sigma_a, sigma_b, sigma_c)` 三列 tag evaluations。
/// 示例：后续可以把这些点值插值成 `S_sigma1(X), S_sigma2(X), S_sigma3(X)`。
pub(crate) fn compute_sigma_tag_evaluations_for_quotient(
    domain: &PlonkDomain,
    sigma: &SigmaMapping,
) -> Result<SigmaTagEvaluations> {
    // Paper mapping: sigma-image tags corresponding to the quotient's S_sigma1/S_sigma2/S_sigma3 values.
    validate_sigma_bijection(sigma)?;
    ensure(
        sigma.domain_size() == domain.size(),
        "sigma domain_size must match the original H-domain size",
    )?;

    let domain_size = domain.size();
    let mut sigma_a_evaluations = Vec::with_capacity(domain_size);
    let mut sigma_b_evaluations = Vec::with_capacity(domain_size);
    let mut sigma_c_evaluations = Vec::with_capacity(domain_size);

    for row_index in 0..domain_size {
        // 对应位置的在coset上的值，也就是H U k1H Uk2U
        sigma_a_evaluations.push(sigma_target_tag(sigma, domain, Column::A, row_index)?);
        sigma_b_evaluations.push(sigma_target_tag(sigma, domain, Column::B, row_index)?);
        sigma_c_evaluations.push(sigma_target_tag(sigma, domain, Column::C, row_index)?);
    }

    Ok(SigmaTagEvaluations {
        sigma_a_evaluations,
        sigma_b_evaluations,
        sigma_c_evaluations,
    })
}

/// 功能说明：校验 grand product 入口需要的输入是否一致。
/// 输入：三列 witness evaluations 和 sigma。
/// 输出：`Ok(())` 或错误。
/// 示例：空 witness、长度不一致或坏 sigma 都会被拒绝。
fn validate_inputs(
    a_eval: &[Fr],
    b_eval: &[Fr],
    c_eval: &[Fr],
    sigma: &SigmaMapping,
) -> Result<()> {
    ensure(!a_eval.is_empty(), "witness evaluations must be non-empty")?;
    ensure(
        a_eval.len() == b_eval.len() && a_eval.len() == c_eval.len(),
        "a_eval, b_eval, c_eval must have the same length",
    )?;
    ensure(
        sigma.domain_size() == a_eval.len(),
        "sigma domain_size must match witness evaluation length",
    )?;
    validate_sigma_bijection(sigma)?;
    Ok(())
}

/// 功能说明：构造某一行递推所需的 numerator/denominator。
/// 输入：domain、sigma、当前行索引、当前行 a/b/c、beta、gamma。
/// 输出：`RowTerms`。
/// 示例：正确 copy 关系下，所有行连乘后 closing value 应回到 1。
fn row_terms(
    domain: &PlonkDomain,
    sigma: &SigmaMapping,
    row_index: usize,
    a_value: Fr,
    b_value: Fr,
    c_value: Fr,
    beta: Fr,
    gamma: Fr,
) -> Result<RowTerms> {
    // Paper mapping: the per-row products that appear in both the grand product and quotient formulas.
    let row_label = domain.element(row_index);
    let one = Fr::from(1u64);
    let k1 = Fr::from(K1);
    let k2 = Fr::from(K2);

    let a_tag = one * row_label;
    let b_tag = k1 * row_label;
    let c_tag = k2 * row_label;

    let sigma_a_tag = sigma_target_tag(sigma, domain, Column::A, row_index)?;
    let sigma_b_tag = sigma_target_tag(sigma, domain, Column::B, row_index)?;
    let sigma_c_tag = sigma_target_tag(sigma, domain, Column::C, row_index)?;

    let numerator = (a_value + beta * a_tag + gamma)
        * (b_value + beta * b_tag + gamma)
        * (c_value + beta * c_tag + gamma);
    let denominator = (a_value + beta * sigma_a_tag + gamma)
        * (b_value + beta * sigma_b_tag + gamma)
        * (c_value + beta * sigma_c_tag + gamma);

    Ok(RowTerms {
        numerator,
        denominator,
    })
}

/// 功能说明：把 sigma 目标 id 转成 `column_factor * omega^row` 形式的标签。
/// 输入：source 列、source 行以及 sigma/domain。
/// 输出：目标位置的标签值。
/// 示例：若目标是 `(B, 3)`，则返回 `k1 * omega^3`。
fn sigma_target_tag(
    sigma: &SigmaMapping,
    domain: &PlonkDomain,
    source_column: Column, // 这个就是tag，表示 a 列或者b列，或者c列
    source_row: usize, //行的位置 [1,,,n]
) -> Result<Fr> {
    // Paper mapping: convert one sigma target position into its tagged field element k_j * omega^i.
    let source_id = pos_to_wire_id(
        Pos {
            col: source_column,
            row: source_row,
        },
        sigma.domain_size(),
    )?;
    // 相等的位置
    let target_id = sigma.image_at(source_id)?;
    ensure(
        target_id < sigma.expected_sigma_len(),
        "sigma image out of range when mapping target tag",
    )?;

    let target_column_index = target_id / sigma.domain_size();
    let target_row = target_id % sigma.domain_size();
    let target_column = match target_column_index {
        0 => Column::A,
        1 => Column::B,
        2 => Column::C,
        _ => return Err(PlonkError::InvalidInput("target column index out of range")),
    };

    let row_label = domain.element(target_row);
    Ok(column_factor(target_column) * row_label)
}

/// 功能说明：返回列标签系数，A=1、B=K1、C=K2。
/// 输入：列枚举。
/// 输出：对应的域元素系数。
/// 示例：`column_factor(Column::B)` 返回 `Fr::from(K1)`。
fn column_factor(column: Column) -> Fr {
    match column {
        Column::A => Fr::from(1u64),
        Column::B => Fr::from(K1),
        Column::C => Fr::from(K2),
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_grand_product_evaluations, verify_grand_product_recurrence};
    use crate::{curve::Fr, permutation::SigmaMapping};

    /// 功能说明：验证 grand product 入口会显式拒绝非双射 sigma。
    /// 输入：一个未校验的坏 sigma。
    /// 输出：应返回错误。
    /// 示例：长度正确但重复像的 sigma 不得进入主路径。
    #[test]
    fn invalid_sigma_is_rejected_at_grand_product_entrypoints() {
        let a_eval = vec![Fr::from(1u64), Fr::from(2u64)];
        let b_eval = vec![Fr::from(3u64), Fr::from(4u64)];
        let c_eval = vec![Fr::from(5u64), Fr::from(6u64)];
        // 置换不对啊
        let invalid_sigma = SigmaMapping::from_raw_parts_unchecked(2, vec![0, 0, 2, 3, 4, 5]);
        let compute_result = compute_grand_product_evaluations(
            &a_eval,
            &b_eval,
            &c_eval,
            &invalid_sigma,
            Fr::from(7u64),
            Fr::from(11u64),
        );
        assert!(compute_result.is_err());

        let verify_result = verify_grand_product_recurrence(
            &[Fr::from(1u64), Fr::from(1u64), Fr::from(1u64)],
            &a_eval,
            &b_eval,
            &c_eval,
            &invalid_sigma,
            Fr::from(7u64),
            Fr::from(11u64),
        );
        assert!(verify_result.is_err());
    }
}
