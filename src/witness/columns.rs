//! Step 3.1：Witness 三列（a/b/c）evaluations 的 canonical 表示。
//!
//! 设计目标：
//! - 只保存 Vec<Fr> 形式的 evaluations
//! - 从 Circuit 提取时强制要求先 `pad_to_domain()`

use ark_poly::univariate::DensePolynomial;

use crate::{
    cs::Circuit,
    curve::Fr,
    domain::PlonkDomain,
    error::{PlonkError, Result},
    witness::interpolate::interpolate_column_evaluations,
};

/// Witness 三列在子群 H 上的 evaluations。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessColumns {
    pub wire_a_evaluations: Vec<Fr>,
    pub wire_b_evaluations: Vec<Fr>,
    pub wire_c_evaluations: Vec<Fr>,
    domain_size: usize,
}

impl WitnessColumns {
    /// 从已完成 `pad_to_domain()` 的电路提取 witness 三列。
    /// 示例：输入一个已 pad 到 8 行的电路；输出三列长度都为 8 的 evaluations。
    pub fn from_padded_circuit(circuit: &Circuit) -> Result<Self> {
        let domain_size = circuit.domain_size().ok_or(PlonkError::InvalidInput(
            "circuit must call pad_to_domain() before Step 3.1 witness extraction",
        ))?;

        if domain_size != circuit.num_rows() {
            return Err(PlonkError::InconsistentLength(
                "after pad_to_domain, domain_size must equal circuit row length",
            ));
        }
        
        let mut wire_a_evaluations = Vec::with_capacity(domain_size);
        let mut wire_b_evaluations = Vec::with_capacity(domain_size);
        let mut wire_c_evaluations = Vec::with_capacity(domain_size);

        for row in circuit.rows() {
            wire_a_evaluations.push(row.wire_a);
            wire_b_evaluations.push(row.wire_b);
            wire_c_evaluations.push(row.wire_c);
        }

        Self::from_evaluations(
            wire_a_evaluations,
            wire_b_evaluations,
            wire_c_evaluations,
            domain_size,
        )
    }

    /// 直接从给定 evaluations 构造 `WitnessColumns`，并执行长度一致性校验。
    /// 示例：输入三列长度都为 16 且 domain_size=16；输出校验通过的 `WitnessColumns`。
    pub fn from_evaluations(
        wire_a_evaluations: Vec<Fr>,
        wire_b_evaluations: Vec<Fr>,
        wire_c_evaluations: Vec<Fr>,
        domain_size: usize,
    ) -> Result<Self> {
        validate_evaluation_lengths(
            &wire_a_evaluations,
            &wire_b_evaluations,
            &wire_c_evaluations,
            domain_size,
        )?;

        Ok(Self {
            wire_a_evaluations,
            wire_b_evaluations,
            wire_c_evaluations,
            domain_size,
        })
    }

    /// 返回当前 witness evaluations 对应的 domain 大小。
    /// 示例：如果 a/b/c 列长度都为 32，则返回 32。
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// 点值变成多项式（evaluations -> polynomial）的按需插值接口。
    /// 底层是iffft，但是是填充之后的 evaluations，长度等于 domain_size。
    /// 按需把 a 列 evaluations 插值为 `DensePolynomial`。
    /// 示例：输入 8 点 evaluations；输出满足 `a_poly(g^i)=a_eval[i]` 的多项式。
    pub fn interpolate_wire_a(
        &self,
        domain: &PlonkDomain,
    ) -> Result<DensePolynomial<Fr>> {
        interpolate_column_evaluations(domain, &self.wire_a_evaluations)
    }

    /// 按需把 b 列 evaluations 插值为 `DensePolynomial`。
    /// 示例：输入 8 点 evaluations；输出满足 `b_poly(g^i)=b_eval[i]` 的多项式。
    pub fn interpolate_wire_b(
        &self,
        domain: &PlonkDomain,
    ) -> Result<DensePolynomial<Fr>> {
        interpolate_column_evaluations(domain, &self.wire_b_evaluations)
    }

    /// 按需把 c 列 evaluations 插值为 `DensePolynomial`。
    /// 示例：输入 8 点 evaluations；输出满足 `c_poly(g^i)=c_eval[i]` 的多项式。
    pub fn interpolate_wire_c(
        &self,
        domain: &PlonkDomain,
    ) -> Result<DensePolynomial<Fr>> {
        interpolate_column_evaluations(domain, &self.wire_c_evaluations)
    }
}

/// 校验三列长度是否都与 domain_size 严格一致。
/// 示例：a/b/c 长度分别为 8/8/8 且 domain_size=8 时通过；任一不一致时返回 InconsistentLength。
fn validate_evaluation_lengths(
    wire_a_evaluations: &[Fr],
    wire_b_evaluations: &[Fr],
    wire_c_evaluations: &[Fr],
    domain_size: usize,
) -> Result<()> {
    if wire_a_evaluations.len() != wire_b_evaluations.len()
        || wire_a_evaluations.len() != wire_c_evaluations.len()
        || wire_a_evaluations.len() != domain_size
    {
        return Err(PlonkError::InconsistentLength(
            "a_eval.len == b_eval.len == c_eval.len == domain_size must hold",
        ));
    }

    Ok(())
}
