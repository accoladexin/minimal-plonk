//! Step 4.3: selector evaluations 的提取接口。
//!
//! 这里的目标和 `witness::columns` 一样：
//! - 只提供 padded circuit 上的 canonical evaluations
//! - 明确要求先 `pad_to_domain()`
//! - 保证 selector 与 witness 使用同一个 domain 语义

use crate::{
    cs::Circuit,
    curve::Fr,
    error::{PlonkError, Result},
};

/// padded circuit 上五个 selector 列的 evaluations。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorColumns {
    pub q_l_evaluations: Vec<Fr>,
    pub q_r_evaluations: Vec<Fr>,
    pub q_o_evaluations: Vec<Fr>,
    pub q_m_evaluations: Vec<Fr>,
    pub q_c_evaluations: Vec<Fr>,
    domain_size: usize,
}

impl SelectorColumns {
    /// 功能说明：从已经 pad 的电路中提取 selector evaluations。
    /// 输入：已经调用过 `pad_to_domain()` 的 `Circuit`。
    /// 输出：`SelectorColumns`。
    /// 示例：4 行 padded circuit 会返回长度都为 4 的五列 evaluations。
    pub fn from_padded_circuit(circuit: &Circuit) -> Result<Self> {
        let domain_size = circuit.domain_size().ok_or(PlonkError::InvalidInput(
            "circuit must call pad_to_domain() before selector extraction",
        ))?;

        if domain_size != circuit.num_rows() {
            return Err(PlonkError::InconsistentLength(
                "after pad_to_domain, domain_size must equal circuit row length",
            ));
        }

        let mut q_l_evaluations = Vec::with_capacity(domain_size);
        let mut q_r_evaluations = Vec::with_capacity(domain_size);
        let mut q_o_evaluations = Vec::with_capacity(domain_size);
        let mut q_m_evaluations = Vec::with_capacity(domain_size);
        let mut q_c_evaluations = Vec::with_capacity(domain_size);

        for row in circuit.rows() {
            q_l_evaluations.push(row.q_l);
            q_r_evaluations.push(row.q_r);
            q_o_evaluations.push(row.q_o);
            q_m_evaluations.push(row.q_m);
            q_c_evaluations.push(row.q_c);
        }

        Self::from_evaluations(
            q_l_evaluations,
            q_r_evaluations,
            q_o_evaluations,
            q_m_evaluations,
            q_c_evaluations,
            domain_size,
        )
    }

    /// 功能说明：从外部给定 evaluations 构造 selector 列，并做长度一致性检查。
    /// 输入：五列 evaluations 和 `domain_size`。
    /// 输出：合法时返回 `SelectorColumns`。
    /// 示例：五列长度都为 8 且 `domain_size=8` 时构造成功。
    pub fn from_evaluations(
        q_l_evaluations: Vec<Fr>,
        q_r_evaluations: Vec<Fr>,
        q_o_evaluations: Vec<Fr>,
        q_m_evaluations: Vec<Fr>,
        q_c_evaluations: Vec<Fr>,
        domain_size: usize,
    ) -> Result<Self> {
        validate_evaluation_lengths(
            &q_l_evaluations,
            &q_r_evaluations,
            &q_o_evaluations,
            &q_m_evaluations,
            &q_c_evaluations,
            domain_size,
        )?;

        Ok(Self {
            q_l_evaluations,
            q_r_evaluations,
            q_o_evaluations,
            q_m_evaluations,
            q_c_evaluations,
            domain_size,
        })
    }

    /// 功能说明：返回这些 selector evaluations 对应的 domain 大小。
    /// 输入：`self`。
    /// 输出：`usize`。
    /// 示例：五列长度均为 16 时返回 16。
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }
}

/// 功能说明：检查五列 selector evaluations 是否与 `domain_size` 严格一致。
/// 输入：五列切片和 `domain_size`。
/// 输出：一致时返回 `Ok(())`，否则返回错误。
/// 示例：只要任意一列长度不同就会失败。
fn validate_evaluation_lengths(
    q_l_evaluations: &[Fr],
    q_r_evaluations: &[Fr],
    q_o_evaluations: &[Fr],
    q_m_evaluations: &[Fr],
    q_c_evaluations: &[Fr],
    domain_size: usize,
) -> Result<()> {
    let expected = domain_size;
    let lengths = [
        q_l_evaluations.len(),
        q_r_evaluations.len(),
        q_o_evaluations.len(),
        q_m_evaluations.len(),
        q_c_evaluations.len(),
    ];

    if lengths.iter().any(|len| *len != expected) {
        return Err(PlonkError::InconsistentLength(
            "q_l/q_r/q_o/q_m/q_c lengths must all equal domain_size",
        ));
    }

    Ok(())
}
