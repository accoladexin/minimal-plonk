//! Shared Step 5 quotient-input type.

use crate::{
    cs::SelectorColumns,
    error::{PlonkError, Result as PlonkResult},
    permutation::{GrandProductEvaluations, SigmaMapping},
    witness::WitnessColumns,
};

/// Minimal same-domain Step 5 input bundle shared across quotient code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotientInputs {
    pub domain_size: usize,
    pub witness_columns: WitnessColumns,
    pub selector_columns: SelectorColumns,
    pub sigma_mapping: SigmaMapping,
    pub grand_product_evaluations: GrandProductEvaluations,
}

impl QuotientInputs {
    /// 功能说明：校验 Step 5 所需输入是否处于同一个 size-`n` domain 上。
    /// 输入：witness columns、selector columns、sigma mapping、grand product evaluations。
    /// 输出：校验通过时返回 `QuotientInputs`，否则返回长度不一致错误。
    /// 示例：当四组输入都对应同一 padded domain 时，该构造会成功。
    pub fn new(
        witness_columns: WitnessColumns,
        selector_columns: SelectorColumns,
        sigma_mapping: SigmaMapping,
        grand_product_evaluations: GrandProductEvaluations,
    ) -> PlonkResult<Self> {
        let domain_size = witness_columns.domain_size();

        if selector_columns.domain_size() != domain_size {
            return Err(PlonkError::InconsistentLength(
                "selector domain_size must match witness domain_size",
            ));
        }
        if sigma_mapping.domain_size() != domain_size {
            return Err(PlonkError::InconsistentLength(
                "sigma domain_size must match witness domain_size",
            ));
        }
        if grand_product_evaluations.domain_size != domain_size {
            return Err(PlonkError::InconsistentLength(
                "grand product domain_size must match witness domain_size",
            ));
        }
        if grand_product_evaluations.grand_product_evaluations.len() != domain_size + 1 {
            return Err(PlonkError::InconsistentLength(
                "grand product evaluations length must equal domain_size + 1",
            ));
        }

        Ok(Self {
            domain_size,
            witness_columns,
            selector_columns,
            sigma_mapping,
            grand_product_evaluations,
        })
    }
}
