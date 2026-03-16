//! Shared verifier-side fixed input types.

use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    curve::Fr,
    types::config::DomainParams,
};

/// Selector polynomials needed by the future verifier boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectorPolynomials {
    pub q_l: DensePolynomial<Fr>,
    pub q_r: DensePolynomial<Fr>,
    pub q_o: DensePolynomial<Fr>,
    pub q_m: DensePolynomial<Fr>,
    pub q_c: DensePolynomial<Fr>,
}

impl SelectorPolynomials {
    /// 功能说明：把 verifier 需要的五个 selector 多项式收口到一个对象里。
    /// 输入：`q_l`、`q_r`、`q_o`、`q_m`、`q_c` 五个多项式。
    /// 输出：一个 `SelectorPolynomials`。
    /// 示例：`SelectorPolynomials::new(q_l, q_r, q_o, q_m, q_c)`。
    pub fn new(
        q_l: DensePolynomial<Fr>,
        q_r: DensePolynomial<Fr>,
        q_o: DensePolynomial<Fr>,
        q_m: DensePolynomial<Fr>,
        q_c: DensePolynomial<Fr>,
    ) -> Self {
        Self {
            q_l,
            q_r,
            q_o,
            q_m,
            q_c,
        }
    }
}

/// Fixed sigma-tag polynomials needed by the future verifier boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct SigmaTagPolynomials {
    pub wire_a: DensePolynomial<Fr>,
    pub wire_b: DensePolynomial<Fr>,
    pub wire_c: DensePolynomial<Fr>,
}

impl SigmaTagPolynomials {
    /// 功能说明：把 verifier 需要的三个 sigma tag 多项式收口到一个对象里。
    /// 输入：A/B/C 三列的 sigma tag 多项式。
    /// 输出：一个 `SigmaTagPolynomials`。
    /// 示例：`SigmaTagPolynomials::new(id_a, id_b, id_c)`。
    pub fn new(
        wire_a: DensePolynomial<Fr>,
        wire_b: DensePolynomial<Fr>,
        wire_c: DensePolynomial<Fr>,
    ) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
        }
    }
}

/// Fixed protocol parameters needed by the future verifier boundary.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierProtocolParams {
    pub num_wire_columns: u32,
    pub permutation_column_factors: [Fr; 3],
}

impl VerifierProtocolParams {
    /// 功能说明：构造 verifier 需要的最小固定协议参数。
    /// 输入：wire 列数与 A/B/C 三列的固定区分因子。
    /// 输出：一个可序列化的 `VerifierProtocolParams`。
    /// 示例：`VerifierProtocolParams::new(3, [1, 2, 3])`。
    pub fn new(num_wire_columns: u32, permutation_column_factors: [Fr; 3]) -> Self {
        Self {
            num_wire_columns,
            permutation_column_factors,
        }
    }
}

impl Default for VerifierProtocolParams {
    /// 功能说明：提供当前实现计划默认使用的 verifier 固定协议参数。
    /// 输入：无。
    /// 输出：默认的 `VerifierProtocolParams`。
    /// 示例：`VerifierProtocolParams::default()`。
    fn default() -> Self {
        Self::new(3, [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)])
    }
}

/// Minimal verifier-side fixed input boundary before a full vk lands.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifierPreprocessedInput {
    pub domain: DomainParams,
    pub selector_polynomials: SelectorPolynomials,
    pub sigma_tag_polynomials: SigmaTagPolynomials,
    pub protocol_params: VerifierProtocolParams,
}

impl VerifierPreprocessedInput {
    /// 功能说明：构造 Step 7.1 定义的 verifier 固定输入边界对象。
    /// 输入：domain 参数、selector 多项式、sigma tag 多项式、固定协议参数。
    /// 输出：一个 `VerifierPreprocessedInput`。
    /// 示例：`VerifierPreprocessedInput::new(domain, selectors, sigma_tags, params)`。
    pub fn new(
        domain: DomainParams,
        selector_polynomials: SelectorPolynomials,
        sigma_tag_polynomials: SigmaTagPolynomials,
        protocol_params: VerifierProtocolParams,
    ) -> Self {
        Self {
            domain,
            selector_polynomials,
            sigma_tag_polynomials,
            protocol_params,
        }
    }
}
