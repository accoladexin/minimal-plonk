//! Shared verifier-side fixed input types.
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crate::{
    curve::Fr,
    kzg::commit_polynomial,
    types::{config::DomainParams, proof::Commitment},
};
/// Selector polynomials needed by the verifier boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectorPolynomials {
    pub q_l: DensePolynomial<Fr>,
    pub q_r: DensePolynomial<Fr>,
    pub q_o: DensePolynomial<Fr>,
    pub q_m: DensePolynomial<Fr>,
    pub q_c: DensePolynomial<Fr>,
}
impl SelectorPolynomials {
    /// Bundle the five selector polynomials used by the verifier.
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
/// Fixed sigma-tag polynomials needed by the verifier boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct SigmaTagPolynomials {
    pub wire_a: DensePolynomial<Fr>,
    pub wire_b: DensePolynomial<Fr>,
    pub wire_c: DensePolynomial<Fr>,
}
impl SigmaTagPolynomials {
    /// Bundle the three sigma-tag polynomials used by the verifier.
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
/// Fixed protocol parameters needed by the verifier boundary.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierProtocolParams {
    pub num_wire_columns: u32,
    pub permutation_column_factors: [Fr; 3],
}
impl VerifierProtocolParams {
    /// Build the fixed protocol parameters required by the verifier.
    pub fn new(num_wire_columns: u32, permutation_column_factors: [Fr; 3]) -> Self {
        Self {
            num_wire_columns,
            permutation_column_factors,
        }
    }
}
impl Default for VerifierProtocolParams {
    /// Provide the repository default verifier protocol parameters.
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
    /// Build the verifier-side fixed input boundary.
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
    /// Convert polynomial fixed data into the commitment view bound by the transcript.
    pub fn to_transcript_preprocessed_input(
        &self,
        srs: &crate::kzg::KzgSrs,
    ) -> crate::error::Result<TranscriptPreprocessedInput> {
        Ok(TranscriptPreprocessedInput::new(
            self.domain.clone(),
            [
                commit_polynomial(&self.selector_polynomials.q_m, srs)?,
                commit_polynomial(&self.selector_polynomials.q_l, srs)?,
                commit_polynomial(&self.selector_polynomials.q_r, srs)?,
                commit_polynomial(&self.selector_polynomials.q_o, srs)?,
                commit_polynomial(&self.selector_polynomials.q_c, srs)?,
            ],
            [
                commit_polynomial(&self.sigma_tag_polynomials.wire_a, srs)?,
                commit_polynomial(&self.sigma_tag_polynomials.wire_b, srs)?,
                commit_polynomial(&self.sigma_tag_polynomials.wire_c, srs)?,
            ],
            self.protocol_params.clone(),
        ))
    }
}
/// Fixed committed data that Phase 9 binds into the transcript.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct TranscriptPreprocessedInput {
    pub domain: DomainParams,
    pub selector_commitments: [Commitment; 5],
    pub sigma_commitments: [Commitment; 3],
    pub protocol_params: VerifierProtocolParams,
}
impl TranscriptPreprocessedInput {
    /// Build the committed fixed-data view bound into the Phase 9 transcript.
    pub fn new(
        domain: DomainParams,
        selector_commitments: [Commitment; 5],
        sigma_commitments: [Commitment; 3],
        protocol_params: VerifierProtocolParams,
    ) -> Self {
        Self {
            domain,
            selector_commitments,
            sigma_commitments,
            protocol_params,
        }
    }
}
