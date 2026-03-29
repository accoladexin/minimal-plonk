//! Step 4.2: permutation grand-product evaluations and recurrence helpers.
use ark_ff::Field;
use ark_poly::{EvaluationDomain, univariate::DensePolynomial};
use crate::{
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, evaluations_to_polynomial},
    error::{PlonkError, Result},
    permutation::{Column, Pos, SigmaMapping, pos_to_wire_id, validate_sigma_bijection},
    validate::ensure,
};

/// Fixed column factors used by the B/C column tags.
pub const K1: u64 = 2;
pub const K2: u64 = 3;
/// Canonical Round 2 output: `Z(1), Z(omega), ..., Z(omega^n)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrandProductEvaluations {
    pub domain_size: usize,
    pub grand_product_evaluations: Vec<Fr>,
}

/// Per-row numerator and denominator reused by the grand-product and quotient identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowTerms {
    pub numerator: Fr,
    pub denominator: Fr,
}
/// Sigma-tag evaluations needed when Step 5.1 builds `S_sigma1/2/3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigmaTagEvaluations {
    pub sigma_a_evaluations: Vec<Fr>,
    pub sigma_b_evaluations: Vec<Fr>,
    pub sigma_c_evaluations: Vec<Fr>,
}

pub fn compute_grand_product_evaluations(
    a_eval: &[Fr],
    b_eval: &[Fr],
    c_eval: &[Fr],
    sigma: &SigmaMapping,
    beta: Fr,
    gamma: Fr,
) -> Result<GrandProductEvaluations> {
    validate_inputs(a_eval, b_eval, c_eval, sigma)?;
    let domain_size = a_eval.len();
    let domain = build_domain_from_size(domain_size)?;
    let mut z_eval = Vec::with_capacity(domain_size + 1);
    z_eval.push(Fr::from(1u64));
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
        let denominator_inverse = terms
            .denominator
            .inverse()
            .ok_or(PlonkError::InvalidInput("permutation denominator is zero"))?;
        let next_z = z_eval[row_index] * terms.numerator * denominator_inverse;
        z_eval.push(next_z);
    }
    Ok(GrandProductEvaluations {
        domain_size,
        grand_product_evaluations: z_eval,
    })
}
/// Check one recurrence step `Z(next) = Z(cur) * numerator / denominator`.
pub fn verify_single_grand_product_step(
    previous_z: Fr,
    next_z: Fr,
    terms: &RowTerms,
) -> Result<bool> {
    let denominator_inverse = terms
        .denominator
        .inverse()
        .ok_or(PlonkError::InvalidInput("permutation denominator is zero"))?;
    Ok(next_z == previous_z * terms.numerator * denominator_inverse)
}

pub fn verify_grand_product_recurrence(
    z_eval: &[Fr],
    a_eval: &[Fr],
    b_eval: &[Fr],
    c_eval: &[Fr],
    sigma: &SigmaMapping,
    beta: Fr,
    gamma: Fr,
) -> Result<bool> {
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
        if !verify_single_grand_product_step(z_eval[row_index], z_eval[row_index + 1], &terms)? {
            return Ok(false);
        }
    }
    Ok(true)
}
/// Check the permutation boundary `Z(1)=1` and `Z(omega^n)=1`.
pub fn verify_grand_product_boundary(z_eval: &[Fr], domain_size: usize) -> Result<bool> {
    ensure(
        z_eval.len() == domain_size + 1,
        "grand product evaluations length must equal n + 1",
    )?;
    let one = Fr::from(1u64);
    Ok(z_eval[0] == one && z_eval[domain_size] == one)
}

pub fn interpolate_grand_product_evaluations(
    z_eval: &[Fr],
    domain_size: usize,
) -> Result<DensePolynomial<Fr>> {
    ensure(
        z_eval.len() == domain_size + 1,
        "grand product evaluations length must equal n + 1",
    )?;
    let domain = build_domain_from_size(domain_size)?;
    evaluations_to_polynomial(&domain, &z_eval[..domain_size])
}
/// Expose one row's permutation numerator and denominator to the quotient builder.
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
    row_terms(domain, sigma, row_index, a_value, b_value, c_value, beta, gamma)
}

pub(crate) fn compute_sigma_tag_evaluations_for_quotient(
    domain: &PlonkDomain,
    sigma: &SigmaMapping,
) -> Result<SigmaTagEvaluations> {
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
    let row_label = domain.element(row_index);
    let a_tag = row_label;
    let b_tag = Fr::from(K1) * row_label;
    let c_tag = Fr::from(K2) * row_label;
    let sigma_a_tag = sigma_target_tag(sigma, domain, Column::A, row_index)?;
    let sigma_b_tag = sigma_target_tag(sigma, domain, Column::B, row_index)?;
    let sigma_c_tag = sigma_target_tag(sigma, domain, Column::C, row_index)?;
    Ok(RowTerms {
        numerator: (a_value + beta * a_tag + gamma)
            * (b_value + beta * b_tag + gamma)
            * (c_value + beta * c_tag + gamma),
        denominator: (a_value + beta * sigma_a_tag + gamma)
            * (b_value + beta * sigma_b_tag + gamma)
            * (c_value + beta * sigma_c_tag + gamma),
    })
}
fn sigma_target_tag(
    sigma: &SigmaMapping,
    domain: &PlonkDomain,
    source_column: Column,
    source_row: usize,
) -> Result<Fr> {
    let source_id = pos_to_wire_id(
        Pos {
            col: source_column,
            row: source_row,
        },
        sigma.domain_size(),
    )?;
    let target_id = sigma.image_at(source_id)?;
    ensure(
        target_id < sigma.expected_sigma_len(),
        "sigma image out of range when mapping target tag",
    )?;
    let target_column = match target_id / sigma.domain_size() {
        0 => Column::A,
        1 => Column::B,
        2 => Column::C,
        _ => return Err(PlonkError::InvalidInput("target column index out of range")),
    };
    let target_row = target_id % sigma.domain_size();
    Ok(column_factor(target_column) * domain.element(target_row))
}
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
    #[test]
    fn invalid_sigma_is_rejected_at_grand_product_entrypoints() {
        let a_eval = vec![Fr::from(1u64), Fr::from(2u64)];
        let b_eval = vec![Fr::from(3u64), Fr::from(4u64)];
        let c_eval = vec![Fr::from(5u64), Fr::from(6u64)];
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
