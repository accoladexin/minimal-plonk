//! Step 6.1 / 6.2 acceptance tests for generic KZG module.

use ark_ff::Zero;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};

use minimal_plonk::{
    curve::Fr,
    kzg::{
        KzgSrs, commit_polynomial, open_polynomial_at_point, open_polynomials_at_same_point,
        verify_opening, verify_polynomials_at_same_point,
    },
};

/// Build a dense polynomial from small integer coefficients.
fn polynomial_from_u64(coefficients: &[u64]) -> DensePolynomial<Fr> {
    DensePolynomial::from_coefficients_vec(coefficients.iter().map(|c| Fr::from(*c)).collect())
}

/// Build a testing SRS with internal random tau.
fn sample_srs(max_degree: usize) -> KzgSrs {
    KzgSrs::setup_for_testing(max_degree).expect("testing srs should build")
}

/// Step 6.1: SRS shape should match KZG requirements.
#[test]
fn srs_shape_matches_kzg_requirements() {
    let srs = sample_srs(8);
    assert_eq!(srs.g1_powers.len(), 9);
    assert_eq!(srs.g2_powers.len(), 2);
}

/// Step 6.1: same polynomial with same SRS should give same commitment.
#[test]
fn commitment_is_deterministic_for_same_polynomial_and_srs() {
    let srs = sample_srs(8);
    let polynomial = polynomial_from_u64(&[3, 5, 7, 11]);

    let left = commit_polynomial(&polynomial, &srs).expect("commit should succeed");
    let right = commit_polynomial(&polynomial, &srs).expect("commit should succeed");

    assert_eq!(left, right);
}

/// Step 6.1: polynomial change should change commitment.
#[test]
fn commitment_changes_when_polynomial_changes() {
    let srs = sample_srs(8);
    let left_poly = polynomial_from_u64(&[3, 5, 7, 11]);
    let right_poly = polynomial_from_u64(&[3, 5, 7, 12]);

    let left = commit_polynomial(&left_poly, &srs).expect("commit should succeed");
    let right = commit_polynomial(&right_poly, &srs).expect("commit should succeed");

    assert_ne!(left, right);
}

/// Step 6.1: degree above SRS bound must be rejected.
#[test]
fn commitment_rejects_polynomial_degree_over_srs_limit() {
    let srs = sample_srs(2);
    let too_large = polynomial_from_u64(&[1, 2, 3, 4]); // degree = 3
    let result = commit_polynomial(&too_large, &srs);
    assert!(result.is_err());
}

/// Step 6.2: valid single opening should verify.
#[test]
fn single_opening_verifies_for_correct_claim() {
    let srs = sample_srs(8);
    let polynomial = polynomial_from_u64(&[2, 4, 6, 8]);
    let point = Fr::from(9u64);
    let commitment = commit_polynomial(&polynomial, &srs).expect("commit should succeed");
    let opening = open_polynomial_at_point(&polynomial, point, &srs).expect("open should succeed");

    let verified = verify_opening(
        &commitment,
        opening.point,
        opening.value,
        &opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(verified);
}

/// Step 6.2: tampered value should fail verification.
#[test]
fn single_opening_fails_with_wrong_value() {
    let srs = sample_srs(8);
    let polynomial = polynomial_from_u64(&[2, 4, 6, 8]);
    let point = Fr::from(9u64);
    let commitment = commit_polynomial(&polynomial, &srs).expect("commit should succeed");
    let opening = open_polynomial_at_point(&polynomial, point, &srs).expect("open should succeed");
    let wrong_value = opening.value + Fr::from(1u64);

    let verified =
        verify_opening(&commitment, opening.point, wrong_value, &opening.proof, &srs)
            .expect("verify should run");
    assert!(!verified);
}

/// Step 6.2: tampered proof should fail verification.
#[test]
fn single_opening_fails_with_wrong_proof() {
    let srs = sample_srs(8);
    let polynomial = polynomial_from_u64(&[2, 4, 6, 8]);
    let other_polynomial = polynomial_from_u64(&[1, 3, 5, 7]);
    let point = Fr::from(9u64);
    let commitment = commit_polynomial(&polynomial, &srs).expect("commit should succeed");
    let opening = open_polynomial_at_point(&polynomial, point, &srs).expect("open should succeed");
    let wrong_opening =
        open_polynomial_at_point(&other_polynomial, point, &srs).expect("open should succeed");

    let verified = verify_opening(
        &commitment,
        opening.point,
        opening.value,
        &wrong_opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(!verified);
}

/// Step 6.2: wrong point should fail verification.
#[test]
fn single_opening_fails_with_wrong_point() {
    let srs = sample_srs(8);
    let polynomial = polynomial_from_u64(&[2, 4, 6, 8]);
    let point = Fr::from(9u64);
    let wrong_point = Fr::from(10u64);
    let commitment = commit_polynomial(&polynomial, &srs).expect("commit should succeed");
    let opening = open_polynomial_at_point(&polynomial, point, &srs).expect("open should succeed");

    let verified = verify_opening(
        &commitment,
        wrong_point,
        opening.value,
        &opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(!verified);
}

/// Step 6.2: multi-polynomial same-point opening should verify.
#[test]
fn multi_opening_at_same_point_verifies() {
    let srs = sample_srs(8);
    let point = Fr::from(21u64);
    let challenge = Fr::from(17u64);
    let polynomials = vec![
        polynomial_from_u64(&[1, 2, 3]),
        polynomial_from_u64(&[4, 5, 6, 7]),
        polynomial_from_u64(&[8, 9]),
    ];

    let commitments = polynomials
        .iter()
        .map(|poly| commit_polynomial(poly, &srs).expect("commit should succeed"))
        .collect::<Vec<_>>();
    let opening = open_polynomials_at_same_point(&polynomials, point, challenge, &srs)
        .expect("multi-open should succeed");

    let verified = verify_polynomials_at_same_point(
        &commitments,
        opening.point,
        &opening.values,
        challenge,
        &opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(verified);
}

/// Step 6.2: if one value is modified, multi-opening verification must fail.
#[test]
fn multi_opening_fails_when_one_value_is_tampered() {
    let srs = sample_srs(8);
    let point = Fr::from(21u64);
    let challenge = Fr::from(17u64);
    let polynomials = vec![
        polynomial_from_u64(&[1, 2, 3]),
        polynomial_from_u64(&[4, 5, 6, 7]),
        polynomial_from_u64(&[8, 9]),
    ];

    let commitments = polynomials
        .iter()
        .map(|poly| commit_polynomial(poly, &srs).expect("commit should succeed"))
        .collect::<Vec<_>>();
    let opening = open_polynomials_at_same_point(&polynomials, point, challenge, &srs)
        .expect("multi-open should succeed");

    let mut tampered_values = opening.values.clone();
    tampered_values[1] += Fr::from(1u64);
    let verified = verify_polynomials_at_same_point(
        &commitments,
        opening.point,
        &tampered_values,
        challenge,
        &opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(!verified);
}

/// Step 6.2: aggregation order is fixed to input slice order.
#[test]
fn multi_opening_verification_is_order_sensitive() {
    let srs = sample_srs(8);
    let point = Fr::from(21u64);
    let challenge = Fr::from(17u64);
    let polynomials = vec![
        polynomial_from_u64(&[1, 2, 3]),
        polynomial_from_u64(&[4, 5, 6, 7]),
        polynomial_from_u64(&[8, 9]),
    ];

    let commitments = polynomials
        .iter()
        .map(|poly| commit_polynomial(poly, &srs).expect("commit should succeed"))
        .collect::<Vec<_>>();
    let opening = open_polynomials_at_same_point(&polynomials, point, challenge, &srs)
        .expect("multi-open should succeed");

    let mut reversed_commitments = commitments.clone();
    reversed_commitments.reverse();
    let mut reversed_values = opening.values.clone();
    reversed_values.reverse();

    let verified = verify_polynomials_at_same_point(
        &reversed_commitments,
        opening.point,
        &reversed_values,
        challenge,
        &opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(!verified);
}

/// Step 6.2: opening a zero polynomial should still verify.
#[test]
fn zero_polynomial_opening_verifies() {
    let srs = sample_srs(4);
    let polynomial = DensePolynomial::zero();
    let point = Fr::from(5u64);
    let commitment = commit_polynomial(&polynomial, &srs).expect("commit should succeed");
    let opening = open_polynomial_at_point(&polynomial, point, &srs).expect("open should succeed");

    let verified = verify_opening(
        &commitment,
        opening.point,
        opening.value,
        &opening.proof,
        &srs,
    )
    .expect("verify should run");
    assert!(verified);
    assert!(opening.value.is_zero());
}
