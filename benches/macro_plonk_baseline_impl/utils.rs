//! Shared helpers for the primitive-aligned macro baseline bench.

use std::time::Duration;

use ark_serialize::CanonicalSerialize;
use minimal_plonk::{
    kzg::{
        KzgBatchOpening, KzgOpening, KzgSrs, commit_polynomial, open_polynomial_at_point,
        open_polynomials_at_same_point,
    },
    types::{Commitment, QuotientChunkCommitments, TranscriptPreprocessedInput},
};

use super::fixture::{PrimitiveProveInputs, PrimitiveVerifyInputs};

pub fn run_primitive_prove(
    inputs: &PrimitiveProveInputs,
    srs: &KzgSrs,
) -> (
    Commitment,
    [Commitment; 3],
    Commitment,
    QuotientChunkCommitments,
    KzgBatchOpening,
    KzgOpening,
) {
    let linearization_commitment = commit_polynomial(&inputs.linearization_polynomial, srs)
        .expect("r commitment should succeed");
    let wire_commitments = [
        commit_polynomial(&inputs.wire_polynomials.wire_a_poly, srs)
            .expect("wire a commit should succeed"),
        commit_polynomial(&inputs.wire_polynomials.wire_b_poly, srs)
            .expect("wire b commit should succeed"),
        commit_polynomial(&inputs.wire_polynomials.wire_c_poly, srs)
            .expect("wire c commit should succeed"),
    ];
    let grand_product_commitment = commit_polynomial(&inputs.grand_product_polynomial, srs)
        .expect("z commit should succeed");
    let quotient_commitments = commit_quotient_chunks(&inputs.quotient_chunks, srs);
    let same_point_opening = open_polynomials_at_same_point(
        &[
            inputs.linearization_polynomial.clone(),
            inputs.wire_polynomials.wire_a_poly.clone(),
            inputs.wire_polynomials.wire_b_poly.clone(),
            inputs.wire_polynomials.wire_c_poly.clone(),
            inputs.sigma_tag_polynomials.wire_a.clone(),
            inputs.sigma_tag_polynomials.wire_b.clone(),
        ],
        inputs.zeta,
        inputs.v,
        srs,
    )
    .expect("same-point baseline opening should succeed");
    let shifted_opening =
        open_polynomial_at_point(&inputs.grand_product_polynomial, inputs.shifted_zeta, srs)
            .expect("shifted baseline opening should succeed");
    (
        linearization_commitment,
        wire_commitments,
        grand_product_commitment,
        quotient_commitments,
        same_point_opening,
        shifted_opening,
    )
}

pub fn build_primitive_verify_inputs(
    inputs: &PrimitiveProveInputs,
    preprocessed_input: &TranscriptPreprocessedInput,
    artifacts: (
        Commitment,
        [Commitment; 3],
        Commitment,
        QuotientChunkCommitments,
        KzgBatchOpening,
        KzgOpening,
    ),
) -> PrimitiveVerifyInputs {
    let (
        linearization_commitment,
        wire_commitments,
        grand_product_commitment,
        _quotient_commitments,
        same_point_opening,
        shifted_opening,
    ) = artifacts;
    PrimitiveVerifyInputs {
        same_point_commitments: vec![
            linearization_commitment,
            wire_commitments[0].clone(),
            wire_commitments[1].clone(),
            wire_commitments[2].clone(),
            preprocessed_input.sigma_commitments[0].clone(),
            preprocessed_input.sigma_commitments[1].clone(),
        ],
        same_point_values: same_point_opening.values,
        same_point_proof: same_point_opening.proof,
        grand_product_commitment,
        shifted_value: shifted_opening.value,
        shifted_proof: shifted_opening.proof,
        zeta: inputs.zeta,
        shifted_zeta: inputs.shifted_zeta,
        v: inputs.v,
    }
}

pub fn commit_quotient_chunks(
    chunks: &minimal_plonk::quotient::QuotientChunkPolynomials,
    srs: &KzgSrs,
) -> QuotientChunkCommitments {
    QuotientChunkCommitments::new(
        commit_polynomial(&chunks.t_lo, srs).expect("t_lo commitment should succeed"),
        commit_polynomial(&chunks.t_mid, srs).expect("t_mid commitment should succeed"),
        commit_polynomial(&chunks.t_hi, srs).expect("t_hi commitment should succeed"),
    )
}

pub fn sample_srs(domain_size: usize) -> KzgSrs {
    KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two())
        .expect("baseline srs should build")
}

pub fn serialized_proof_size_bytes(proof: &minimal_plonk::types::PlonkProof) -> usize {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("proof serialization should succeed");
    bytes.len()
}

#[allow(clippy::too_many_arguments)]
pub fn print_fixture_summary(
    case_id: &str,
    case_label: &str,
    domain_size: usize,
    srs_max_degree: usize,
    public_input_count: usize,
    copy_constraint_count: usize,
    proof_size_bytes: usize,
    full_prove_time: Duration,
    full_verify_preprocess_time: Duration,
    full_verify_time: Duration,
    primitive_preprocess_time: Duration,
    primitive_prove_time: Duration,
    primitive_verify_time: Duration,
) {
    eprintln!(
        "macro baseline case: id={} label={} domain={} srs_max_degree={} public_inputs={} copy_constraints={} proof_size_bytes={} full_prove_ms={:.3} full_verify_preprocess_ms={:.3} full_verify_ms={:.3} primitive_preprocess_ms={:.3} primitive_prove_ms={:.3} primitive_verify_ms={:.3} prove_ratio={:.2}x verify_ratio={:.2}x",
        case_id,
        case_label,
        domain_size,
        srs_max_degree,
        public_input_count,
        copy_constraint_count,
        proof_size_bytes,
        full_prove_time.as_secs_f64() * 1_000.0,
        full_verify_preprocess_time.as_secs_f64() * 1_000.0,
        full_verify_time.as_secs_f64() * 1_000.0,
        primitive_preprocess_time.as_secs_f64() * 1_000.0,
        primitive_prove_time.as_secs_f64() * 1_000.0,
        primitive_verify_time.as_secs_f64() * 1_000.0,
        full_prove_time.as_secs_f64() / primitive_prove_time.as_secs_f64(),
        full_verify_time.as_secs_f64() / primitive_verify_time.as_secs_f64(),
    );
}
