//! Prover-side primitive inputs for the primitive-aligned macro baseline bench.

use ark_poly::{EvaluationDomain, Polynomial};
use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::PlonkDomain,
    kzg::{KzgSrs, commit_polynomial},
    permutation::{
        CopyConstraint, build_sigma_from_copy_constraints, compute_grand_product_evaluations,
        interpolate_grand_product_evaluations,
    },
    quotient::{
        blind_grand_product_polynomial, blind_witness_polynomial, build_linearization_polynomial,
        compute_blinded_quotient_polynomial, rerandomize_quotient_chunks, split_quotient_polynomial,
    },
    transcript::Transcript,
    types::{EvaluationsAtZeta, TranscriptPreprocessedInput},
    witness::{WitnessColumns, WitnessPolynomials, interpolate_witness_column_polynomials},
};

use super::{
    fixture::PrimitiveProveInputs,
    fixed_data::{build_sigma_tag_polynomials, verifier_input_selector_polynomials},
    utils::commit_quotient_chunks,
};

pub fn build_primitive_prove_inputs(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
    public_inputs: &[Fr],
    domain: &PlonkDomain,
    preprocessed_input: &TranscriptPreprocessedInput,
    srs: &KzgSrs,
) -> PrimitiveProveInputs {
    let domain_size = domain.size();
    let witness_columns =
        WitnessColumns::from_padded_circuit(circuit).expect("baseline witness should extract");
    let raw_wire_polynomials = interpolate_witness_column_polynomials(domain, &witness_columns)
        .expect("baseline witness interpolation should succeed");
    let wire_polynomials = WitnessPolynomials {
        wire_a_poly: blind_witness_polynomial(
            &raw_wire_polynomials.wire_a_poly,
            domain_size,
            Fr::from(11u64),
            Fr::from(13u64),
        )
        .expect("wire a blinding should succeed"),
        wire_b_poly: blind_witness_polynomial(
            &raw_wire_polynomials.wire_b_poly,
            domain_size,
            Fr::from(17u64),
            Fr::from(19u64),
        )
        .expect("wire b blinding should succeed"),
        wire_c_poly: blind_witness_polynomial(
            &raw_wire_polynomials.wire_c_poly,
            domain_size,
            Fr::from(23u64),
            Fr::from(29u64),
        )
        .expect("wire c blinding should succeed"),
    };
    let wire_commitments = [
        commit_polynomial(&wire_polynomials.wire_a_poly, srs).expect("wire a commitment should succeed"),
        commit_polynomial(&wire_polynomials.wire_b_poly, srs).expect("wire b commitment should succeed"),
        commit_polynomial(&wire_polynomials.wire_c_poly, srs).expect("wire c commitment should succeed"),
    ];

    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)
        .expect("baseline sigma mapping should build");
    let sigma_tag_polynomials = build_sigma_tag_polynomials(domain, &sigma_mapping);

    let mut transcript = Transcript::default();
    transcript.absorb_phase_9_preprocessed_input(preprocessed_input);
    transcript.absorb_plonk_public_inputs(public_inputs);
    transcript.absorb_plonk_wire_commitments(&wire_commitments);
    let beta = transcript.challenge_scalar(b"beta");
    let gamma = transcript.challenge_scalar(b"gamma");

    let grand_product_evaluations = compute_grand_product_evaluations(
        &witness_columns.wire_a_evaluations,
        &witness_columns.wire_b_evaluations,
        &witness_columns.wire_c_evaluations,
        &sigma_mapping,
        beta,
        gamma,
    )
    .expect("baseline grand product evaluations should build");
    let grand_product_polynomial = interpolate_grand_product_evaluations(
        &grand_product_evaluations.grand_product_evaluations,
        domain_size,
    )
    .expect("baseline grand product interpolation should succeed");
    let grand_product_polynomial = blind_grand_product_polynomial(
        &grand_product_polynomial,
        domain_size,
        Fr::from(31u64),
        Fr::from(37u64),
        Fr::from(41u64),
    )
    .expect("baseline grand product blinding should succeed");
    let grand_product_commitment = commit_polynomial(&grand_product_polynomial, srs)
        .expect("baseline z commitment should succeed");
    transcript.absorb_plonk_grand_product_commitment(&grand_product_commitment);
    let alpha = transcript.challenge_scalar(b"alpha");

    let selector_columns =
        SelectorColumns::from_padded_circuit(circuit).expect("baseline selectors should extract");
    let quotient_inputs = minimal_plonk::types::QuotientInputs::new(
        witness_columns,
        selector_columns,
        sigma_mapping,
        grand_product_evaluations,
    )
    .expect("baseline quotient inputs should build");
    let quotient_polynomial = compute_blinded_quotient_polynomial(
        &quotient_inputs,
        public_inputs,
        alpha,
        beta,
        gamma,
        &wire_polynomials,
        &grand_product_polynomial,
    )
    .expect("baseline quotient should build");
    let quotient_chunks = rerandomize_quotient_chunks(
        &split_quotient_polynomial(&quotient_polynomial, domain_size)
            .expect("baseline chunk split should succeed"),
        domain_size,
        Fr::from(43u64),
        Fr::from(47u64),
    )
    .expect("baseline chunk rerandomization should succeed");
    let quotient_commitments = commit_quotient_chunks(&quotient_chunks, srs);
    transcript.absorb_phase_9_quotient_chunk_commitments(&quotient_commitments);
    let zeta = transcript.challenge_scalar(b"zeta");
    let shifted_zeta = domain.group_gen() * zeta;

    let evaluations_at_zeta = EvaluationsAtZeta::new(
        wire_polynomials.wire_a_poly.evaluate(&zeta),
        wire_polynomials.wire_b_poly.evaluate(&zeta),
        wire_polynomials.wire_c_poly.evaluate(&zeta),
        sigma_tag_polynomials.wire_a.evaluate(&zeta),
        sigma_tag_polynomials.wire_b.evaluate(&zeta),
    );
    let grand_product_at_zeta_omega = grand_product_polynomial.evaluate(&shifted_zeta);
    transcript.absorb_phase_9_evaluations(&evaluations_at_zeta, &grand_product_at_zeta_omega);
    let v = transcript.challenge_scalar(b"v");

    let selector_polynomials = verifier_input_selector_polynomials(domain, circuit);
    let linearization_polynomial = build_linearization_polynomial(
        domain,
        &selector_polynomials.q_l,
        &selector_polynomials.q_r,
        &selector_polynomials.q_o,
        &selector_polynomials.q_m,
        &selector_polynomials.q_c,
        &sigma_tag_polynomials.wire_c,
        &grand_product_polynomial,
        &quotient_chunks,
        public_inputs,
        alpha,
        beta,
        gamma,
        zeta,
        evaluations_at_zeta.wire_a,
        evaluations_at_zeta.wire_b,
        evaluations_at_zeta.wire_c,
        evaluations_at_zeta.sigma_1,
        evaluations_at_zeta.sigma_2,
        grand_product_at_zeta_omega,
    );

    PrimitiveProveInputs {
        wire_polynomials,
        sigma_tag_polynomials,
        grand_product_polynomial,
        quotient_chunks,
        linearization_polynomial,
        zeta,
        shifted_zeta,
        v,
    }
}
