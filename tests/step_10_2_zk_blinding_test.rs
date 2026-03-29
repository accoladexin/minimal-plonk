//! Step 10.2 acceptance tests for blinded prover / verifier integration.

use ark_ec::{AffineRepr, Group};
use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::{Fr, G1},
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::{KzgSrs, commit_polynomial, verify_opening},
    permutation::{Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints},
    prover::prove,
    quotient::{
        blind_grand_product_polynomial, evaluate_chunked_quotient, split_quotient_polynomial,
    },
    transcript::Transcript,
    types::{
        Commitment, SelectorPolynomials, SigmaTagPolynomials, TranscriptPreprocessedInput,
        VerifierPreprocessedInput, VerifierProtocolParams,
    },
    verifier::verify,
    witness::{
        WitnessColumns, interpolate_column_evaluations, interpolate_witness_column_polynomials,
    },
};

struct ZkFixture {
    circuit: Circuit,
    copy_constraints: Vec<CopyConstraint>,
    public_inputs: Vec<Fr>,
    proof: minimal_plonk::types::PlonkProof,
    verifier_input: VerifierPreprocessedInput,
    transcript_input: TranscriptPreprocessedInput,
    srs: KzgSrs,
}

fn build_public_input_copy_circuit() -> (Circuit, Vec<CopyConstraint>, Vec<Fr>) {
    let left_public_input = Fr::from(5u64);
    let right_public_input = Fr::from(9u64);
    let public_inputs = vec![left_public_input, right_public_input];
    let sum = left_public_input + right_public_input;
    let mut circuit = Circuit::new();

    circuit
        .add_gate(
            left_public_input,
            Fr::from(0u64),
            Fr::from(0u64),
            -Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .unwrap();
    circuit
        .add_gate(
            right_public_input,
            Fr::from(0u64),
            Fr::from(0u64),
            -Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .unwrap();
    circuit
        .add_gate(
            left_public_input,
            right_public_input,
            sum,
            Fr::from(1u64),
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .unwrap();
    circuit.pad_to_domain();

    let copy_constraints = vec![
        CopyConstraint {
            left: Pos {
                col: Column::A,
                row: 0,
            },
            right: Pos {
                col: Column::A,
                row: 2,
            },
        },
        CopyConstraint {
            left: Pos {
                col: Column::A,
                row: 1,
            },
            right: Pos {
                col: Column::B,
                row: 2,
            },
        },
    ];

    (circuit, copy_constraints, public_inputs)
}

fn sample_srs(domain_size: usize) -> KzgSrs {
    KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two()).unwrap()
}

fn build_sigma_tag_evaluations(
    domain: &PlonkDomain,
    sigma_mapping: &SigmaMapping,
) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let domain_size = domain.size();
    let mut sigma_a = Vec::with_capacity(domain_size);
    let mut sigma_b = Vec::with_capacity(domain_size);
    let mut sigma_c = Vec::with_capacity(domain_size);

    for row in 0..domain_size {
        sigma_a.push(target_tag_for_source(domain, sigma_mapping, row, 0));
        sigma_b.push(target_tag_for_source(domain, sigma_mapping, row, 1));
        sigma_c.push(target_tag_for_source(domain, sigma_mapping, row, 2));
    }

    (sigma_a, sigma_b, sigma_c)
}

fn target_tag_for_source(
    domain: &PlonkDomain,
    sigma_mapping: &SigmaMapping,
    row: usize,
    column_index: usize,
) -> Fr {
    let domain_size = domain.size();
    let source_id = column_index * domain_size + row;
    let target_id = sigma_mapping.image_at(source_id).unwrap();
    let target_column = target_id / domain_size;
    let target_row = target_id % domain_size;
    let column_factor = match target_column {
        0 => Fr::from(1u64),
        1 => Fr::from(2u64),
        2 => Fr::from(3u64),
        _ => panic!("target column index out of range"),
    };

    column_factor * domain.element(target_row)
}

fn build_verifier_input(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
) -> VerifierPreprocessedInput {
    let domain_size = circuit.domain_size().unwrap();
    let domain = build_domain_from_size(domain_size).unwrap();
    let selectors = SelectorColumns::from_padded_circuit(circuit).unwrap();
    let selector_polynomials = SelectorPolynomials::new(
        interpolate_column_evaluations(&domain, &selectors.q_l_evaluations).unwrap(),
        interpolate_column_evaluations(&domain, &selectors.q_r_evaluations).unwrap(),
        interpolate_column_evaluations(&domain, &selectors.q_o_evaluations).unwrap(),
        interpolate_column_evaluations(&domain, &selectors.q_m_evaluations).unwrap(),
        interpolate_column_evaluations(&domain, &selectors.q_c_evaluations).unwrap(),
    );
    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints).unwrap();
    let (sigma_a, sigma_b, sigma_c) = build_sigma_tag_evaluations(&domain, &sigma_mapping);
    let sigma_tag_polynomials = SigmaTagPolynomials::new(
        interpolate_column_evaluations(&domain, &sigma_a).unwrap(),
        interpolate_column_evaluations(&domain, &sigma_b).unwrap(),
        interpolate_column_evaluations(&domain, &sigma_c).unwrap(),
    );

    VerifierPreprocessedInput::new(
        domain_params(&domain),
        selector_polynomials,
        sigma_tag_polynomials,
        VerifierProtocolParams::default(),
    )
}

fn build_transcript_input(
    verifier_input: &VerifierPreprocessedInput,
    srs: &KzgSrs,
) -> TranscriptPreprocessedInput {
    verifier_input.to_transcript_preprocessed_input(srs).unwrap()
}

fn sample_fixture() -> ZkFixture {
    let (circuit, copy_constraints, public_inputs) = build_public_input_copy_circuit();
    let srs = sample_srs(circuit.domain_size().unwrap());
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);
    let transcript_input = build_transcript_input(&verifier_input, &srs);

    ZkFixture {
        circuit,
        copy_constraints,
        public_inputs,
        proof,
        verifier_input,
        transcript_input,
        srs,
    }
}

fn build_raw_wire_commitments(circuit: &Circuit, srs: &KzgSrs) -> [Commitment; 3] {
    let domain = build_domain_from_size(circuit.domain_size().unwrap()).unwrap();
    let witness_columns = WitnessColumns::from_padded_circuit(circuit).unwrap();
    let wire_polynomials = interpolate_witness_column_polynomials(&domain, &witness_columns).unwrap();

    [
        commit_polynomial(&wire_polynomials.wire_a_poly, srs).unwrap(),
        commit_polynomial(&wire_polynomials.wire_b_poly, srs).unwrap(),
        commit_polynomial(&wire_polynomials.wire_c_poly, srs).unwrap(),
    ]
}

#[test]
fn blinded_proof_verifies_with_non_empty_copy_constraints() {
    let fixture = sample_fixture();
    let challenges = Transcript::default().replay_phase_9_proof(
        &fixture.proof,
        fixture.public_inputs.as_slice(),
        &fixture.transcript_input,
    );
    let shifted_zeta = build_domain_from_size(fixture.circuit.domain_size().unwrap())
        .unwrap()
        .group_gen()
        * challenges.zeta;

    assert_eq!(fixture.copy_constraints.len(), 2);
    assert!(
        verify_opening(
            &fixture.proof.grand_product_commitment,
            shifted_zeta,
            fixture.proof.grand_product_at_zeta_omega,
            &minimal_plonk::types::OpeningProof::new(
                fixture.proof.opening_commitments.at_shifted_zeta.clone(),
            ),
            &fixture.srs,
        )
        .unwrap()
    );
    let linearization_commitment = build_linearization_commitment_for_test(
        &fixture.proof,
        &fixture.verifier_input,
        &fixture.transcript_input,
        fixture.public_inputs.as_slice(),
        challenges.alpha,
        challenges.beta,
        challenges.gamma,
        challenges.zeta,
    );
    let same_point_commitment =
        build_same_point_commitment_for_test(&linearization_commitment, &fixture.proof, &fixture.transcript_input, challenges.v);
    let same_point_value = build_same_point_value_for_test(&fixture.proof, challenges.v);
    assert!(
        verify_opening(
            &same_point_commitment,
            challenges.zeta,
            same_point_value,
            &minimal_plonk::types::OpeningProof::new(
                fixture.proof.opening_commitments.at_zeta.clone(),
            ),
            &fixture.srs,
        )
        .unwrap()
    );
    assert!(
        verify(
            &fixture.proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );
}

#[test]
fn repeated_proofs_change_blinded_commitments_but_both_verify() {
    let (circuit, copy_constraints, public_inputs) = build_public_input_copy_circuit();
    let srs = sample_srs(circuit.domain_size().unwrap());
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);

    let left = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();
    let right = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();

    assert!(
        left.wire_commitments != right.wire_commitments
            || left.quotient_chunk_commitments != right.quotient_chunk_commitments
    );
    assert!(verify(&left, public_inputs.as_slice(), &verifier_input, &srs).unwrap());
    assert!(verify(&right, public_inputs.as_slice(), &verifier_input, &srs).unwrap());
}

#[test]
fn grand_product_blinding_matches_paper_quadratic_shape() {
    let raw = ark_poly::univariate::DensePolynomial::from_coefficients_vec(vec![
        Fr::from(11u64),
        Fr::from(13u64),
    ]);
    let domain_size = 4usize;
    let constant = Fr::from(5u64);
    let linear = Fr::from(7u64);
    let quadratic = Fr::from(9u64);

    let blinded =
        blind_grand_product_polynomial(&raw, domain_size, constant, linear, quadratic).unwrap();

    let mut expected = raw.coeffs.clone();
    expected.resize(domain_size + 3, Fr::from(0u64));
    expected[0] -= constant;
    expected[1] -= linear;
    expected[2] -= quadratic;
    expected[domain_size] += constant;
    expected[domain_size + 1] += linear;
    expected[domain_size + 2] += quadratic;

    assert_eq!(blinded.coeffs, expected);
}

#[test]
fn quotient_split_keeps_high_degree_tail_inside_t_hi() {
    let domain_size = 4usize;
    let quotient = ark_poly::univariate::DensePolynomial::from_coefficients_vec(vec![
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
        Fr::from(8u64),
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(11u64),
    ]);
    let chunks = split_quotient_polynomial(&quotient, domain_size).unwrap();
    let point = Fr::from(13u64);

    assert_eq!(chunks.t_lo.coeffs.len(), domain_size);
    assert_eq!(chunks.t_mid.coeffs.len(), domain_size);
    assert_eq!(chunks.t_hi.coeffs, vec![Fr::from(9u64), Fr::from(10u64), Fr::from(11u64)]);
    assert_eq!(
        evaluate_chunked_quotient(&chunks, domain_size, point),
        quotient.evaluate(&point)
    );
}

#[test]
fn transcript_replay_uses_blinded_objects_without_changing_order() {
    let fixture = sample_fixture();
    let raw_wire_commitments = build_raw_wire_commitments(&fixture.circuit, &fixture.srs);

    assert!(fixture.proof.wire_commitments != raw_wire_commitments);

    let blinded_challenges = Transcript::default().replay_phase_9_proof(
        &fixture.proof,
        fixture.public_inputs.as_slice(),
        &fixture.transcript_input,
    );

    let mut raw_commitment_proof = fixture.proof.clone();
    raw_commitment_proof.wire_commitments = raw_wire_commitments;
    let raw_commitment_challenges = Transcript::default().replay_phase_9_proof(
        &raw_commitment_proof,
        fixture.public_inputs.as_slice(),
        &fixture.transcript_input,
    );

    assert!(
        blinded_challenges.beta != raw_commitment_challenges.beta
            || blinded_challenges.gamma != raw_commitment_challenges.gamma
    );
}

#[test]
fn tampering_blinded_wire_evaluations_breaks_verification() {
    let fixture = sample_fixture();

    let mut proof = fixture.proof.clone();
    proof.evaluations_at_zeta.wire_a += Fr::from(1u64);
    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );

    let mut proof = fixture.proof.clone();
    proof.evaluations_at_zeta.wire_b += Fr::from(1u64);
    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );

    let mut proof = fixture.proof.clone();
    proof.evaluations_at_zeta.wire_c += Fr::from(1u64);
    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );
}

#[test]
fn tampering_blinded_shifted_grand_product_breaks_verification() {
    let fixture = sample_fixture();
    let mut proof = fixture.proof.clone();
    proof.grand_product_at_zeta_omega += Fr::from(1u64);

    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );
}

#[test]
fn tampering_blinded_quotient_chunk_commitment_breaks_verification() {
    let fixture = sample_fixture();
    let mut proof = fixture.proof.clone();
    proof.quotient_chunk_commitments.t_mid = proof.quotient_chunk_commitments.t_lo.clone();

    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );
}

#[test]
fn tampering_opening_commitments_breaks_verification() {
    let fixture = sample_fixture();

    let mut proof = fixture.proof.clone();
    proof.opening_commitments.at_zeta = proof.opening_commitments.at_shifted_zeta.clone();
    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );

    let mut proof = fixture.proof.clone();
    proof.opening_commitments.at_shifted_zeta = proof.opening_commitments.at_zeta.clone();
    assert!(
        !verify(
            &proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );
}

#[test]
fn repeated_proofs_keep_transcript_replay_self_consistent() {
    let (circuit, copy_constraints, public_inputs) = build_public_input_copy_circuit();
    let srs = sample_srs(circuit.domain_size().unwrap());
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);
    let transcript_input = build_transcript_input(&verifier_input, &srs);

    let left = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();
    let right = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();

    let left_first =
        Transcript::default().replay_phase_9_proof(&left, public_inputs.as_slice(), &transcript_input);
    let left_second =
        Transcript::default().replay_phase_9_proof(&left, public_inputs.as_slice(), &transcript_input);
    let right_first = Transcript::default().replay_phase_9_proof(
        &right,
        public_inputs.as_slice(),
        &transcript_input,
    );

    assert_eq!(left_first, left_second);
    assert!(left_first != right_first || left.wire_commitments != right.wire_commitments);
}

fn build_linearization_commitment_for_test(
    proof: &minimal_plonk::types::PlonkProof,
    verifier_input: &VerifierPreprocessedInput,
    transcript_input: &TranscriptPreprocessedInput,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    zeta: Fr,
) -> Commitment {
    let domain = build_domain_from_size(verifier_input.domain.size as usize).unwrap();
    let public_input_at_zeta = public_inputs
        .iter()
        .enumerate()
        .fold(Fr::from(0u64), |accumulator, (index, public_input)| {
            accumulator + (*public_input * domain.evaluate_all_lagrange_coefficients(zeta)[index])
        });
    let l_0_at_zeta = domain.evaluate_all_lagrange_coefficients(zeta)[0];
    let z_h_at_zeta = domain.evaluate_vanishing_polynomial(zeta);
    let point_to_n = zeta.pow([domain.size() as u64]);
    let point_to_2n = point_to_n * point_to_n;
    let a_at_zeta = proof.evaluations_at_zeta.wire_a;
    let b_at_zeta = proof.evaluations_at_zeta.wire_b;
    let c_at_zeta = proof.evaluations_at_zeta.wire_c;
    let sigma_1_at_zeta = proof.evaluations_at_zeta.sigma_1;
    let sigma_2_at_zeta = proof.evaluations_at_zeta.sigma_2;
    let z_at_omega_zeta = proof.grand_product_at_zeta_omega;

    let gate_scalar_q_m = a_at_zeta * b_at_zeta;
    let gate_scalar_q_l = a_at_zeta;
    let gate_scalar_q_r = b_at_zeta;
    let gate_scalar_q_o = c_at_zeta;

    let permutation_scalar = alpha
        * (a_at_zeta + beta * zeta + gamma)
        * (b_at_zeta
            + beta * verifier_input.protocol_params.permutation_column_factors[1] * zeta
            + gamma)
        * (c_at_zeta
            + beta * verifier_input.protocol_params.permutation_column_factors[2] * zeta
            + gamma);

    let sigma_scalar = -alpha
        * (a_at_zeta + beta * sigma_1_at_zeta + gamma)
        * (b_at_zeta + beta * sigma_2_at_zeta + gamma);
    let sigma_linear_scalar = beta * sigma_scalar * z_at_omega_zeta;
    let sigma_constant = (c_at_zeta + gamma) * sigma_scalar * z_at_omega_zeta;

    let quotient_commitment_group = proof.quotient_chunk_commitments.t_lo.point.into_group()
        + proof.quotient_chunk_commitments.t_mid.point.into_group() * point_to_n
        + proof.quotient_chunk_commitments.t_hi.point.into_group() * point_to_2n;

    Commitment::from_projective(
        transcript_input.selector_commitments[0].point.into_group() * gate_scalar_q_m
            + transcript_input.selector_commitments[1].point.into_group() * gate_scalar_q_l
            + transcript_input.selector_commitments[2].point.into_group() * gate_scalar_q_r
            + transcript_input.selector_commitments[3].point.into_group() * gate_scalar_q_o
            + transcript_input.selector_commitments[4].point.into_group()
            + (G1::generator() * public_input_at_zeta)
            + proof.grand_product_commitment.point.into_group() * permutation_scalar
            + transcript_input.sigma_commitments[2].point.into_group() * sigma_linear_scalar
            + (G1::generator() * sigma_constant)
            + proof.grand_product_commitment.point.into_group() * (alpha * alpha * l_0_at_zeta)
            + (G1::generator() * (-alpha * alpha * l_0_at_zeta))
            - (quotient_commitment_group * z_h_at_zeta),
    )
}

fn build_same_point_commitment_for_test(
    linearization_commitment: &Commitment,
    proof: &minimal_plonk::types::PlonkProof,
    transcript_input: &TranscriptPreprocessedInput,
    v: Fr,
) -> Commitment {
    Commitment::from_projective(
        linearization_commitment.point.into_group()
            + proof.wire_commitments[0].point.into_group() * v
            + proof.wire_commitments[1].point.into_group() * (v * v)
            + proof.wire_commitments[2].point.into_group() * (v * v * v)
            + transcript_input.sigma_commitments[0].point.into_group() * (v * v * v * v)
            + transcript_input.sigma_commitments[1].point.into_group() * (v * v * v * v * v),
    )
}

fn build_same_point_value_for_test(proof: &minimal_plonk::types::PlonkProof, v: Fr) -> Fr {
    v * proof.evaluations_at_zeta.wire_a
        + v * v * proof.evaluations_at_zeta.wire_b
        + v * v * v * proof.evaluations_at_zeta.wire_c
        + v * v * v * v * proof.evaluations_at_zeta.sigma_1
        + v * v * v * v * v * proof.evaluations_at_zeta.sigma_2
}
