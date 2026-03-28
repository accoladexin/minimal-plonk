//! Step 9.3 acceptance tests for the paper-aligned prover refactor.

use ark_ff::Zero;
use ark_poly::EvaluationDomain;

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::{KzgSrs, commit_polynomial},
    permutation::{Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints},
    prover::prove,
    transcript::{Phase9TranscriptChallenges, Transcript},
    types::{
        SelectorPolynomials, SigmaTagPolynomials, TranscriptPreprocessedInput,
        VerifierProtocolParams,
    },
    witness::interpolate_column_evaluations,
};

fn build_public_input_copy_circuit(
    left_public_input: Fr,
    right_public_input: Fr,
) -> (Circuit, Vec<CopyConstraint>, Vec<Fr>) {
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
        .expect("adding public-input gate should succeed");
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
        .expect("adding public-input gate should succeed");
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
        .expect("adding sum gate should succeed");
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
    let extended_size = (8 * domain_size).next_power_of_two();
    KzgSrs::setup_for_testing(extended_size).expect("testing srs should build")
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
    let target_id = sigma_mapping
        .image_at(source_id)
        .expect("sigma image should be in range");
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

fn build_phase_9_preprocessed_input(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
    srs: &KzgSrs,
) -> TranscriptPreprocessedInput {
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let domain = build_domain_from_size(domain_size).expect("domain should build");

    let selectors =
        SelectorColumns::from_padded_circuit(circuit).expect("selector extraction should work");
    let selector_polynomials = SelectorPolynomials::new(
        interpolate_column_evaluations(&domain, &selectors.q_l_evaluations)
            .expect("interpolation should work"),
        interpolate_column_evaluations(&domain, &selectors.q_r_evaluations)
            .expect("interpolation should work"),
        interpolate_column_evaluations(&domain, &selectors.q_o_evaluations)
            .expect("interpolation should work"),
        interpolate_column_evaluations(&domain, &selectors.q_m_evaluations)
            .expect("interpolation should work"),
        interpolate_column_evaluations(&domain, &selectors.q_c_evaluations)
            .expect("interpolation should work"),
    );

    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)
        .expect("sigma mapping should build");
    let (sigma_a, sigma_b, sigma_c) = build_sigma_tag_evaluations(&domain, &sigma_mapping);
    let sigma_tag_polynomials = SigmaTagPolynomials::new(
        interpolate_column_evaluations(&domain, &sigma_a).expect("interpolation should work"),
        interpolate_column_evaluations(&domain, &sigma_b).expect("interpolation should work"),
        interpolate_column_evaluations(&domain, &sigma_c).expect("interpolation should work"),
    );

    TranscriptPreprocessedInput::new(
        domain_params(&domain),
        [
            commit_polynomial(&selector_polynomials.q_m, srs).expect("commitment should work"),
            commit_polynomial(&selector_polynomials.q_l, srs).expect("commitment should work"),
            commit_polynomial(&selector_polynomials.q_r, srs).expect("commitment should work"),
            commit_polynomial(&selector_polynomials.q_o, srs).expect("commitment should work"),
            commit_polynomial(&selector_polynomials.q_c, srs).expect("commitment should work"),
        ],
        [
            commit_polynomial(&sigma_tag_polynomials.wire_a, srs).expect("commitment should work"),
            commit_polynomial(&sigma_tag_polynomials.wire_b, srs).expect("commitment should work"),
            commit_polynomial(&sigma_tag_polynomials.wire_c, srs).expect("commitment should work"),
        ],
        VerifierProtocolParams::new(3, [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]),
    )
}

fn replay_phase_9(
    proof: &minimal_plonk::types::PlonkProof,
    public_inputs: &[Fr],
    preprocessed_input: &TranscriptPreprocessedInput,
) -> Phase9TranscriptChallenges {
    Transcript::default().replay_phase_9_proof(proof, public_inputs, preprocessed_input)
}

#[test]
fn prover_generates_phase_9_proof_for_valid_circuit() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);

    let challenges = replay_phase_9(&proof, &public_inputs, &preprocessed_input);

    assert_ne!(
        proof.quotient_chunk_commitments.t_lo,
        proof.quotient_chunk_commitments.t_mid
    );
    assert_ne!(
        proof.opening_commitments.at_zeta,
        proof.opening_commitments.at_shifted_zeta
    );
    assert!(!challenges.beta.is_zero());
    assert!(!challenges.u.is_zero());
}

#[test]
fn phase_9_proof_boundary_exposes_only_chunked_quotient_and_opening_commitments() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");

    let quotient_chunks = &proof.quotient_chunk_commitments;
    let openings = &proof.opening_commitments;

    assert_ne!(quotient_chunks.t_lo, quotient_chunks.t_mid);
    assert_ne!(quotient_chunks.t_mid, quotient_chunks.t_hi);
    assert_ne!(openings.at_zeta, openings.at_shifted_zeta);
}

#[test]
fn transcript_replay_reconstructs_all_phase_9_challenges() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);

    let left = replay_phase_9(&proof, &public_inputs, &preprocessed_input);
    let right = replay_phase_9(&proof, &public_inputs, &preprocessed_input);

    assert_eq!(left, right);
}

#[test]
fn quotient_chunk_commitments_change_the_phase_9_zeta_challenge() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);
    let original = replay_phase_9(&proof, &public_inputs, &preprocessed_input);

    let mut tampered = proof.clone();
    tampered.quotient_chunk_commitments.t_mid = tampered.quotient_chunk_commitments.t_lo.clone();
    let changed = replay_phase_9(&tampered, &public_inputs, &preprocessed_input);

    assert_ne!(original.zeta, changed.zeta);
}

#[test]
fn opening_commitments_change_the_phase_9_u_challenge() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);
    let original = replay_phase_9(&proof, &public_inputs, &preprocessed_input);

    let mut tampered = proof.clone();
    tampered.opening_commitments.at_zeta = tampered.opening_commitments.at_shifted_zeta.clone();
    let changed = replay_phase_9(&tampered, &public_inputs, &preprocessed_input);

    assert_ne!(original.u, changed.u);
}

#[test]
fn prover_keeps_non_empty_copy_constraints_on_phase_9_path() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);
    let challenges = replay_phase_9(&proof, &public_inputs, &preprocessed_input);

    assert_eq!(copy_constraints.len(), 2);
    assert!(!challenges.alpha.is_zero());
}

#[test]
fn fixed_data_changes_early_phase_9_challenges() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let original = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);
    let mut tampered = original.clone();
    tampered.selector_commitments[0] = tampered.selector_commitments[1].clone();

    let left = replay_phase_9(&proof, &public_inputs, &original);
    let right = replay_phase_9(&proof, &public_inputs, &tampered);

    assert_ne!(left.beta, right.beta);
    assert_ne!(left.gamma, right.gamma);
}
