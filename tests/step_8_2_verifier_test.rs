//! Step 8.2 compatibility tests after the Step 9.4 verifier refactor.

use ark_poly::EvaluationDomain;

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::KzgSrs,
    mimc::build_mimc_feistel_circuit,
    permutation::{Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints},
    prover::prove,
    types::{
        SelectorPolynomials, SigmaTagPolynomials, VerifierPreprocessedInput, VerifierProtocolParams,
    },
    verifier::verify,
    witness::interpolate_column_evaluations,
};

struct VerifierFixture {
    proof: minimal_plonk::types::PlonkProof,
    public_inputs: Vec<Fr>,
    verifier_input: VerifierPreprocessedInput,
    srs: KzgSrs,
}

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

fn sample_fixture() -> VerifierFixture {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs(circuit.domain_size().unwrap());
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);
    VerifierFixture {
        proof,
        public_inputs,
        verifier_input,
        srs,
    }
}

#[test]
fn verifier_accepts_valid_phase_9_fixture() {
    let fixture = sample_fixture();
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
fn verifier_rejects_tampered_public_inputs() {
    let fixture = sample_fixture();
    let mut wrong_public_inputs = fixture.public_inputs.clone();
    wrong_public_inputs[0] += Fr::from(1u64);
    assert!(
        !verify(
            &fixture.proof,
            wrong_public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .unwrap()
    );
}

#[test]
fn verifier_accepts_valid_mimc_fixture_shape() {
    let circuit = build_mimc_feistel_circuit(Fr::from(7u64), 4)
        .unwrap()
        .circuit;
    let public_inputs = vec![];
    let copy_constraints = vec![];
    let srs = sample_srs(circuit.domain_size().unwrap());
    let proof = prove(
        &circuit,
        copy_constraints.as_slice(),
        public_inputs.clone(),
        &srs,
    )
    .unwrap();
    let verifier_input = build_verifier_input(&circuit, copy_constraints.as_slice());
    assert!(verify(&proof, public_inputs.as_slice(), &verifier_input, &srs).unwrap());
}
