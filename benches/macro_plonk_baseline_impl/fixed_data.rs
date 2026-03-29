//! Fixed-data helpers shared by the primitive-aligned macro baseline bench.

use ark_poly::EvaluationDomain;
use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    permutation::{Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints},
    types::{SelectorPolynomials, SigmaTagPolynomials, VerifierPreprocessedInput, VerifierProtocolParams},
    witness::interpolate_column_evaluations,
};

pub fn build_verifier_input(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
) -> VerifierPreprocessedInput {
    let domain_size = circuit
        .domain_size()
        .expect("baseline circuit must be padded");
    let domain = build_domain_from_size(domain_size).expect("baseline domain should build");
    let selector_polynomials = verifier_input_selector_polynomials(&domain, circuit);
    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)
        .expect("baseline sigma mapping should build");
    let sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping);
    VerifierPreprocessedInput::new(
        domain_params(&domain),
        selector_polynomials,
        sigma_tag_polynomials,
        VerifierProtocolParams::default(),
    )
}

pub fn build_verifier_public_input_copy_fixture_parts() -> (Circuit, Vec<CopyConstraint>, Vec<Fr>) {
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
        .expect("left public-input gate should build");
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
        .expect("right public-input gate should build");
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
        .expect("sum gate should build");
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

pub fn verifier_input_selector_polynomials(
    domain: &PlonkDomain,
    circuit: &Circuit,
) -> SelectorPolynomials {
    let selectors =
        SelectorColumns::from_padded_circuit(circuit).expect("baseline selectors should extract");
    SelectorPolynomials::new(
        interpolate_column_evaluations(domain, &selectors.q_l_evaluations)
            .expect("q_l interpolation should succeed"),
        interpolate_column_evaluations(domain, &selectors.q_r_evaluations)
            .expect("q_r interpolation should succeed"),
        interpolate_column_evaluations(domain, &selectors.q_o_evaluations)
            .expect("q_o interpolation should succeed"),
        interpolate_column_evaluations(domain, &selectors.q_m_evaluations)
            .expect("q_m interpolation should succeed"),
        interpolate_column_evaluations(domain, &selectors.q_c_evaluations)
            .expect("q_c interpolation should succeed"),
    )
}

pub fn build_sigma_tag_polynomials(
    domain: &PlonkDomain,
    sigma_mapping: &SigmaMapping,
) -> SigmaTagPolynomials {
    let (sigma_a, sigma_b, sigma_c) = build_sigma_tag_evaluations(domain, sigma_mapping);
    SigmaTagPolynomials::new(
        interpolate_column_evaluations(domain, &sigma_a)
            .expect("sigma_1 interpolation should succeed"),
        interpolate_column_evaluations(domain, &sigma_b)
            .expect("sigma_2 interpolation should succeed"),
        interpolate_column_evaluations(domain, &sigma_c)
            .expect("sigma_3 interpolation should succeed"),
    )
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
        .expect("sigma image should exist");
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
