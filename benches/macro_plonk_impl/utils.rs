//! Shared helper functions for the end-to-end Mini-Plonk macro benchmark.

use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::KzgSrs,
    permutation::{CopyConstraint, SigmaMapping, build_sigma_from_copy_constraints},
    types::{
        PlonkProof, SelectorPolynomials, SigmaTagPolynomials, VerifierPreprocessedInput,
        VerifierProtocolParams,
    },
    witness::interpolate_column_evaluations,
};

use super::fixture::MacroFixture;

pub fn sample_srs(domain_size: usize) -> KzgSrs {
    KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two())
        .expect("macrobench srs should build")
}

pub fn build_verifier_input(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
) -> VerifierPreprocessedInput {
    let domain_size = circuit
        .domain_size()
        .expect("macrobench circuit must be padded");
    let domain = build_domain_from_size(domain_size).expect("macrobench domain should build");
    let selectors =
        SelectorColumns::from_padded_circuit(circuit).expect("selector columns should extract");
    let selector_polynomials = SelectorPolynomials::new(
        interpolate_column_evaluations(&domain, &selectors.q_l_evaluations)
            .expect("q_l interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_r_evaluations)
            .expect("q_r interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_o_evaluations)
            .expect("q_o interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_m_evaluations)
            .expect("q_m interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_c_evaluations)
            .expect("q_c interpolation should succeed"),
    );
    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)
        .expect("sigma mapping should build");
    let (sigma_a, sigma_b, sigma_c) = build_sigma_tag_evaluations(&domain, &sigma_mapping);
    let sigma_tag_polynomials = SigmaTagPolynomials::new(
        interpolate_column_evaluations(&domain, &sigma_a)
            .expect("sigma_1 interpolation should succeed"),
        interpolate_column_evaluations(&domain, &sigma_b)
            .expect("sigma_2 interpolation should succeed"),
        interpolate_column_evaluations(&domain, &sigma_c)
            .expect("sigma_3 interpolation should succeed"),
    );

    VerifierPreprocessedInput::new(
        domain_params(&domain),
        selector_polynomials,
        sigma_tag_polynomials,
        VerifierProtocolParams::default(),
    )
}

pub fn serialized_proof_size_bytes(proof: &PlonkProof) -> usize {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("proof serialization should succeed");
    bytes.len()
}

pub fn print_fixture_summary(fixture: &MacroFixture) {
    let total =
        fixture.setup_time + fixture.prove_time + fixture.verify_preprocess_time + fixture.verify_time;
    let total_secs = total.as_secs_f64();
    let setup_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.setup_time.as_secs_f64() / total_secs * 100.0
    };
    let prove_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.prove_time.as_secs_f64() / total_secs * 100.0
    };
    let preprocess_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.verify_preprocess_time.as_secs_f64() / total_secs * 100.0
    };
    let verify_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.verify_time.as_secs_f64() / total_secs * 100.0
    };

    eprintln!(
        "macrobench case: id={} label={} domain={} srs_max_degree={} srs_g1_len={} public_inputs={} copy_constraints={} proof_size_bytes={} setup_ms={:.3} prove_ms={:.3} verify_preprocess_ms={:.3} verify_ms={:.3} shares=setup:{:.1}%/prove:{:.1}%/verify_preprocess:{:.1}%/verify:{:.1}%",
        fixture.case_id,
        fixture.case_label,
        fixture.domain_size,
        fixture.srs_max_degree,
        fixture.srs_g1_length,
        fixture.public_input_count,
        fixture.copy_constraint_count,
        fixture.proof_size_bytes,
        fixture.setup_time.as_secs_f64() * 1_000.0,
        fixture.prove_time.as_secs_f64() * 1_000.0,
        fixture.verify_preprocess_time.as_secs_f64() * 1_000.0,
        fixture.verify_time.as_secs_f64() * 1_000.0,
        setup_share,
        prove_share,
        preprocess_share,
        verify_share,
    );
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
