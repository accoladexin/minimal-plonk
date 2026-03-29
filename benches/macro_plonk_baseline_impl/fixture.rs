//! Reusable baseline fixtures for the primitive-aligned macro benchmark.

use std::time::Instant;

use minimal_plonk::{
    cs::Circuit,
    curve::Fr,
    domain::build_domain_from_size,
    kzg::{KzgSrs, verify_opening, verify_polynomials_at_same_point},
    mimc::build_mimc_feistel_circuit,
    permutation::CopyConstraint,
    prover::prove,
    quotient::QuotientChunkPolynomials,
    types::{SigmaTagPolynomials, VerifierPreprocessedInput},
    verifier::{prepare_verifier_input, verify_with_prepared_input},
    witness::WitnessPolynomials,
};

use super::utils::{
    build_primitive_verify_inputs, print_fixture_summary, run_primitive_prove, sample_srs,
    serialized_proof_size_bytes,
};
use super::{
    fixed_data::{build_verifier_input, build_verifier_public_input_copy_fixture_parts},
    prove_inputs::build_primitive_prove_inputs,
};

pub const MIMC_ROUNDS: [usize; 3] = [8, 16, 32];

pub struct BaselineFixture {
    pub case_id: String,
    pub verifier_input: VerifierPreprocessedInput,
    pub srs: KzgSrs,
    pub prove_inputs: PrimitiveProveInputs,
    pub verify_inputs: PrimitiveVerifyInputs,
}

pub struct PrimitiveProveInputs {
    pub wire_polynomials: WitnessPolynomials,
    pub sigma_tag_polynomials: SigmaTagPolynomials,
    pub grand_product_polynomial: ark_poly::univariate::DensePolynomial<Fr>,
    pub quotient_chunks: QuotientChunkPolynomials,
    pub linearization_polynomial: ark_poly::univariate::DensePolynomial<Fr>,
    pub zeta: Fr,
    pub shifted_zeta: Fr,
    pub v: Fr,
}

pub struct PrimitiveVerifyInputs {
    pub same_point_commitments: Vec<minimal_plonk::types::Commitment>,
    pub same_point_values: Vec<Fr>,
    pub same_point_proof: minimal_plonk::types::OpeningProof,
    pub grand_product_commitment: minimal_plonk::types::Commitment,
    pub shifted_value: Fr,
    pub shifted_proof: minimal_plonk::types::OpeningProof,
    pub zeta: Fr,
    pub shifted_zeta: Fr,
    pub v: Fr,
}

pub fn build_baseline_fixtures() -> Vec<BaselineFixture> {
    let mut fixtures: Vec<_> = MIMC_ROUNDS
        .into_iter()
        .map(build_mimc_baseline_fixture)
        .collect();
    fixtures.push(build_public_input_copy_baseline_fixture());
    fixtures
}

fn build_mimc_baseline_fixture(rounds: usize) -> BaselineFixture {
    let build = build_mimc_feistel_circuit(Fr::from(7u64), rounds)
        .expect("baseline MiMC circuit should build");
    build_baseline_fixture(
        format!("mimc_gate_dominant_rounds_{rounds}"),
        "mimc_gate_dominant",
        build.circuit,
        Vec::new(),
        Vec::new(),
    )
}

fn build_public_input_copy_baseline_fixture() -> BaselineFixture {
    let (circuit, copy_constraints, public_inputs) = build_verifier_public_input_copy_fixture_parts();
    build_baseline_fixture(
        "public_input_copy_nontrivial".to_string(),
        "public_input_copy_nontrivial",
        circuit,
        copy_constraints,
        public_inputs,
    )
}

fn build_baseline_fixture(
    case_id: String,
    case_label: &'static str,
    circuit: Circuit,
    copy_constraints: Vec<CopyConstraint>,
    public_inputs: Vec<Fr>,
) -> BaselineFixture {
    let domain_size = circuit
        .domain_size()
        .expect("baseline circuit must be padded");
    let domain = build_domain_from_size(domain_size).expect("baseline domain should build");
    let srs = sample_srs(domain_size);
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);

    let primitive_preprocess_start = Instant::now();
    let preprocessed_input = verifier_input
        .to_transcript_preprocessed_input(&srs)
        .expect("baseline fixed commitments should build");
    let primitive_preprocess_time = primitive_preprocess_start.elapsed();

    let proof_start = Instant::now();
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("full prove should succeed");
    let full_prove_time = proof_start.elapsed();

    let full_verify_preprocess_start = Instant::now();
    let prepared_verifier_input = prepare_verifier_input(&verifier_input, &srs)
        .expect("full verifier preprocessing should succeed");
    let full_verify_preprocess_time = full_verify_preprocess_start.elapsed();

    let full_verify_start = Instant::now();
    let verified = verify_with_prepared_input(
        &proof,
        public_inputs.as_slice(),
        &verifier_input,
        &prepared_verifier_input,
        &srs,
    )
    .expect("full prepared verify should run");
    let full_verify_time = full_verify_start.elapsed();
    assert!(verified, "full proof must verify");

    let proof_size_bytes = serialized_proof_size_bytes(&proof);
    let prove_inputs = build_primitive_prove_inputs(
        &circuit,
        &copy_constraints,
        public_inputs.as_slice(),
        &domain,
        &preprocessed_input,
        &srs,
    );
    let primitive_prove_start = Instant::now();
    let primitive_artifacts = run_primitive_prove(&prove_inputs, &srs);
    let primitive_prove_time = primitive_prove_start.elapsed();
    let primitive_verify_inputs =
        build_primitive_verify_inputs(&prove_inputs, &preprocessed_input, primitive_artifacts);
    let primitive_verify_start = Instant::now();
    let same_point_ok = verify_polynomials_at_same_point(
        primitive_verify_inputs.same_point_commitments.as_slice(),
        primitive_verify_inputs.zeta,
        primitive_verify_inputs.same_point_values.as_slice(),
        primitive_verify_inputs.v,
        &primitive_verify_inputs.same_point_proof,
        &srs,
    )
    .expect("same-point baseline verify should run");
    let shifted_ok = verify_opening(
        &primitive_verify_inputs.grand_product_commitment,
        primitive_verify_inputs.shifted_zeta,
        primitive_verify_inputs.shifted_value,
        &primitive_verify_inputs.shifted_proof,
        &srs,
    )
    .expect("shifted baseline verify should run");
    let primitive_verify_time = primitive_verify_start.elapsed();
    assert!(same_point_ok && shifted_ok, "primitive baseline checks must verify");

    print_fixture_summary(
        &case_id,
        case_label,
        domain_size,
        srs.max_degree(),
        public_inputs.len(),
        copy_constraints.len(),
        proof_size_bytes,
        full_prove_time,
        full_verify_preprocess_time,
        full_verify_time,
        primitive_preprocess_time,
        primitive_prove_time,
        primitive_verify_time,
    );

    BaselineFixture {
        case_id,
        verifier_input,
        srs,
        prove_inputs,
        verify_inputs: primitive_verify_inputs,
    }
}
