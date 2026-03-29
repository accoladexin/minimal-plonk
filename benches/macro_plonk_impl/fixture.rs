//! Reusable fixtures for the end-to-end Mini-Plonk macro benchmark.

use std::time::Instant;

use minimal_plonk::{
    cs::Circuit,
    curve::Fr,
    mimc::build_mimc_feistel_circuit,
    permutation::{Column, CopyConstraint, Pos},
    prover::prove,
    verifier::{PreparedVerifierInput, prepare_verifier_input, verify_with_prepared_input},
};

use super::utils::{build_verifier_input, sample_srs, serialized_proof_size_bytes};

const MIMC_ROUNDS: [usize; 3] = [8, 16, 32];

pub struct MacroFixture {
    pub case_id: String,
    pub case_label: &'static str,
    pub domain_size: usize,
    pub srs_max_degree: usize,
    pub srs_g1_length: usize,
    pub public_input_count: usize,
    pub copy_constraint_count: usize,
    pub public_inputs: Vec<Fr>,
    pub circuit: Circuit,
    pub copy_constraints: Vec<CopyConstraint>,
    pub verifier_input: minimal_plonk::types::VerifierPreprocessedInput,
    pub prepared_verifier_input: PreparedVerifierInput,
    pub proof: minimal_plonk::types::PlonkProof,
    pub srs: minimal_plonk::kzg::KzgSrs,
    pub setup_time: std::time::Duration,
    pub prove_time: std::time::Duration,
    pub verify_preprocess_time: std::time::Duration,
    pub verify_time: std::time::Duration,
    pub proof_size_bytes: usize,
}

pub fn build_macro_fixtures() -> Vec<MacroFixture> {
    let mut fixtures: Vec<_> = MIMC_ROUNDS
        .into_iter()
        .map(build_mimc_fixture)
        .collect();
    fixtures.push(build_public_input_copy_fixture());
    fixtures
}

fn build_mimc_fixture(rounds: usize) -> MacroFixture {
    let build = build_mimc_feistel_circuit(Fr::from(7u64), rounds)
        .expect("macrobench MiMC circuit should build");
    build_macro_fixture(
        format!("mimc_gate_dominant_rounds_{rounds}"),
        "mimc_gate_dominant",
        build.circuit,
        Vec::new(),
        Vec::new(),
    )
}

fn build_public_input_copy_fixture() -> MacroFixture {
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

    build_macro_fixture(
        "public_input_copy_nontrivial".to_string(),
        "public_input_copy_nontrivial",
        circuit,
        copy_constraints,
        public_inputs,
    )
}

fn build_macro_fixture(
    case_id: String,
    case_label: &'static str,
    circuit: Circuit,
    copy_constraints: Vec<CopyConstraint>,
    public_inputs: Vec<Fr>,
) -> MacroFixture {
    let setup_start = Instant::now();
    let domain_size = circuit
        .domain_size()
        .expect("macrobench circuit must be padded");
    let srs = sample_srs(domain_size);
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);
    let setup_time = setup_start.elapsed();

    let prove_start = Instant::now();
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("macrobench prove should succeed");
    let prove_time = prove_start.elapsed();

    let preprocess_start = Instant::now();
    let prepared_verifier_input = prepare_verifier_input(&verifier_input, &srs)
        .expect("macrobench fixed-data preprocessing should succeed");
    let verify_preprocess_time = preprocess_start.elapsed();

    let verify_start = Instant::now();
    let verified = verify_with_prepared_input(
        &proof,
        public_inputs.as_slice(),
        &verifier_input,
        &prepared_verifier_input,
        &srs,
    )
    .expect("macrobench prepared verify should run");
    let verify_time = verify_start.elapsed();
    assert!(verified, "macrobench fixture proof must verify");

    MacroFixture {
        case_id,
        case_label,
        domain_size,
        srs_max_degree: srs.max_degree(),
        srs_g1_length: srs.g1_powers.len(),
        public_input_count: public_inputs.len(),
        copy_constraint_count: copy_constraints.len(),
        public_inputs,
        circuit,
        copy_constraints,
        verifier_input,
        prepared_verifier_input,
        proof_size_bytes: serialized_proof_size_bytes(&proof),
        proof,
        srs,
        setup_time,
        prove_time,
        verify_preprocess_time,
        verify_time,
    }
}
