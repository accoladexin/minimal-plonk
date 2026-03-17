//! Step 8.1 acceptance tests for prover orchestration.

use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::{KzgSrs, commit_polynomial},
    mimc::build_mimc_feistel_circuit,
    permutation::{Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints},
    prover::prove,
    transcript::Transcript,
    types::{
        PlonkProof, SelectorPolynomials, SigmaTagPolynomials, TranscriptPreprocessedInput,
        VerifierProtocolParams,
    },
    witness::interpolate_column_evaluations,
};

/// 功能说明：构造一个可重复使用的 MiMC 电路测试输入。
/// 输入：无。
/// 输出：`Circuit`。
/// 示例：当前 MiMC 测试路径不显式声明 public inputs，所以会传空 `public_inputs`。
fn sample_mimc_circuit() -> Circuit {
    build_mimc_feistel_circuit(Fr::from(7u64), 4)
        .expect("mimc circuit should build")
        .circuit
}

/// 功能说明：构造一个显式依赖 public inputs 且带非空 copy constraints 的最小电路。
/// 输入：两个要绑定到 statement 的 public inputs。
/// 输出：`(circuit, copy_constraints, public_inputs)`。
/// 示例：前两行是 public-input rows，第三行通过 copy constraints 复用这两个值。
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

/// 功能说明：根据电路规模构造足够大的测试 SRS。
/// 输入：电路对应的 H-domain 大小。
/// 输出：能覆盖当前 prover 路径的测试 SRS。
/// 示例：Step 8.1 成功路径测试统一使用这个 helper。
fn sample_srs_for_prover(domain_size: usize) -> KzgSrs {
    let extended_size = (4 * domain_size).next_power_of_two();
    KzgSrs::setup_for_testing(extended_size).expect("testing srs should build")
}

/// 功能说明：根据电路和 copy constraints 构造 Phase 9 transcript fixed data。
/// 输入：冻结后的电路、copy constraints 与 SRS。
/// 输出：`TranscriptPreprocessedInput`。
/// 示例：Step 8.1 prover 测试通过它重放 Phase 9 transcript。
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
    let sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping);

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

/// 功能说明：构造 sigma tag evaluations 并插值成多项式。
/// 输入：domain 与 sigma mapping。
/// 输出：`SigmaTagPolynomials`。
/// 示例：供 transcript fixed-data 构造使用。
fn build_sigma_tag_polynomials(
    domain: &PlonkDomain,
    sigma_mapping: &SigmaMapping,
) -> SigmaTagPolynomials {
    let domain_size = domain.size();
    let mut sigma_a = Vec::with_capacity(domain_size);
    let mut sigma_b = Vec::with_capacity(domain_size);
    let mut sigma_c = Vec::with_capacity(domain_size);

    for row in 0..domain_size {
        sigma_a.push(target_tag_for_source(domain, sigma_mapping, row, 0));
        sigma_b.push(target_tag_for_source(domain, sigma_mapping, row, 1));
        sigma_c.push(target_tag_for_source(domain, sigma_mapping, row, 2));
    }

    SigmaTagPolynomials::new(
        interpolate_column_evaluations(domain, &sigma_a).expect("interpolation should work"),
        interpolate_column_evaluations(domain, &sigma_b).expect("interpolation should work"),
        interpolate_column_evaluations(domain, &sigma_c).expect("interpolation should work"),
    )
}

/// 功能说明：把某个 source 位置在 sigma 下的目标位置转换成 `k_j * omega^i` 标签。
/// 输入：domain、sigma mapping、行号、列号（A=0/B=1/C=2）。
/// 输出：该 source 对应的 sigma tag 值。
/// 示例：source=A,row=0 时，返回 sigma(A,0) 的标签值。
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

/// 功能说明：确认 prover 产出的 proof 已走到 Phase 9 transcript 和 opening 边界。
/// 输入：proof、外部 public inputs、fixed data。
/// 输出：无；若 replay 失败则测试直接失败。
/// 示例：Step 8.1 集成测试用它确认 proof 已切到新边界。
fn assert_phase_9_boundary(
    proof: &PlonkProof,
    public_inputs: &[Fr],
    preprocessed_input: &TranscriptPreprocessedInput,
) {
    let replayed =
        Transcript::default().replay_phase_9_proof(proof, public_inputs, preprocessed_input);

    assert!(!replayed.beta.is_zero());
    assert!(!replayed.gamma.is_zero());
    assert!(!replayed.alpha.is_zero());
    assert!(!replayed.zeta.is_zero());
    assert!(!replayed.v.is_zero());
    assert!(!replayed.u.is_zero());
    assert_ne!(
        proof.quotient_chunk_commitments.t_lo,
        proof.quotient_chunk_commitments.t_mid
    );
    assert_ne!(
        proof.opening_commitments.at_zeta,
        proof.opening_commitments.at_shifted_zeta
    );
}

/// 有效 MiMC 电路在不声明 public inputs 时应能生成完整 Phase 9 proof。
#[test]
fn prover_generates_complete_proof_for_valid_mimc_circuit() {
    let circuit = sample_mimc_circuit();
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let srs = sample_srs_for_prover(domain_size);
    let proof = prove(&circuit, &[], vec![], &srs).expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &[], &srs);

    assert_eq!(proof.wire_commitments.len(), 3);
    assert_phase_9_boundary(&proof, &[], &preprocessed_input);
}

/// prover 必须覆盖真实 permutation 集成路径，而不只是 identity sigma。
#[test]
fn prover_generates_proof_for_public_inputs_and_nontrivial_copy_constraints() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let srs = sample_srs_for_prover(domain_size);
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);

    assert_phase_9_boundary(&proof, &public_inputs, &preprocessed_input);
}

/// public inputs 必须进入主约束；若 statement 与电路绑定值不一致，prover 应拒绝输出 proof。
#[test]
fn prover_rejects_mismatched_public_inputs_in_main_constraints() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs_for_prover(circuit.domain_size().expect("circuit should be padded"));
    let wrong_public_inputs = vec![public_inputs[0] + Fr::from(1u64), public_inputs[1]];

    let error = prove(&circuit, &copy_constraints, wrong_public_inputs, &srs)
        .expect_err("prove should reject mismatched public inputs");

    assert!(error.to_string().contains("must satisfy Plonk constraints"));
}

/// 在都合法的前提下，改变 statement `public_inputs` 仍必须改变 transcript replay challenge。
#[test]
fn prover_replay_challenges_change_when_valid_public_inputs_change() {
    let (left_circuit, left_copy_constraints, left_public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let (right_circuit, right_copy_constraints, right_public_inputs) =
        build_public_input_copy_circuit(Fr::from(6u64), Fr::from(9u64));
    let srs = sample_srs_for_prover(
        left_circuit
            .domain_size()
            .expect("circuit should be padded"),
    );
    let left = prove(
        &left_circuit,
        &left_copy_constraints,
        left_public_inputs.clone(),
        &srs,
    )
    .expect("prove should succeed");
    let right = prove(
        &right_circuit,
        &right_copy_constraints,
        right_public_inputs.clone(),
        &srs,
    )
    .expect("prove should succeed");
    let left_preprocessed =
        build_phase_9_preprocessed_input(&left_circuit, &left_copy_constraints, &srs);
    let right_preprocessed =
        build_phase_9_preprocessed_input(&right_circuit, &right_copy_constraints, &srs);

    let left_challenges =
        Transcript::default().replay_phase_9_proof(&left, &left_public_inputs, &left_preprocessed);
    let right_challenges = Transcript::default().replay_phase_9_proof(
        &right,
        &right_public_inputs,
        &right_preprocessed,
    );

    assert_ne!(left_challenges.beta, right_challenges.beta);
    assert_ne!(left_challenges.gamma, right_challenges.gamma);
}

/// proof 序列化往返后，Phase 9 transcript replay 仍应保持不变。
#[test]
fn prover_proof_round_trip_keeps_transcript_replay_stable() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs_for_prover(circuit.domain_size().expect("circuit should be padded"));
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let preprocessed_input = build_phase_9_preprocessed_input(&circuit, &copy_constraints, &srs);
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("serializing proof should succeed");
    let decoded = PlonkProof::deserialize_compressed(bytes.as_slice())
        .expect("deserializing proof should succeed");

    assert_eq!(
        Transcript::default().replay_phase_9_proof(&proof, &public_inputs, &preprocessed_input),
        Transcript::default().replay_phase_9_proof(&decoded, &public_inputs, &preprocessed_input)
    );
}

/// quotient chunking 后，过小的 SRS 仍必须让 `prove()` 失败。
#[test]
fn prover_fails_when_srs_degree_is_too_small_for_phase_9_quotient_path() {
    let circuit = sample_mimc_circuit();
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let insufficient_srs =
        KzgSrs::setup_for_testing(domain_size).expect("testing srs should build");

    let error = prove(&circuit, &[], vec![], &insufficient_srs)
        .expect_err("prove should fail when quotient degree exceeds srs");

    assert!(
        error
            .to_string()
            .contains("polynomial degree exceeds kzg srs max_degree")
    );
}
