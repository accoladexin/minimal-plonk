//! Step 8.1 acceptance tests for prover orchestration.

use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use minimal_plonk::{
    cs::Circuit,
    curve::Fr,
    domain::build_domain_from_size,
    kzg::{KzgSrs, verify_opening, verify_polynomials_at_same_point},
    mimc::build_mimc_feistel_circuit,
    permutation::{Column, CopyConstraint, Pos},
    prover::prove,
    transcript::Transcript,
    types::PlonkProof,
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
/// 输出：能覆盖当前单个 `T(X)` commitment 的测试 SRS。
/// 示例：Step 8.1 成功路径测试统一使用这个 helper。
fn sample_srs_for_prover(domain_size: usize) -> KzgSrs {
    let extended_size = (4 * domain_size).next_power_of_two();
    KzgSrs::setup_for_testing(extended_size).expect("testing srs should build")
}

/// 功能说明：复用现有 KZG 能力验证 prover 产出的两个 opening。
/// 输入：proof、对应 domain size 和 SRS。
/// 输出：无；若 opening 无法验证，测试直接失败。
/// 示例：Step 8.1 集成测试用它确认 proof 中的 opening 字段可被后续 verifier 使用。
fn assert_proof_openings_verify(proof: &PlonkProof, domain_size: usize, srs: &KzgSrs) {
    let replayed = Transcript::default().replay_plonk_proof(proof);
    let domain = build_domain_from_size(domain_size).expect("domain should build");
    let shifted_zeta = domain.element(1) * replayed.zeta;
    let zeta_values = vec![
        proof.evaluations_at_zeta.wire_a,
        proof.evaluations_at_zeta.wire_b,
        proof.evaluations_at_zeta.wire_c,
        proof.evaluations_at_zeta.grand_product,
        proof.evaluations_at_zeta.quotient,
    ];
    let zeta_commitments = vec![
        proof.wire_commitments[0].clone(),
        proof.wire_commitments[1].clone(),
        proof.wire_commitments[2].clone(),
        proof.grand_product_commitment.clone(),
        proof.quotient_commitment.clone(),
    ];

    assert!(
        verify_polynomials_at_same_point(
            &zeta_commitments,
            replayed.zeta,
            &zeta_values,
            replayed.v,
            &proof.opening_proof_at_zeta,
            srs,
        )
        .expect("same-point opening verification should run")
    );
    assert!(
        verify_opening(
            &proof.grand_product_commitment,
            shifted_zeta,
            proof.shifted_evaluations.grand_product_next,
            &proof.opening_proof_at_shifted_zeta,
            srs,
        )
        .expect("shifted opening verification should run")
    );
}

/// 有效 MiMC 电路在不声明 public inputs 时应能生成完整 proof。
#[test]
fn prover_generates_complete_proof_for_valid_mimc_circuit() {
    let circuit = sample_mimc_circuit();
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let srs = sample_srs_for_prover(domain_size);
    let proof = prove(&circuit, &[], vec![], &srs).expect("prove should succeed");

    assert!(proof.public_inputs.is_empty());
    assert_eq!(proof.wire_commitments.len(), 3);
    assert_proof_openings_verify(&proof, domain_size, &srs);
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

    assert_eq!(proof.public_inputs, public_inputs);
    assert_eq!(
        Transcript::default().replay_plonk_proof(&proof),
        Transcript::default().replay_plonk_proof(&proof)
    );
    assert_proof_openings_verify(&proof, domain_size, &srs);
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

    assert!(
        error
            .to_string()
            .contains("must satisfy Plonk constraints")
    );
}

/// 在都合法的前提下，改变 statement `public_inputs` 仍必须改变 transcript replay challenge。
#[test]
fn prover_replay_challenges_change_when_valid_public_inputs_change() {
    let (left_circuit, left_copy_constraints, left_public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let (right_circuit, right_copy_constraints, right_public_inputs) =
        build_public_input_copy_circuit(Fr::from(6u64), Fr::from(9u64));
    let srs = sample_srs_for_prover(left_circuit.domain_size().expect("circuit should be padded"));
    let left = prove(
        &left_circuit,
        &left_copy_constraints,
        left_public_inputs,
        &srs,
    )
    .expect("prove should succeed");
    let right = prove(
        &right_circuit,
        &right_copy_constraints,
        right_public_inputs,
        &srs,
    )
    .expect("prove should succeed");

    let left_challenges = Transcript::default().replay_plonk_proof(&left);
    let right_challenges = Transcript::default().replay_plonk_proof(&right);

    assert_ne!(left_challenges.beta, right_challenges.beta);
    assert_ne!(left_challenges.gamma, right_challenges.gamma);
}

/// proof 序列化往返后，带 public inputs 的 transcript replay 仍应保持不变。
#[test]
fn prover_proof_round_trip_keeps_transcript_replay_stable() {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let srs = sample_srs_for_prover(circuit.domain_size().expect("circuit should be padded"));
    let proof =
        prove(&circuit, &copy_constraints, public_inputs, &srs).expect("prove should succeed");
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("serializing proof should succeed");
    let decoded =
        PlonkProof::deserialize_compressed(bytes.as_slice()).expect("deserializing proof should succeed");

    assert_eq!(
        Transcript::default().replay_plonk_proof(&proof),
        Transcript::default().replay_plonk_proof(&decoded)
    );
}

/// 当前版本不做 quotient chunking，所以 SRS 次数不足时 `prove()` 必须失败。
#[test]
fn prover_fails_when_srs_degree_is_too_small_for_single_quotient_commitment() {
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
