//! Step 8.2 acceptance tests for verifier orchestration.

use ark_ec::Group;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, univariate::DensePolynomial};

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::{Fr, G1},
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::KzgSrs,
    mimc::build_mimc_feistel_circuit,
    permutation::{Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints},
    prover::prove,
    types::{
        Commitment, SelectorPolynomials, SigmaTagPolynomials, VerifierPreprocessedInput,
        VerifierProtocolParams,
    },
    verifier::verify,
    witness::interpolate_column_evaluations,
};

/// 功能说明：测试统一使用的 prover/verifier 夹具。
/// 输入：无。
/// 输出：proof、外部 public inputs、verifier fixed input、SRS。
/// 示例：各测试通过 `sample_fixture()` 复用相同数据流。
struct VerifierFixture {
    proof: minimal_plonk::types::PlonkProof,
    public_inputs: Vec<Fr>,
    verifier_input: VerifierPreprocessedInput,
    srs: KzgSrs,
}

/// 功能说明：构造一个带非空 copy constraints 的最小电路，并显式绑定 public inputs。
/// 输入：两个 public input。
/// 输出：`(circuit, copy_constraints, public_inputs)`。
/// 示例：第三行使用 copy constraints 复用前两行输入。
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

/// 功能说明：按当前单 `T(X)` 策略构造够用的测试 SRS。
/// 输入：原始 domain 大小。
/// 输出：可覆盖当前 prover/verifier 的 KZG SRS。
/// 示例：`sample_srs_for_step_8(domain_size)`。
fn sample_srs_for_step_8(domain_size: usize) -> KzgSrs {
    let extended_size = (4 * domain_size).next_power_of_two();
    KzgSrs::setup_for_testing(extended_size).expect("testing srs should build")
}

/// 功能说明：构造一个固定的 commitment，便于篡改测试字段。
/// 输入：标量倍数。
/// 输出：一个确定性的 commitment。
/// 示例：`sample_commitment(17)`。
fn sample_commitment(multiplier: u64) -> Commitment {
    let mut point = G1::generator();
    point *= Fr::from(multiplier);
    Commitment::from_projective(point)
}

/// 功能说明：根据 sigma 映射构造三列 sigma tag 在 H 上的 evaluations。
/// 输入：domain 和 sigma 映射。
/// 输出：`(sigma_a, sigma_b, sigma_c)`。
/// 示例：后续会插值为 verifier 固定输入里的 sigma tag 多项式。
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

/// 功能说明：把某个 source 位置在 sigma 下的目标位置转换成 `k_j * omega^i` 标签。
/// 输入：domain、sigma 映射、行号、列号（A=0/B=1/C=2）。
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

/// 功能说明：从电路与 copy constraints 构造 verifier 最小预处理固定输入。
/// 输入：已 pad 的电路与 copy constraints。
/// 输出：`VerifierPreprocessedInput`。
/// 示例：Step 8.2 verifier 直接消费该结构。
fn build_verifier_input(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
) -> VerifierPreprocessedInput {
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

    VerifierPreprocessedInput::new(
        domain_params(&domain),
        selector_polynomials,
        sigma_tag_polynomials,
        VerifierProtocolParams::default(),
    )
}

/// 功能说明：构造 Step 8.2 所需统一测试夹具。
/// 输入：无。
/// 输出：`VerifierFixture`。
/// 示例：所有测试通过这个夹具保证走到非空 copy constraints 路径。
fn sample_fixture() -> VerifierFixture {
    let (circuit, copy_constraints, public_inputs) =
        build_public_input_copy_circuit(Fr::from(5u64), Fr::from(9u64));
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let srs = sample_srs_for_step_8(domain_size);
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("prove should succeed");
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);

    VerifierFixture {
        proof,
        public_inputs,
        verifier_input,
        srs,
    }
}

/// 功能说明：Step 8.1 产出的有效 proof 在 Step 8.2 verifier 下应被接受。
/// 输入：无。
/// 输出：无（断言 `verify() == true`）。
/// 示例：该测试同时覆盖了非空 copy constraints 的真实集成路径。
#[test]
fn verifier_accepts_valid_proof_from_prover() {
    let fixture = sample_fixture();
    assert!(
        verify(
            &fixture.proof,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .expect("verification should run")
    );
}

/// 功能说明：篡改 claimed evaluations 必须导致 verifier 拒绝。
/// 输入：无。
/// 输出：无（断言 `verify() == false`）。
/// 示例：覆盖 `a(zeta)`、`t(zeta)`、`Z(omega*zeta)` 三种篡改。
#[test]
fn verifier_rejects_tampered_evaluations() {
    let fixture = sample_fixture();

    let mut tampered_a = fixture.proof.clone();
    tampered_a.evaluations_at_zeta.wire_a += Fr::from(1u64);
    assert!(
        !verify(
            &tampered_a,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .expect("verification should run")
    );

    let mut tampered_t = fixture.proof.clone();
    tampered_t.evaluations_at_zeta.quotient += Fr::from(1u64);
    assert!(
        !verify(
            &tampered_t,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .expect("verification should run")
    );

    let mut tampered_shifted = fixture.proof.clone();
    tampered_shifted.shifted_evaluations.grand_product_next += Fr::from(1u64);
    assert!(
        !verify(
            &tampered_shifted,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .expect("verification should run")
    );
}

/// 功能说明：篡改外部 public inputs 必须导致 verifier 拒绝。
/// 输入：无。
/// 输出：无（断言 `verify() == false`）。
/// 示例：用于确认 statement 由 verifier 外部输入驱动。
#[test]
fn verifier_rejects_tampered_external_public_inputs() {
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
        .expect("verification should run")
    );
}

/// 功能说明：篡改 opening proof 必须导致 verifier 拒绝。
/// 输入：无。
/// 输出：无（断言 `verify() == false`）。
/// 示例：该测试确保 verifier 真正执行了 opening/pairing 检查路径。
#[test]
fn verifier_rejects_tampered_opening_proof() {
    let fixture = sample_fixture();
    let mut tampered = fixture.proof.clone();
    tampered.opening_proof_at_zeta.witness_commitment = sample_commitment(97);

    assert!(
        !verify(
            &tampered,
            fixture.public_inputs.as_slice(),
            &fixture.verifier_input,
            &fixture.srs
        )
        .expect("verification should run")
    );
}

/// 功能说明：fixed data（selector/sigma/domain）错误时 verifier 必须拒绝。
/// 输入：无。
/// 输出：无（断言 `verify() == false`）。
/// 示例：分别覆盖 selector 错、sigma tag 错、domain 参数错。
#[test]
fn verifier_rejects_wrong_fixed_data() {
    let fixture = sample_fixture();

    let mut wrong_selector_input = fixture.verifier_input.clone();
    let selector_delta = DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]);
    wrong_selector_input.selector_polynomials.q_l +=
        &selector_delta;
    assert!(
        !verify(
            &fixture.proof,
            fixture.public_inputs.as_slice(),
            &wrong_selector_input,
            &fixture.srs
        )
        .expect("verification should run")
    );

    let mut wrong_sigma_input = fixture.verifier_input.clone();
    let sigma_delta = DensePolynomial::from_coefficients_vec(vec![Fr::from(1u64)]);
    wrong_sigma_input.sigma_tag_polynomials.wire_a +=
        &sigma_delta;
    assert!(
        !verify(
            &fixture.proof,
            fixture.public_inputs.as_slice(),
            &wrong_sigma_input,
            &fixture.srs
        )
        .expect("verification should run")
    );

    let mut wrong_domain_input = fixture.verifier_input.clone();
    wrong_domain_input.domain.generator += Fr::from(1u64);
    assert!(
        !verify(
            &fixture.proof,
            fixture.public_inputs.as_slice(),
            &wrong_domain_input,
            &fixture.srs
        )
        .expect("verification should run")
    );
}

/// 功能说明：额外 sanity 测试，确保 MiMC 路径与空 public_inputs 也可验证成功。
/// 输入：无。
/// 输出：无（断言 `verify() == true`）。
/// 示例：该测试覆盖常见示例电路路径，不替代上面的非平凡 permutation 路径。
#[test]
fn verifier_accepts_valid_mimc_proof() {
    let circuit = build_mimc_feistel_circuit(Fr::from(7u64), 4)
        .expect("mimc circuit should build")
        .circuit;
    let public_inputs = vec![];
    let copy_constraints = vec![];
    let domain_size = circuit.domain_size().expect("circuit should be padded");
    let srs = sample_srs_for_step_8(domain_size);
    let proof =
        prove(&circuit, copy_constraints.as_slice(), public_inputs.clone(), &srs).expect("prove");
    let verifier_input = build_verifier_input(&circuit, copy_constraints.as_slice());

    assert!(verify(&proof, public_inputs.as_slice(), &verifier_input, &srs).expect("verify"));
}
