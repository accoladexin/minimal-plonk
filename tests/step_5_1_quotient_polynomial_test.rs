//! Step 5.1 验收测试：
//! - H-domain 上只做约束零性检查
//! - extended-domain 上做真实 quotient 构造

use ark_ff::Zero;
use ark_poly::EvaluationDomain;

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    permutation::{
        Column, CopyConstraint, GrandProductEvaluations, Pos, build_sigma_from_copy_constraints,
        compute_grand_product_evaluations,
    },
    quotient::{
        build_extended_quotient_domain, build_h_vanishing_polynomial,
        compute_extended_domain_quotient, compute_h_domain_constraint_evaluations,
        compute_step_5_1,
    },
    types::QuotientInputs,
    witness::WitnessColumns,
};

/// 固定 Step 5.1 测试中的 alpha。
fn sample_alpha() -> Fr {
    Fr::from(7u64)
}

/// 固定 Step 5.1 测试中的 beta。
fn sample_beta() -> Fr {
    Fr::from(13u64)
}

/// 固定 Step 5.1 测试中的 gamma。
fn sample_gamma() -> Fr {
    Fr::from(29u64)
}

/// 构造一个 gate/permutation/boundary 都满足的基础输入。
fn build_valid_inputs() -> QuotientInputs {
    let mut circuit = Circuit::new();
    circuit
        .add_gate(
            Fr::from(31u64),
            Fr::from(2u64),
            Fr::from(8u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit
        .add_gate(
            Fr::from(9u64),
            Fr::from(31u64),
            Fr::from(10u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit
        .add_gate(
            Fr::from(11u64),
            Fr::from(12u64),
            Fr::from(31u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit.pad_to_domain();

    let witness = WitnessColumns::from_padded_circuit(&circuit).expect("witness should extract");
    let selectors =
        SelectorColumns::from_padded_circuit(&circuit).expect("selectors should extract");
    let sigma_constraints = vec![
        CopyConstraint {
            left: Pos {
                col: Column::A,
                row: 0,
            },
            right: Pos {
                col: Column::B,
                row: 1,
            },
        },
        CopyConstraint {
            left: Pos {
                col: Column::B,
                row: 1,
            },
            right: Pos {
                col: Column::C,
                row: 2,
            },
        },
    ];
    let sigma = build_sigma_from_copy_constraints(witness.domain_size(), &sigma_constraints)
        .expect("sigma should build");
    let z = compute_grand_product_evaluations(
        &witness.wire_a_evaluations,
        &witness.wire_b_evaluations,
        &witness.wire_c_evaluations,
        &sigma,
        sample_beta(),
        sample_gamma(),
    )
    .expect("grand product should compute");

    QuotientInputs::new(witness, selectors, sigma, z).expect("quotient inputs should build")
}

/// 构造一个显式依赖 public inputs 的最小电路，并带上非空 copy constraints。
fn build_public_input_bound_inputs() -> (QuotientInputs, Vec<Fr>) {
    let public_inputs = vec![Fr::from(5u64), Fr::from(9u64)];
    let sum = public_inputs[0] + public_inputs[1];

    let mut circuit = Circuit::new();
    circuit
        .add_gate(
            public_inputs[0],
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
            public_inputs[1],
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
            public_inputs[0],
            public_inputs[1],
            sum,
            Fr::from(1u64),
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding sum gate should succeed");
    circuit.pad_to_domain();

    let witness = WitnessColumns::from_padded_circuit(&circuit).expect("witness should extract");
    let selectors =
        SelectorColumns::from_padded_circuit(&circuit).expect("selectors should extract");
    let sigma_constraints = vec![
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
    let sigma = build_sigma_from_copy_constraints(witness.domain_size(), &sigma_constraints)
        .expect("sigma should build");
    let z = compute_grand_product_evaluations(
        &witness.wire_a_evaluations,
        &witness.wire_b_evaluations,
        &witness.wire_c_evaluations,
        &sigma,
        sample_beta(),
        sample_gamma(),
    )
    .expect("grand product should compute");

    (
        QuotientInputs::new(witness, selectors, sigma, z).expect("quotient inputs should build"),
        public_inputs,
    )
}

/// 判断一个 evaluations 向量里是否有非零值。
fn has_nonzero(values: &[Fr]) -> bool {
    values.iter().any(|value| !value.is_zero())
}

/// 去掉系数向量尾部的 0，方便比较多项式等价性。
fn trim_trailing_zeros(mut coefficients: Vec<Fr>) -> Vec<Fr> {
    while let Some(last) = coefficients.last() {
        if last.is_zero() {
            coefficients.pop();
        } else {
            break;
        }
    }
    coefficients
}

/// 正确 witness 时，H-domain 上的 numerator 必须全为 0。
#[test]
fn h_domain_numerator_is_zero_for_valid_inputs() {
    let inputs = build_valid_inputs();
    let output = compute_h_domain_constraint_evaluations(
        &inputs,
        &[],
        sample_alpha(),
        sample_beta(),
        sample_gamma(),
    )
    .expect("H-domain constraints should compute");

    assert!(
        output
            .numerator_evaluations
            .iter()
            .all(|value| value.is_zero())
    );
}

/// gate 失败时，H-domain 上的 gate term 和 numerator 至少有一个点非 0。
#[test]
fn h_domain_gate_failure_makes_numerator_nonzero() {
    let inputs = build_valid_inputs();
    let mut q_c = inputs.selector_columns.q_c_evaluations.clone();
    q_c[0] = Fr::from(1u64);
    let broken_selectors = SelectorColumns::from_evaluations(
        inputs.selector_columns.q_l_evaluations.clone(),
        inputs.selector_columns.q_r_evaluations.clone(),
        inputs.selector_columns.q_o_evaluations.clone(),
        inputs.selector_columns.q_m_evaluations.clone(),
        q_c,
        inputs.domain_size,
    )
    .expect("selector columns should build");

    let broken_inputs = QuotientInputs::new(
        inputs.witness_columns.clone(),
        broken_selectors,
        inputs.sigma_mapping.clone(),
        inputs.grand_product_evaluations.clone(),
    )
    .expect("broken inputs should build");

    let output = compute_h_domain_constraint_evaluations(
        &broken_inputs,
        &[],
        sample_alpha(),
        sample_beta(),
        sample_gamma(),
    )
    .expect("H-domain constraints should compute");

    assert!(has_nonzero(&output.gate_term_evaluations));
    assert!(has_nonzero(&output.numerator_evaluations));
}

/// permutation recursion 失败时，H-domain 上的 permutation term 至少有一个点非 0。
#[test]
fn h_domain_permutation_failure_makes_numerator_nonzero() {
    let inputs = build_valid_inputs();
    let mut broken_a = inputs.witness_columns.wire_a_evaluations.clone();
    broken_a[0] += Fr::from(1u64);
    let broken_witness = WitnessColumns::from_evaluations(
        broken_a,
        inputs.witness_columns.wire_b_evaluations.clone(),
        inputs.witness_columns.wire_c_evaluations.clone(),
        inputs.domain_size,
    )
    .expect("witness columns should build");

    let broken_inputs = QuotientInputs::new(
        broken_witness,
        inputs.selector_columns.clone(),
        inputs.sigma_mapping.clone(),
        inputs.grand_product_evaluations.clone(),
    )
    .expect("broken inputs should build");

    let output = compute_h_domain_constraint_evaluations(
        &broken_inputs,
        &[],
        sample_alpha(),
        sample_beta(),
        sample_gamma(),
    )
    .expect("H-domain constraints should compute");

    assert!(has_nonzero(&output.permutation_term_evaluations));
    assert!(has_nonzero(&output.numerator_evaluations));
}

/// boundary 失败时，H-domain 上对应的 boundary 项应出现非 0。
#[test]
fn h_domain_boundary_failure_makes_numerator_nonzero() {
    let inputs = build_valid_inputs();
    let mut broken_z_values = inputs
        .grand_product_evaluations
        .grand_product_evaluations
        .clone();
    broken_z_values[inputs.domain_size] = Fr::from(2u64);
    let broken_z = GrandProductEvaluations {
        domain_size: inputs.domain_size,
        grand_product_evaluations: broken_z_values,
    };

    let broken_inputs = QuotientInputs::new(
        inputs.witness_columns.clone(),
        inputs.selector_columns.clone(),
        inputs.sigma_mapping.clone(),
        broken_z,
    )
    .expect("broken inputs should build");

    let output = compute_h_domain_constraint_evaluations(
        &broken_inputs,
        &[],
        sample_alpha(),
        sample_beta(),
        sample_gamma(),
    )
    .expect("H-domain constraints should compute");

    assert!(has_nonzero(&output.boundary_term_2_evaluations));
    assert!(has_nonzero(&output.numerator_evaluations));
}

/// public inputs 必须进入主约束，而不是只影响 transcript。
#[test]
fn h_domain_public_input_term_binds_statement_into_main_constraints() {
    let (inputs, public_inputs) = build_public_input_bound_inputs();
    let matching = compute_h_domain_constraint_evaluations(
        &inputs,
        &public_inputs,
        sample_alpha(),
        sample_beta(),
        sample_gamma(),
    )
    .expect("matching public inputs should compute");
    let wrong_public_inputs = vec![public_inputs[0] + Fr::from(1u64), public_inputs[1]];
    let mismatched = compute_h_domain_constraint_evaluations(
        &inputs,
        &wrong_public_inputs,
        sample_alpha(),
        sample_beta(),
        sample_gamma(),
    )
    .expect("mismatched public inputs should still compute");

    assert_eq!(matching.public_input_term_evaluations[0], public_inputs[0]);
    assert_eq!(matching.public_input_term_evaluations[1], public_inputs[1]);
    assert!(
        matching
            .numerator_evaluations
            .iter()
            .all(|value| value.is_zero())
    );
    assert!(has_nonzero(&mismatched.public_input_term_evaluations));
    assert!(has_nonzero(&mismatched.numerator_evaluations));
}

/// 扩展 quotient domain 的大小应固定为 next_power_of_two(4 * n)。
#[test]
fn extended_quotient_domain_uses_next_power_of_two_of_four_n() {
    let inputs = build_valid_inputs();
    let domain = build_extended_quotient_domain(inputs.domain_size)
        .expect("extended quotient domain should build");
    assert_eq!(domain.size(), (4 * inputs.domain_size).next_power_of_two());
}

/// 对正确 witness，extended-domain 上应满足 quotient * Z_H == numerator。
#[test]
fn extended_domain_quotient_recomposes_numerator_polynomial() {
    let inputs = build_valid_inputs();
    let output =
        compute_extended_domain_quotient(&inputs, &[], sample_alpha(), sample_beta(), sample_gamma())
            .expect("extended-domain quotient should compute");

    let vanishing_polynomial = build_h_vanishing_polynomial(output.original_domain_size);
    let recomposed = &output.quotient_polynomial * &vanishing_polynomial;
    assert_eq!(
        trim_trailing_zeros(recomposed.coeffs),
        trim_trailing_zeros(output.numerator_polynomial.coeffs)
    );
}

/// 扩展 domain 上的 quotient pointwise 定义也应满足 q(x) * Z_H(x) = numerator(x)。
#[test]
fn extended_domain_pointwise_division_matches_numerator() {
    let inputs = build_valid_inputs();
    let output =
        compute_extended_domain_quotient(&inputs, &[], sample_alpha(), sample_beta(), sample_gamma())
            .expect("extended-domain quotient should compute");

    for index in 0..output.extended_domain_size {
        assert_eq!(
            output.quotient_evaluations[index] * output.vanishing_evaluations[index],
            output.numerator_evaluations[index]
        );
    }
}

/// 顶层 Step 5.1 API 应同时返回 H-domain 与 extended-domain 两层结果。
#[test]
fn step_5_1_output_contains_both_layers() {
    let inputs = build_valid_inputs();
    let output = compute_step_5_1(&inputs, &[], sample_alpha(), sample_beta(), sample_gamma())
        .expect("step 5.1 output should compute");

    assert!(
        output
            .h_domain
            .numerator_evaluations
            .iter()
            .all(|value| value.is_zero())
    );
    assert_eq!(
        output.extended_domain.extended_domain_size,
        (4 * inputs.domain_size).next_power_of_two()
    );
}
