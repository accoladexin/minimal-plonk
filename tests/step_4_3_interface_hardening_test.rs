//! Step 4.3 回归测试：
//! - padded circuit 冻结
//! - selector 提取与 witness 同域
//! - n = 1
//! - 空 witness 拒绝
//! - Circuit -> Witness -> Sigma -> Z -> QuotientInputs 整链路 smoke test

use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    permutation::{
        build_sigma_from_copy_constraints, compute_grand_product_evaluations, Column,
        CopyConstraint, Pos,
    },
    types::QuotientInputs,
    witness::WitnessColumns,
};

/// pad_to_domain 之后继续 add_gate_with_tag 也必须失败。
#[test]
fn add_gate_with_tag_fails_after_pad_to_domain() {
    let mut circuit = Circuit::new();
    circuit
        .add_gate(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit.pad_to_domain();

    let result = circuit.add_gate_with_tag(
        Fr::from(4u64),
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Some("late gate".to_string()),
    );
    assert!(result.is_err());
}

/// `n = 1` 时整条 permutation 主路径也应成立。
#[test]
fn grand_product_supports_domain_size_one() {
    let mut circuit = Circuit::new();
    circuit
        .add_gate(
            Fr::from(7u64),
            Fr::from(7u64),
            Fr::from(7u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit.pad_to_domain();

    let witness = WitnessColumns::from_padded_circuit(&circuit).expect("witness should extract");
    let sigma_constraints = vec![
        CopyConstraint {
            left: Pos {
                col: Column::A,
                row: 0,
            },
            right: Pos {
                col: Column::B,
                row: 0,
            },
        },
        CopyConstraint {
            left: Pos {
                col: Column::B,
                row: 0,
            },
            right: Pos {
                col: Column::C,
                row: 0,
            },
        },
    ];
    let sigma = build_sigma_from_copy_constraints(1, &sigma_constraints)
        .expect("sigma should build for n = 1");
    let z = compute_grand_product_evaluations(
        &witness.wire_a_evaluations,
        &witness.wire_b_evaluations,
        &witness.wire_c_evaluations,
        &sigma,
        Fr::from(13u64),
        Fr::from(17u64),
    )
    .expect("grand product should compute for n = 1");

    assert_eq!(z.domain_size, 1);
    assert_eq!(z.grand_product_evaluations.len(), 2);
}

/// 空 witness 应被 grand product 主路径显式拒绝。
#[test]
fn empty_witness_is_rejected() {
    let sigma = build_sigma_from_copy_constraints(1, &[]).expect("identity sigma should build");
    let result = compute_grand_product_evaluations(
        &[],
        &[],
        &[],
        &sigma,
        Fr::from(5u64),
        Fr::from(9u64),
    );
    assert!(result.is_err());
}

/// selector 提取应与 witness 使用同一个 domain 语义。
#[test]
fn selector_extraction_matches_padded_domain() {
    let mut circuit = Circuit::new();
    circuit
        .add_gate(
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(12u64),
            Fr::from(0u64),
            Fr::from(0u64),
            -Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit.pad_to_domain();

    let witness = WitnessColumns::from_padded_circuit(&circuit).expect("witness should extract");
    let selectors =
        SelectorColumns::from_padded_circuit(&circuit).expect("selectors should extract");

    assert_eq!(witness.domain_size(), selectors.domain_size());
    assert_eq!(selectors.q_m_evaluations, vec![Fr::from(1u64)]);
    assert_eq!(selectors.q_o_evaluations, vec![-Fr::from(1u64)]);
}

/// Step 4.3 的最小目标：把 Step 5 所需输入收口为同域对象。
#[test]
fn quotient_inputs_smoke_test() {
    let mut circuit = Circuit::new();
    circuit
        .add_gate(
            Fr::from(31u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit
        .add_gate(
            Fr::from(2u64),
            Fr::from(31u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit
        .add_gate(
            Fr::from(3u64),
            Fr::from(0u64),
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
        Fr::from(13u64),
        Fr::from(29u64),
    )
    .expect("grand product should compute");

    let inputs =
        QuotientInputs::new(witness.clone(), selectors.clone(), sigma.clone(), z.clone())
            .expect("quotient inputs should build");

    assert_eq!(inputs.domain_size, 4);
    assert_eq!(inputs.witness_columns, witness);
    assert_eq!(inputs.selector_columns, selectors);
    assert_eq!(inputs.sigma_mapping, sigma);
    assert_eq!(inputs.grand_product_evaluations, z);
}
