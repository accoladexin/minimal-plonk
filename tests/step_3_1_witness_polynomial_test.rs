//! Step 3.1 验收测试：
//! - 必须先 pad 才能提取 witness evaluations
//! - a/b/c 列长度一致性检查
//! - evaluations 顺序与电路行顺序一致
//! - evals -> poly -> evals 插值回一致

use minimal_plonk::{
    cs::Circuit,
    curve::Fr,
    domain::{build_domain_from_size, polynomial_to_evaluations},
    error::PlonkError,
    witness::{interpolate_witness_column_polynomials, WitnessColumns},
};

/// 构造一个顺序明确的测试电路，并完成 pad。
fn build_padded_sample_circuit() -> Circuit {
    let mut circuit = Circuit::new();

    circuit
        .add_gate(
            Fr::from(11u64),
            Fr::from(101u64),
            Fr::from(1001u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit
        .add_gate(
            Fr::from(22u64),
            Fr::from(202u64),
            Fr::from(2002u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");
    circuit
        .add_gate(
            Fr::from(33u64),
            Fr::from(303u64),
            Fr::from(3003u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )
        .expect("adding gate should succeed");

    circuit.pad_to_domain();
    circuit
}

/// 未执行 `pad_to_domain` 时，不允许进入 Step 3.1 witness 提取。
#[test]
fn witness_extraction_requires_padded_circuit() {
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

    let result = WitnessColumns::from_padded_circuit(&circuit);
    assert_eq!(
        result,
        Err(PlonkError::InvalidInput(
            "circuit must call pad_to_domain() before Step 3.1 witness extraction"
        ))
    );
}

/// 三列长度与 domain_size 不一致时，必须返回 `InconsistentLength`。
#[test]
fn witness_columns_reject_inconsistent_lengths() {
    let result = WitnessColumns::from_evaluations(
        vec![Fr::from(1u64), Fr::from(2u64)],
        vec![Fr::from(3u64)],
        vec![Fr::from(4u64), Fr::from(5u64)],
        2,
    );
    assert_eq!(
        result,
        Err(PlonkError::InconsistentLength(
            "a_eval.len == b_eval.len == c_eval.len == domain_size must hold"
        ))
    );
}

/// a/b/c evaluations 顺序必须与电路行顺序一致（防止反转或乱序）。
#[test]
fn witness_evaluation_order_matches_row_order() {
    let circuit = build_padded_sample_circuit();
    let columns = WitnessColumns::from_padded_circuit(&circuit).expect("extraction should succeed");

    assert_eq!(
        columns.wire_a_evaluations,
        vec![Fr::from(11u64), Fr::from(22u64), Fr::from(33u64), Fr::from(0u64)]
    );
    assert_eq!(
        columns.wire_b_evaluations,
        vec![
            Fr::from(101u64),
            Fr::from(202u64),
            Fr::from(303u64),
            Fr::from(0u64)
        ]
    );
    assert_eq!(
        columns.wire_c_evaluations,
        vec![
            Fr::from(1001u64),
            Fr::from(2002u64),
            Fr::from(3003u64),
            Fr::from(0u64)
        ]
    );
    assert_eq!(columns.domain_size(), 4);
}

/// 插值后再评估，应回到原始 evaluations（Step 3.1 关键一致性）。
#[test]
fn interpolation_round_trip_matches_original_witness_evaluations() {
    let circuit = build_padded_sample_circuit();
    let columns = WitnessColumns::from_padded_circuit(&circuit).expect("extraction should succeed");
    let domain = build_domain_from_size(columns.domain_size()).expect("domain should build");

    let polynomials =
        interpolate_witness_column_polynomials(&domain, &columns).expect("interpolation should work");

    let a_back =
        polynomial_to_evaluations(&domain, &polynomials.wire_a_poly).expect("evaluation should work");
    let b_back =
        polynomial_to_evaluations(&domain, &polynomials.wire_b_poly).expect("evaluation should work");
    let c_back =
        polynomial_to_evaluations(&domain, &polynomials.wire_c_poly).expect("evaluation should work");

    assert_eq!(a_back, columns.wire_a_evaluations);
    assert_eq!(b_back, columns.wire_b_evaluations);
    assert_eq!(c_back, columns.wire_c_evaluations);
}
