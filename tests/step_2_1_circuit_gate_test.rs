//! Step 2.1 验收测试：
//! - 正确 witness 的 gate 约束应满足
//! - 错误 witness 的 gate 约束应失败
//! - `pad_to_domain` 应补齐到下一个 2^k，并插入零约束行

use minimal_plonk::{
    cs::Circuit,
    curve::Fr,
};

/// 测试单行 gate：`a * b - c = 0` 在正确 witness 下成立。
#[test]
fn valid_gate_witness_passes_constraint_check() {
    let mut circuit = Circuit::new();

    let wire_a = Fr::from(3u64);
    let wire_b = Fr::from(4u64);
    let wire_c = Fr::from(12u64);
    let q_l = Fr::from(0u64);
    let q_r = Fr::from(0u64);
    let q_o = -Fr::from(1u64);
    let q_m = Fr::from(1u64);
    let q_c = Fr::from(0u64);

    circuit
        .add_gate(wire_a, wire_b, wire_c, q_l, q_r, q_o, q_m, q_c)
        .expect("adding gate should succeed");

    assert_eq!(
        circuit
            .gate_constraint_value(0)
            .expect("row must exist"),
        Fr::from(0u64)
    );
    assert!(
        circuit
            .is_gate_satisfied(0)
            .expect("row must exist"),
        "row 0 should satisfy gate constraint"
    );
    assert!(circuit.are_all_gates_satisfied());
    assert_eq!(circuit.first_unsatisfied_row(), None);
}

/// 测试单行 gate：`a * b - c = 0` 在错误 witness 下失败。
#[test]
fn invalid_gate_witness_fails_constraint_check() {
    let mut circuit = Circuit::new();

    let wire_a = Fr::from(3u64);
    let wire_b = Fr::from(4u64);
    let wire_c = Fr::from(11u64);
    let q_l = Fr::from(0u64);
    let q_r = Fr::from(0u64);
    let q_o = -Fr::from(1u64);
    let q_m = Fr::from(1u64);
    let q_c = Fr::from(0u64);

    circuit
        .add_gate(wire_a, wire_b, wire_c, q_l, q_r, q_o, q_m, q_c)
        .expect("adding gate should succeed");

    assert_ne!(
        circuit
            .gate_constraint_value(0)
            .expect("row must exist"),
        Fr::from(0u64)
    );
    assert!(
        !circuit
            .is_gate_satisfied(0)
            .expect("row must exist"),
        "row 0 should fail gate constraint"
    );
    assert!(!circuit.are_all_gates_satisfied());
    assert_eq!(circuit.first_unsatisfied_row(), Some(0));
}

/// 行数为 3 时应 pad 到 4，且新增行是零约束 padding 行。
#[test]
fn pad_to_domain_pads_to_next_power_of_two_with_zero_rows() {
    let mut circuit = Circuit::new();

    for value in [1u64, 2u64, 3u64] {
        circuit
            .add_gate(
                Fr::from(value),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .expect("adding gate should succeed");
    }

    assert_eq!(circuit.num_rows(), 3);
    assert_eq!(circuit.domain_size(), None);

    circuit.pad_to_domain();

    assert_eq!(circuit.domain_size(), Some(4));
    assert_eq!(circuit.num_rows(), 4);

    let padded_row = circuit.row(3).expect("padded row must exist");
    assert!(padded_row.is_padding);
    assert!(padded_row.is_satisfied());
    assert_eq!(padded_row.wire_a, Fr::from(0u64));
    assert_eq!(padded_row.wire_b, Fr::from(0u64));
    assert_eq!(padded_row.wire_c, Fr::from(0u64));
    assert_eq!(padded_row.q_l, Fr::from(0u64));
    assert_eq!(padded_row.q_r, Fr::from(0u64));
    assert_eq!(padded_row.q_o, Fr::from(0u64));
    assert_eq!(padded_row.q_m, Fr::from(0u64));
    assert_eq!(padded_row.q_c, Fr::from(0u64));
}

/// 索引越界时应返回错误，避免读取非法行。
#[test]
fn circuit_rejects_out_of_range_row_index() {
    let circuit = Circuit::new();
    assert!(circuit.gate_constraint_value(0).is_err());
    assert!(circuit.is_gate_satisfied(0).is_err());
    assert!(circuit.row(0).is_err());
}

/// pad_to_domain 之后继续 add_gate 必须失败，避免中间 padding 与后续行混在一起。
#[test]
fn add_gate_fails_after_pad_to_domain() {
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
        .expect("adding gate before padding should succeed");

    circuit.pad_to_domain();

    let result = circuit.add_gate(
        Fr::from(4u64),
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    assert!(result.is_err());
    assert!(circuit.is_frozen());
    assert_eq!(circuit.num_rows(), 1);
}
