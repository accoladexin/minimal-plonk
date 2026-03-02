//! Step 2.2：MiMC 电路验收测试。

use minimal_plonk::{
    curve::Fr,
    mimc::{
        build_mimc_feistel_circuit, build_mimc_feistel_circuit_from_trace, default_round_constants,
        mimc_feistel, mimc_feistel_trace, FeistelRoundTrace, MAX_ROUNDS,
    },
};

/// 电路输出应与 reference 输出严格一致，且约束全部满足。
#[test]
fn mimc_circuit_matches_reference_output() {
    let rounds = 10;
    for sample in [0u64, 1u64, 7u64, 19u64] {
        let input = Fr::from(sample);
        // 直接调用 reference 实现获取预期输出，并构建电路验证约束满足。
        let expected = mimc_feistel(input, rounds).expect("reference should run");
        // 构建电路
        let build = build_mimc_feistel_circuit(input, rounds).expect("circuit should build");

        assert_eq!(build.output, expected);
        // 验证电路约束满足，即验证 witness 的正确性。比如3*5 = 15
        assert!(build.circuit.are_all_gates_satisfied());
        // 注意这里不要求 domain size 是特定值，只要它被设置了（不是 None）就说明 pad_to_domain 起作用了。
        assert!(build.circuit.domain_size().is_some());
    }
}

/// 篡改某轮 witness 后，至少一行 gate 约束应失败。
#[test]
fn tampered_trace_breaks_gate_constraints() {
    let constants = default_round_constants(8).expect("constants should exist");
    let mut trace = mimc_feistel_trace(Fr::from(3u64), &constants);
    trace[2].cubed += Fr::from(1u64);

    let mut circuit = build_mimc_feistel_circuit_from_trace(&trace);
    circuit.pad_to_domain();

    assert!(!circuit.are_all_gates_satisfied());
    assert!(circuit.first_unsatisfied_row().is_some());
}

/// 即使每轮内部约束都自洽，只要跨轮状态连接被破坏，也必须失败。
#[test]
fn broken_cross_round_link_is_detected() {
    // 只要8轮
    let constants = default_round_constants(8).expect("constants should exist");
    // 构建一个合法 trace
    let mut trace = mimc_feistel_trace(Fr::from(5u64), &constants);

    // 只改第 3 轮输入，并重算这一轮内部字段，使其“单轮内”仍自洽。
    trace[3].left_in += Fr::from(1u64);
    recompute_round_in_place(&mut trace[3]);

    // 构建电路
    let mut circuit = build_mimc_feistel_circuit_from_trace(&trace);
    // 填充到2^n
    circuit.pad_to_domain();

    // 一定不会满足，因为换行是拿两行的数据去构建的gate
    assert!(!circuit.are_all_gates_satisfied());
    assert!(circuit.first_unsatisfied_row().is_some());
}

fn recompute_round_in_place(round: &mut FeistelRoundTrace) {
    round.added = round.left_in + round.constant;
    round.squared = round.added * round.added;
    round.cubed = round.squared * round.added;
    round.left_out = round.right_in + round.cubed;
    round.right_out = round.left_in;
}

/// 构建电路时也要遵守 rounds 边界。
#[test]
fn circuit_builder_rejects_invalid_rounds() {
    let input = Fr::from(1u64);
    assert!(build_mimc_feistel_circuit(input, 0).is_err());
    assert!(build_mimc_feistel_circuit(input, MAX_ROUNDS + 1).is_err());
}
