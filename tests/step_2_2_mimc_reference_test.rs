//! Step 2.2：MiMC reference 验收测试。

use minimal_plonk::{
    curve::Fr,
    mimc::{MAX_ROUNDS, constants::default_round_constants, mimc_feistel, mimc_feistel_trace},
};

/// 相同输入与轮数应当给出确定性输出。
#[test]
fn mimc_reference_is_deterministic() {
    let input = Fr::from(9u64);
    let first = mimc_feistel(input, 8).expect("reference should run");
    let second = mimc_feistel(input, 8).expect("reference should run");
    assert_eq!(first, second);
}

/// 1 轮时，Feistel 输出应退化为 `x^3`（因为初始右支为 0，常数为 0）。
#[test]
fn one_round_reference_matches_x_cubed() {
    for sample in [0u64, 1u64, 2u64, 3u64, 11u64] {
        let input = Fr::from(sample);
        let expected = input * input * input;
        let output = mimc_feistel(input, 1).expect("reference should run");
        assert_eq!(output, expected);
    }
}

/// 2 轮时可手算为：`x + (x^3 + 1)^3`。
#[test]
fn two_round_reference_matches_closed_form() {
    for sample in [0u64, 1u64, 2u64, 4u64] {
        let input = Fr::from(sample);
        let x_cubed = input * input * input;
        let inner = x_cubed + Fr::from(1u64);
        let expected = input + inner * inner * inner;
        let output = mimc_feistel(input, 2).expect("reference should run");
        assert_eq!(output, expected);
    }
}

/// trace 长度应等于轮数，且相邻轮状态衔接一致。
#[test]
fn trace_length_and_state_link_are_correct() {
    let constants = default_round_constants(6).expect("constants should exist");
    let trace = mimc_feistel_trace(Fr::from(5u64), &constants);
    assert_eq!(trace.len(), 6);

    for index in 1..trace.len() {
        let previous = &trace[index - 1];
        let current = &trace[index];
        assert_eq!(current.left_in, previous.left_out);
        assert_eq!(current.right_in, previous.right_out);
    }
}

/// rounds 边界应被正确拒绝，避免使用无效常数配置。
#[test]
fn constants_reject_invalid_rounds() {
    assert!(default_round_constants(0).is_err());
    assert!(default_round_constants(MAX_ROUNDS + 1).is_err());
}
