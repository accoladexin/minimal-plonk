//! Step 2.2：MiMC-Feistel 的电路约束映射。
//!
//! 这里只负责把 reference 的每轮中间值展开成 Step 2.1 的 gate 行。

use crate::{
    cs::{
        builtin_gates::{enforce_add, enforce_linear, enforce_mul},
        Circuit,
    },
    curve::Fr,
    error::Result,
    mimc::{
        constants::default_round_constants,
        reference::{mimc_feistel_trace, FeistelRoundTrace},
    },
};

/// MiMC 电路构建结果（单输入单输出）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimcCircuitBuild {
    pub circuit: Circuit, // 构建好的电路
    pub output: Fr,       // 输出
    pub rounds: usize,    // 轮数
}

/// 基于默认固定常数构建 MiMC-Feistel 电路与 witness。
/// 示例：输入 `input=7, rounds=16`，返回包含约束行、输出值和轮数的构建结果。
pub fn build_mimc_feistel_circuit(input: Fr, rounds: usize) -> Result<MimcCircuitBuild> {
    let constants = default_round_constants(rounds)?;
    let trace = mimc_feistel_trace(input, &constants);
    let mut circuit = build_mimc_feistel_circuit_from_trace(&trace);
    circuit.pad_to_domain();

    let output = trace.last().map(|round| round.left_out).unwrap_or(input);
    Ok(MimcCircuitBuild {
        circuit,
        output,
        rounds,
    })
}

/// 使用给定 trace 构建电路，便于测试中验证“篡改 witness 会失败”。
/// 示例：输入一组 Feistel 轮 trace，输出仅由 gate 约束组成的电路（未 pad）。
pub fn build_mimc_feistel_circuit_from_trace(trace: &[FeistelRoundTrace]) -> Circuit {
    let mut circuit = Circuit::new();
    for (round_index, round) in trace.iter().enumerate() {
        append_round_constraints(&mut circuit, round);
        if let Some(next_round) = trace.get(round_index + 1) {
            append_cross_round_link_constraints(&mut circuit, round, next_round);
        }
    }
    circuit
}

/// 把一轮 MiMC-Feistel 的中间值映射成 gate 约束。
/// 示例：对第 i 轮会加入 5 条约束：add_const、square、mul、feistel_left、feistel_right。
fn append_round_constraints(circuit: &mut Circuit, round: &FeistelRoundTrace) {
    enforce_linear(
        circuit,
        round.left_in,
        Fr::from(0u64),
        round.added,
        Fr::from(1u64),
        Fr::from(0u64),
        -Fr::from(1u64),
        round.constant,
        Some(format!("mimc r{}: add_const", round.round_index)),
    );

    enforce_mul(
        circuit,
        round.added,
        round.added,
        round.squared,
        Some(format!("mimc r{}: square", round.round_index)),
    );

    enforce_mul(
        circuit,
        round.squared,
        round.added,
        round.cubed,
        Some(format!("mimc r{}: mul", round.round_index)),
    );

    enforce_add(
        circuit,
        round.right_in,
        round.cubed,
        round.left_out,
        Some(format!("mimc r{}: feistel_left", round.round_index)),
    );

    enforce_linear(
        circuit,
        round.left_in,
        Fr::from(0u64),
        round.right_out,
        Fr::from(1u64),
        Fr::from(0u64),
        -Fr::from(1u64),
        Fr::from(0u64),
        Some(format!("mimc r{}: feistel_right", round.round_index)),
    );
}

/// 添加跨轮连接约束，显式保证状态从当前轮流向下一轮。
/// 示例：约束 `next.left_in = current.left_out` 与 `next.right_in = current.right_out`。
fn append_cross_round_link_constraints(
    circuit: &mut Circuit,
    current: &FeistelRoundTrace,
    next: &FeistelRoundTrace,
) {
    enforce_linear(
        circuit,
        next.left_in,
        Fr::from(0u64),
        current.left_out,
        Fr::from(1u64),
        Fr::from(0u64),
        -Fr::from(1u64),
        Fr::from(0u64),
        Some(format!("mimc r{}: link_left", current.round_index)),
    );

    enforce_linear(
        circuit,
        next.right_in,
        Fr::from(0u64),
        current.right_out,
        Fr::from(1u64),
        Fr::from(0u64),
        -Fr::from(1u64),
        Fr::from(0u64),
        Some(format!("mimc r{}: link_right", current.round_index)),
    );
}
