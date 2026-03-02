//! Step 2.2：MiMC-Feistel 的电路约束映射。
//!
//! 这里只负责把 reference 的每轮中间值展开成 Step 2.1 的 gate 行。

use crate::{
    cs::Circuit,
    curve::Fr,
    error::Result,
    mimc::{
        constants::default_round_constants,
        reference::{FeistelRoundTrace, mimc_feistel_trace},
    },
};

/// MiMC 电路构建结果（单输入单输出）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimcCircuitBuild {
    pub circuit: Circuit, // 构建好的电路
    pub output: Fr,       //输出
    pub rounds: usize,    //轮数
}

/// 基于默认固定常数构建 MiMC-Feistel 电路与 witness。
pub fn build_mimc_feistel_circuit(input: Fr, rounds: usize) -> Result<MimcCircuitBuild> {
    // 获取常量的vec
    let constants = default_round_constants(rounds)?;
    // /// 使用给定常数执行 MiMC-Feistel，并返回每一轮中间值。
    let trace = mimc_feistel_trace(input, &constants);
    // 构建电路
    let mut circuit = build_mimc_feistel_circuit_from_trace(&trace);
    // 补齐电路到域大小，准备好进行 permutation 约束。
    circuit.pad_to_domain();
    // 输出Mimc的最后的结果
    let output = trace.last().map(|round| round.left_out).unwrap_or(input);
    // 返回构建结果
    Ok(MimcCircuitBuild {
        circuit, // 电路
        output,  // 输出
        rounds,  // 轮数
    })
}

/// 使用给定 trace 构建电路，便于测试中验证“篡改 witness 会失败”。
pub fn build_mimc_feistel_circuit_from_trace(trace: &[FeistelRoundTrace]) -> Circuit {
    // 电路构建
    let mut circuit = Circuit::new();
    for (round_index, round) in trace.iter().enumerate() {
        // 把一轮 MiMC-Feistel 的中间值映射成 gate 约束。
        append_round_constraints(&mut circuit, round);
        // 添加跨轮连接约束，显式保证状态从当前轮流向下一轮。
        if let Some(next_round) = trace.get(round_index + 1) {
            // 注意这里是gate约束，还没有到permutation约束，所以不能直接把下一轮的输入等同于当前轮的输出，而是通过约束保证它们相等。
            append_cross_round_link_constraints(&mut circuit, round, next_round);
        }
    }
    circuit
}

/// 把一轮 MiMC-Feistel 的中间值映射成 gate 约束。
/// 输入circuit电路对象, round: &FeistelRoundTrace，实际的等式
/// f(x) = (x + c)^3 mod p
/// 第一步：x + c = added
/// 第二步：added^2 = squared   
/// 第三步：added^3 = cubed
/// 第四步：left_out = right_in + cubed
/// 第五步：right_out = left_in
/// 每个等式都对应一个 gate 行，输入输出分别是等式两边的变量，q_l, q_r, q_o, q_m, q_c 根据等式类型设置为 0, 1, -1 来实现线性组合约束。
fn append_round_constraints(circuit: &mut Circuit, round: &FeistelRoundTrace) {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let neg_one = -one;

    // added = left_in + constant
    circuit.add_gate_with_tag(
        round.left_in,
        zero,
        round.added,
        one,
        zero,
        neg_one,
        zero,
        round.constant,
        Some(format!("round_{}_added", round.round_index)),
    );

    // squared = added * added
    circuit.add_gate_with_tag(
        round.added,
        round.added,
        round.squared,
        zero,
        zero,
        neg_one,
        one,
        zero,
        Some(format!("round_{}_squared", round.round_index)),
    );

    // cubed = squared * added
    circuit.add_gate_with_tag(
        round.squared,
        round.added,
        round.cubed,
        zero,
        zero,
        neg_one,
        one,
        zero,
        Some(format!("round_{}_cubed", round.round_index)),
    );

    // left_out = right_in + cubed
    circuit.add_gate_with_tag(
        round.right_in,
        round.cubed,
        round.left_out,
        one,
        one,
        neg_one,
        zero,
        zero,
        Some(format!("round_{}_left_out", round.round_index)),
    );

    // right_out = left_in
    circuit.add_gate_with_tag(
        round.left_in,
        zero,
        round.right_out,
        one,
        zero,
        neg_one,
        zero,
        zero,
        Some(format!("round_{}_right_out", round.round_index)),
    );
}

/// 添加跨轮连接约束，显式保证状态从当前轮流向下一轮。
/// 注意这里是gate约束，还没有到permutation约束，所以不能直接把下一轮的输入等同于当前轮的输出，而是通过约束保证它们相等。
/// 第一步：next.left_in = current.left_out
/// 第二步：next.right_in = current.right_out
fn append_cross_round_link_constraints(
    circuit: &mut Circuit,
    current: &FeistelRoundTrace,
    next: &FeistelRoundTrace,
) {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let neg_one = -one;

    // next.left_in = current.left_out
    circuit.add_gate_with_tag(
        next.left_in,
        zero,
        current.left_out,
        one,
        zero,
        neg_one,
        zero,
        zero,
        Some(format!("link_{}_left", current.round_index)),
    );

    // next.right_in = current.right_out
    circuit.add_gate_with_tag(
        next.right_in,
        zero,
        current.right_out,
        one,
        zero,
        neg_one,
        zero,
        zero,
        Some(format!("link_{}_right", current.round_index)),
    );
}
