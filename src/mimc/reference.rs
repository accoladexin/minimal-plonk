//! Step 2.2：MiMC-Feistel reference 实现（纯算法）。
//!
//! 说明：
//! - 这个文件不涉及电路约束
//! - 所有 Step 2.2 验收以此实现为 oracle

use crate::{
    curve::Fr,
    error::Result,
    mimc::constants::default_round_constants,
};

/// MiMC-Feistel 单轮的完整中间值（用于电路 witness 构造）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeistelRoundTrace {
    pub round_index: usize,
    pub constant: Fr,
    pub left_in: Fr,
    pub right_in: Fr,
    pub added: Fr,
    pub squared: Fr,
    pub cubed: Fr,
    pub left_out: Fr,
    pub right_out: Fr,
}

/// 使用默认固定常数执行 MiMC-Feistel，并返回单输出值。
pub fn mimc_feistel(input: Fr, rounds: usize) -> Result<Fr> {
    // 获取常量的vec
    let constants = default_round_constants(rounds)?;
    // 执行 Feistel 计算并获取完整 trace
    let trace = mimc_feistel_trace(input, &constants);
    // 返回最后的结果
    Ok(trace
        .last()
        .map(|round| round.left_out)
        .unwrap_or(input))
}

/// 使用给定常数执行 MiMC-Feistel，并返回每一轮中间值。
pub fn mimc_feistel_trace(input: Fr, constants: &[Fr]) -> Vec<FeistelRoundTrace> {
    let mut left_state = input;
    let mut right_state = Fr::from(0u64);
    let mut trace = Vec::with_capacity(constants.len());

    for (round_index, constant) in constants.iter().copied().enumerate() {
        let added = left_state + constant;
        let squared = added * added;
        let cubed = squared * added;
        let next_left = right_state + cubed;
        let next_right = left_state;

        trace.push(FeistelRoundTrace {
            round_index,
            constant,
            left_in: left_state,
            right_in: right_state,
            added,
            squared,
            cubed,
            left_out: next_left,
            right_out: next_right,
        });

        left_state = next_left;
        right_state = next_right;
    }

    trace
}
