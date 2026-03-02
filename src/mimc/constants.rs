//! Step 2.2：MiMC-Feistel 固定轮常数。
//!
//! 这里使用写死常数，保证实现与 benchmark 可复现。

use crate::{
    curve::Fr,
    error::{PlonkError, Result},
    validate::ensure,
};

/// 默认轮数（用于示例和测试）。
pub const DEFAULT_ROUNDS: usize = 16;

/// 当前写死常数支持的最大轮数。
pub const MAX_ROUNDS: usize = 32;

const ROUND_CONSTANTS_U64: [u64; MAX_ROUNDS] = [
    0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765, 10946,
    17711, 28657, 46368, 75025, 121393, 196418, 317811, 514229, 832040, 1346269, 2178309,
];

/// 返回指定轮数的固定 round constants。
/// 例如输入1，输出 [0]；输入3，输出 [0, 1, 2]。
pub fn default_round_constants(rounds: usize) -> Result<Vec<Fr>> {
    ensure(rounds > 0, "round count must be positive")?;
    ensure(
        rounds <= MAX_ROUNDS,
        "round count exceeds built-in constant capacity",
    )?;

    let constants = ROUND_CONSTANTS_U64[..rounds]
        .iter()
        .copied()
        .map(Fr::from)
        .collect::<Vec<_>>();
    if constants.len() != rounds {
        return Err(PlonkError::InvalidInput(
            "failed to build round constants with requested length",
        ));
    }
    Ok(constants)
}
