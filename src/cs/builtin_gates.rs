//! Step 2.x: 常见 gate 的语义化封装。
//!
//! 设计边界：
//! - 只封装高频、通用的约束表达
//! - 内部只调用 `Circuit::add_gate_with_tag`
//! - 不引入 wiring、copy constraints 或 DSL 逻辑

use crate::{cs::Circuit, curve::Fr, error::Result};

/// 功能说明：添加乘法约束 `a * b - c = 0`。
/// 输入：电路、一行 witness 值和可选标签。
/// 输出：成功返回 `Ok(())`，若电路已冻结则返回错误。
/// 示例：`enforce_mul(&mut circuit, 3.into(), 4.into(), 12.into(), None)?;`
pub fn enforce_mul(circuit: &mut Circuit, a: Fr, b: Fr, c: Fr, tag: Option<String>) -> Result<()> {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let neg_one = -one;
    circuit.add_gate_with_tag(a, b, c, zero, zero, neg_one, one, zero, tag)
}

/// 功能说明：添加加法约束 `a + b - c = 0`。
/// 输入：电路、一行 witness 值和可选标签。
/// 输出：成功返回 `Ok(())`，若电路已冻结则返回错误。
/// 示例：`enforce_add(&mut circuit, 2.into(), 5.into(), 7.into(), None)?;`
pub fn enforce_add(circuit: &mut Circuit, a: Fr, b: Fr, c: Fr, tag: Option<String>) -> Result<()> {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let neg_one = -one;
    circuit.add_gate_with_tag(a, b, c, one, one, neg_one, zero, zero, tag)
}

/// 功能说明：添加线性约束 `qL*a + qR*b + qO*c + qC = 0`。
/// 输入：电路、witness 值、线性 selector 和可选标签。
/// 输出：成功返回 `Ok(())`，若电路已冻结则返回错误。
/// 示例：`enforce_linear(&mut circuit, a, b, c, q_l, q_r, q_o, q_c, None)?;`
pub fn enforce_linear(
    circuit: &mut Circuit,
    a: Fr,
    b: Fr,
    c: Fr,
    q_l: Fr,
    q_r: Fr,
    q_o: Fr,
    q_c: Fr,
    tag: Option<String>,
) -> Result<()> {
    let zero = Fr::from(0u64);
    circuit.add_gate_with_tag(a, b, c, q_l, q_r, q_o, zero, q_c, tag)
}

/// 功能说明：添加通用乘加约束 `qM*a*b + qL*a + qR*b + qO*c + qC = 0`。
/// 输入：电路、witness 值、全部 selector 和可选标签。
/// 输出：成功返回 `Ok(())`，若电路已冻结则返回错误。
/// 示例：`enforce_mul_add(&mut circuit, a, b, c, q_m, q_l, q_r, q_o, q_c, None)?;`
pub fn enforce_mul_add(
    circuit: &mut Circuit,
    a: Fr,
    b: Fr,
    c: Fr,
    q_m: Fr,
    q_l: Fr,
    q_r: Fr,
    q_o: Fr,
    q_c: Fr,
    tag: Option<String>,
) -> Result<()> {
    circuit.add_gate_with_tag(a, b, c, q_l, q_r, q_o, q_m, q_c, tag)
}
