//! Step 2.x：常见 gate 语义封装。
//!
//! 设计边界：
//! - 只封装高频、通用的约束表达
//! - 内部仅调用 `Circuit::add_gate_with_tag`
//! - 不引入 wiring、copy constraints 或 DSL 逻辑

use crate::{cs::Circuit, curve::Fr};

/// 约束：`a * b - c = 0`
/// 示例：输入 `(a=3, b=4, c=12)` 时约束成立。
pub fn enforce_mul(circuit: &mut Circuit, a: Fr, b: Fr, c: Fr, tag: Option<String>) {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let neg_one = -one;
    circuit.add_gate_with_tag(a, b, c, zero, zero, neg_one, one, zero, tag);
}

/// 约束：`a + b - c = 0`
/// 示例：输入 `(a=2, b=5, c=7)` 时约束成立。
pub fn enforce_add(circuit: &mut Circuit, a: Fr, b: Fr, c: Fr, tag: Option<String>) {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let neg_one = -one;
    circuit.add_gate_with_tag(a, b, c, one, one, neg_one, zero, zero, tag);
}

/// 约束：`qL*a + qR*b + qO*c + qC = 0`
/// 示例：输入 `qL=2, qR=3, qO=-1, qC=0` 时表示 `2a + 3b - c = 0`。
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
) {
    let zero = Fr::from(0u64);
    circuit.add_gate_with_tag(a, b, c, q_l, q_r, q_o, zero, q_c, tag);
}

/// 约束：`qM*a*b + qL*a + qR*b + qO*c + qC = 0`
/// 示例：输入 `qM=1, qL=0, qR=0, qO=-1, qC=0` 与 `enforce_mul` 等价。
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
) {
    circuit.add_gate_with_tag(a, b, c, q_l, q_r, q_o, q_m, q_c, tag);
}
