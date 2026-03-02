//! Step 2.1：标准 Plonk gate 行表示。
//!
//! 约束形式：
//! `qM * a * b + qL * a + qR * b + qO * c + qC = 0`

use crate::curve::Fr;

/// 一行 Plonk gate 的完整数据（witness + selectors）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateRow {
    pub wire_a: Fr,
    pub wire_b: Fr,
    pub wire_c: Fr,
    pub q_l: Fr,
    pub q_r: Fr,
    pub q_o: Fr,
    pub q_m: Fr,
    pub q_c: Fr,
    pub tag: Option<String>,
    pub is_padding: bool,
}

impl GateRow {
    /// 用完整的一行输入创建普通 gate（非 padding）。
    pub fn new(
        wire_a: Fr,
        wire_b: Fr,
        wire_c: Fr,
        q_l: Fr,
        q_r: Fr,
        q_o: Fr,
        q_m: Fr,
        q_c: Fr,
        tag: Option<String>,
    ) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            q_l,
            q_r,
            q_o,
            q_m,
            q_c,
            tag,
            is_padding: false,
        }
    }

    /// 创建一行“零约束 padding 行”。
    pub fn zero_padding() -> Self {
        let zero = Fr::from(0u64);
        Self {
            wire_a: zero,
            wire_b: zero,
            wire_c: zero,
            q_l: zero,
            q_r: zero,
            q_o: zero,
            q_m: zero,
            q_c: zero,
            tag: Some("padding".to_string()),
            is_padding: true,
        }
    }

    /// 计算该行 gate 约束左侧值（应等于 0 才满足约束）。
    pub fn constraint_value(&self) -> Fr {
        let multiplicative_term = self.q_m * self.wire_a * self.wire_b;
        let linear_a_term = self.q_l * self.wire_a;
        let linear_b_term = self.q_r * self.wire_b;
        let output_term = self.q_o * self.wire_c;
        multiplicative_term + linear_a_term + linear_b_term + output_term + self.q_c
    }

    /// 判断该行是否满足 gate 约束。
    pub fn is_satisfied(&self) -> bool {
        self.constraint_value() == Fr::from(0u64)
    }
}
