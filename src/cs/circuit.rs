//! Step 2.1：电路行集合管理。
//!
//! 该模块只做“纯域运算约束检查”，不包含任何承诺、pairing 或 transcript 逻辑。

use crate::{
    curve::Fr,
    cs::gate::GateRow,
    error::{PlonkError, Result},
    validate::ensure,
};

/// 最小电路容器：按行保存 gate，并记录 pad 后的 domain 大小。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Circuit {
    rows: Vec<GateRow>,         // 实际存储的每一行数据
    domain_size: Option<usize>, // 记录“补齐”后的最终规模
}

impl Circuit {
    /// 创建空电路。
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            domain_size: None,
        }
    }

    /// 读取当前所有 gate 行（只读视图）。
    pub fn rows(&self) -> &[GateRow] {
        &self.rows
    }

    /// 返回当前行数。
    pub fn num_rows(&self) -> usize {
        self.rows.len()
    }

    /// 返回最近一次 `pad_to_domain` 后记录的 domain 大小。
    pub fn domain_size(&self) -> Option<usize> {
        self.domain_size
    }

    /// 按 Step 2.1 约定一次加入一整行 gate。
    pub fn add_gate(
        &mut self,
        wire_a: Fr,
        wire_b: Fr,
        wire_c: Fr,
        q_l: Fr,
        q_r: Fr,
        q_o: Fr,
        q_m: Fr,
        q_c: Fr,
    ) {
        self.add_gate_with_tag(
            wire_a, wire_b, wire_c, q_l, q_r, q_o, q_m, q_c, None,
        );
    }

    /// 与 `add_gate` 相同，但允许添加调试标签。
    pub fn add_gate_with_tag(
        &mut self,
        wire_a: Fr,
        wire_b: Fr,
        wire_c: Fr,
        q_l: Fr,
        q_r: Fr,
        q_o: Fr,
        q_m: Fr,
        q_c: Fr,
        tag: Option<String>,
    ) {
        self.rows.push(GateRow::new(
            wire_a, wire_b, wire_c, q_l, q_r, q_o, q_m, q_c, tag,
        ));
        self.domain_size = None;
    }

    /// 将行数补齐到“当前行数的下一个 2^k”，并记录 `domain_size`。
    pub fn pad_to_domain(&mut self) {
        let current_rows = self.rows.len();
        let target_size = if current_rows == 0 {
            1 // 即使没有行，也要补齐到至少 1 行，以满足后续对 domain_size 的假设。
        } else {
            // 计算下一个 2 的幂次方，确保 domain_size 是合法的域大小。
            current_rows.next_power_of_two()
        };

        while self.rows.len() < target_size {
            self.rows.push(GateRow::zero_padding());
        }
        self.domain_size = Some(target_size);
    }

    /// 计算指定行的 gate 约束值。
    pub fn gate_constraint_value(&self, row_index: usize) -> Result<Fr> {
        ensure(row_index < self.rows.len(), "row index out of range")?;
        Ok(self.rows[row_index].constraint_value())
    }

    /// 判断指定行是否满足 gate 约束。
    pub fn is_gate_satisfied(&self, row_index: usize) -> Result<bool> {
        ensure(row_index < self.rows.len(), "row index out of range")?;
        Ok(self.rows[row_index].is_satisfied())
    }

    /// 检查所有行是否都满足 gate 约束。
    pub fn are_all_gates_satisfied(&self) -> bool {
        self.rows.iter().all(GateRow::is_satisfied)
    }

    /// 若存在首个失败行，返回其索引，便于测试或调试定位。
    pub fn first_unsatisfied_row(&self) -> Option<usize> {
        self.rows
            .iter()
            .enumerate()
            .find_map(|(index, row)| (!row.is_satisfied()).then_some(index))
    }

    /// 读取指定行，便于外部调试使用。
    pub fn row(&self, row_index: usize) -> Result<&GateRow> {
        self.rows
            .get(row_index)
            .ok_or(PlonkError::InvalidInput("row index out of range"))
    }
}
