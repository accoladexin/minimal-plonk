//! Step 2.1: 电路行集合管理。
//!
//! 这个模块只做纯域运算约束检查，不包含任何承诺、pairing 或 transcript 逻辑。

use crate::{
    cs::gate::GateRow,
    curve::Fr,
    error::{PlonkError, Result},
    validate::ensure,
};

/// 最小电路容器：按行保存 gate，并记录 pad 后的 domain 大小。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Circuit {
    rows: Vec<GateRow>,
    domain_size: Option<usize>,
    is_frozen: bool, // 标记电路是否已冻结
}

impl Circuit {
    /// 功能说明：创建一个空电路。
    /// 输入：无。
    /// 输出：空的 `Circuit`。
    /// 示例：`let circuit = Circuit::new();`
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            domain_size: None,
            is_frozen: false,
        }
    }

    /// 功能说明：读取当前所有 gate 行的只读视图。
    /// 输入：`self`。
    /// 输出：`&[GateRow]`。
    /// 示例：`let rows = circuit.rows();`
    pub fn rows(&self) -> &[GateRow] {
        &self.rows
    }

    /// 功能说明：返回当前行数。
    /// 输入：`self`。
    /// 输出：`usize`。
    /// 示例：`assert_eq!(circuit.num_rows(), 3);`
    pub fn num_rows(&self) -> usize {
        self.rows.len()
    }

    /// 功能说明：返回最近一次 `pad_to_domain()` 记录的 domain 大小。
    /// 输入：`self`。
    /// 输出：`Option<usize>`。
    /// 示例：`assert_eq!(circuit.domain_size(), Some(8));`
    pub fn domain_size(&self) -> Option<usize> {
        self.domain_size
    }

    /// 功能说明：返回电路是否已经进入 pad 后冻结状态。
    /// 输入：`self`。
    /// 输出：`bool`。
    /// 示例：`assert!(circuit.is_frozen());`
    pub fn is_frozen(&self) -> bool {
        self.is_frozen
    }

    /// 功能说明：按 Step 2.1 约定加入一整行 gate。
    /// 输入：一行 gate 的 witness 和 selector。
    /// 输出：成功返回 `Ok(())`，若电路已冻结则返回错误。
    /// 示例：`circuit.add_gate(a, b, c, q_l, q_r, q_o, q_m, q_c)?;`
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
    ) -> Result<()> {
        self.add_gate_with_tag(wire_a, wire_b, wire_c, q_l, q_r, q_o, q_m, q_c, None)
    }

    /// 功能说明：与 `add_gate` 相同，但允许附带调试标签。
    /// 输入：一行 gate 的 witness、selector 和可选标签。
    /// 输出：成功返回 `Ok(())`，若电路已冻结则返回错误。
    /// 示例：`circuit.add_gate_with_tag(..., Some("row 3".to_string()))?;`
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
    ) -> Result<()> {
        ensure(
            !self.is_frozen,
            "cannot add gate after pad_to_domain(); circuit is frozen",
        )?;

        self.rows.push(GateRow::new(
            wire_a, wire_b, wire_c, q_l, q_r, q_o, q_m, q_c, tag,
        ));
        self.domain_size = None;
        Ok(())
    }

    /// 功能说明：把行数补齐到当前行数的下一个 2^k，并冻结电路。
    /// 输入：`self`。
    /// 输出：无返回值；内部更新 `rows`、`domain_size` 和冻结状态。
    /// 示例：3 行电路调用后会补到 4 行，并禁止继续 `add_gate`。
    pub fn pad_to_domain(&mut self) {
        let current_rows = self.rows.len();
        let target_size = if current_rows == 0 {
            1
        } else {
            current_rows.next_power_of_two()
        };

        while self.rows.len() < target_size {
            self.rows.push(GateRow::zero_padding());
        }

        self.domain_size = Some(target_size);
        self.is_frozen = true;
    }

    /// 功能说明：计算指定行的 gate 约束值。
    /// 输入：行索引。
    /// 输出：该行约束左侧的域元素值。
    /// 示例：若该行满足约束，则返回 0。
    pub fn gate_constraint_value(&self, row_index: usize) -> Result<Fr> {
        ensure(row_index < self.rows.len(), "row index out of range")?;
        Ok(self.rows[row_index].constraint_value())
    }

    /// 功能说明：判断指定行是否满足 gate 约束。
    /// 输入：行索引。
    /// 输出：`bool`。
    /// 示例：`assert!(circuit.is_gate_satisfied(0)?);`
    pub fn is_gate_satisfied(&self, row_index: usize) -> Result<bool> {
        ensure(row_index < self.rows.len(), "row index out of range")?;
        Ok(self.rows[row_index].is_satisfied())
    }

    /// 功能说明：检查所有行是否都满足 gate 约束。
    /// 输入：`self`。
    /// 输出：`bool`。
    /// 示例：`assert!(circuit.are_all_gates_satisfied());`
    pub fn are_all_gates_satisfied(&self) -> bool {
        self.rows.iter().all(GateRow::is_satisfied)
    }

    /// 功能说明：返回第一个不满足约束的行索引，便于调试定位。
    /// 输入：`self`。
    /// 输出：`Option<usize>`。
    /// 示例：`assert_eq!(circuit.first_unsatisfied_row(), Some(5));`
    pub fn first_unsatisfied_row(&self) -> Option<usize> {
        self.rows
            .iter()
            .enumerate()
            .find_map(|(index, row)| (!row.is_satisfied()).then_some(index))
    }

    /// 功能说明：读取指定行的只读引用。
    /// 输入：行索引。
    /// 输出：`&GateRow`。
    /// 示例：`let row = circuit.row(0)?;`
    pub fn row(&self, row_index: usize) -> Result<&GateRow> {
        self.rows
            .get(row_index)
            .ok_or(PlonkError::InvalidInput("row index out of range"))
    }
}
