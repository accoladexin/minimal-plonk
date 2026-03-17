//! Step 4.1：wire 位置与唯一 ID 编码。
// 把一个二维的“电路表格”，拍平成一个一维的“ID 列表”
use crate::{
    error::{PlonkError, Result},
    validate::ensure,
};

/// 三列 witness 的列标识。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Column {
    A,
    B,
    C,
}

impl Column {
    /// 功能说明：返回列对应的固定索引（A=0, B=1, C=2）。
    /// 输入：`self`（列枚举）。
    /// 输出：`usize` 列索引。
    /// 示例：`Column::B.index()` 返回 `1`。
    pub fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
            Self::C => 2,
        }
    }
}

/// 一个 wire 位置：`(col, row)`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos {
    pub col: Column, // 列标识
    pub row: usize,  // 行索引
}

/// Step 4.1 使用的 wire 唯一 ID 类型。
pub type WireId = usize;

/// 功能说明：把 `Pos=(col,row)` 编码成唯一 ID，规则为 `id = col_index * n + row`。
/// 输入：`pos`（位置）、`domain_size=n`。
/// 输出：`Result<WireId>`，成功时返回范围在 `[0, 3n)` 的 ID。
/// 示例：`n=8, Pos{col:B,row:3}` 返回 `11`。
pub fn pos_to_wire_id(pos: Pos, domain_size: usize) -> Result<WireId> {
    ensure(domain_size > 0, "domain_size must be positive")?;
    ensure(pos.row < domain_size, "position row out of domain range")?;

    let base = pos.col.index() * domain_size;
    base.checked_add(pos.row)
        .ok_or(PlonkError::InvalidInput("wire id overflow"))
}
