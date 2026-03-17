//! Step 3.1：Witness 列与插值模块入口。
//! 这个模块就干了两件事情，提取 witness evaluations 和把 evaluations 插值成多项式（IFFT）。
//! 说明：
//! - `columns.rs` 负责从已 pad 的电路提取 a/b/c evaluations
//! - `interpolate.rs` 只负责 evaluations -> polynomial 的纯函数

pub mod columns;
pub mod interpolate;

pub use columns::WitnessColumns;
pub use interpolate::{
    WitnessPolynomials, interpolate_column_evaluations, interpolate_witness_column_polynomials,
};
