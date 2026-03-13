//! Step 4.1：Permutation（sigma）模块入口。
//!
//! 说明：
//! - `position.rs` 负责位置与 ID 编码
//! - `sigma.rs` 负责 copy 约束到 sigma 映射的构造与校验

pub mod position;
pub mod sigma;
pub mod grand_product;

pub use grand_product::{
    compute_grand_product_evaluations, compute_row_terms_for_quotient,
    interpolate_grand_product_evaluations, verify_grand_product_boundary,
    verify_grand_product_recurrence, verify_single_grand_product_step, GrandProductEvaluations, K1,
    K2,
};
pub use position::{pos_to_wire_id, Column, Pos, WireId};
pub use sigma::{
    build_sigma_from_copy_constraints, validate_sigma_bijection, CopyConstraint, SigmaMapping,
};
