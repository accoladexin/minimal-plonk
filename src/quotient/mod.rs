//! Step 5.1: quotient polynomial 模块入口。
//!
//! 当前只实现约束聚合与多项式除法，不涉及 commitment / transcript / pairing。

pub mod quotient;

pub use quotient::{
    ExtendedDomainQuotientComputation, HDomainConstraintEvaluations, Step5_1QuotientOutput,
    build_extended_quotient_domain, build_h_vanishing_polynomial,
    compute_extended_domain_quotient, compute_h_domain_constraint_evaluations, compute_step_5_1,
    is_zero_polynomial,
};
