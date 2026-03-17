//! Step 5.1: quotient polynomial 模块入口。
//!
//! 当前只实现约束聚合与多项式除法，不涉及 commitment / transcript / pairing。

pub mod quotient;

pub use quotient::{
    ExtendedDomainQuotientComputation, HDomainConstraintEvaluations, QuotientChunkPolynomials,
    Step5_1QuotientOutput, blind_grand_product_polynomial, blind_witness_polynomial,
    build_extended_quotient_domain, build_h_vanishing_polynomial, build_linearization_polynomial,
    compute_blinded_quotient_polynomial, compute_extended_domain_quotient,
    compute_h_domain_constraint_evaluations, compute_step_5_1, evaluate_chunked_quotient,
    evaluate_public_input_polynomial_at_point, is_zero_polynomial, rerandomize_quotient_chunks,
    split_quotient_polynomial,
};
