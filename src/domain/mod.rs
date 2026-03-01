//! Step 1.1：FFT domain 与 Lagrange 工具模块入口。
//!
//! 这个模块只负责“域与多项式基础工具”，不涉及电路、KZG 或 transcript。

pub mod fft;
pub mod lagrange;
pub mod radix2_domain;
pub mod vanishing;

pub use fft::{evaluations_to_polynomial, fft, ifft, polynomial_to_evaluations};
pub use lagrange::{lagrange_basis_value, lagrange_values_at_point};
pub use radix2_domain::{build_domain_from_log_size, build_domain_from_size, domain_params, PlonkDomain};
pub use vanishing::vanishing_value;
