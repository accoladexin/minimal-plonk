//! Generic KZG polynomial commitment module (Step 6.1 / 6.2).
//!
//! This module intentionally stays independent from Plonk-specific logic.

pub mod batch;
pub mod commit;
pub mod open;
pub mod srs;
pub mod verify;

pub use batch::{KzgBatchOpening, open_polynomials_at_same_point, verify_polynomials_at_same_point};
pub use commit::commit_polynomial;
pub use open::{KzgOpening, KzgOpeningProof, open_polynomial_at_point};
pub use srs::KzgSrs;
pub use verify::verify_opening;
