//! Shared protocol data types.
//!
//! This module only hosts shared definitions that are already needed by the
//! current implementation steps.

mod config;
mod proof;
mod quotient_input;
mod verifier_input;

pub use config::{DomainParams, PlonkConfig, TranscriptHash};
pub use proof::{
    Commitment, EvaluationsAtZeta, OpeningProof, PlonkProof, ProofSkeleton, ShiftedEvaluations,
};
pub use quotient_input::QuotientInputs;
pub use verifier_input::{
    SelectorPolynomials, SigmaTagPolynomials, VerifierPreprocessedInput,
    VerifierProtocolParams,
};
