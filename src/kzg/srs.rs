//! Step 6.1: SRS for generic KZG commitment.

use ark_ec::{CurveGroup, Group};
use ark_std::UniformRand;
use rand::thread_rng;

use crate::{
    curve::{Fr, G1, G1Affine, G2, G2Affine},
    error::Result,
    validate::ensure,
};

/// KZG structured reference string.
///
/// `g1_powers[i] = [tau^i]_1`
/// `g2_powers[0] = [1]_2`, `g2_powers[1] = [tau]_2`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgSrs {
    pub g1_powers: Vec<G1Affine>,
    pub g2_powers: Vec<G2Affine>,
}

impl KzgSrs {
    /// Function: build a development SRS up to `max_degree`.
    /// Input: maximum polynomial degree supported by this SRS.
    /// Output: `KzgSrs` with `max_degree + 1` G1 powers and 2 G2 powers.
    /// Example: `KzgSrs::setup_for_testing(16)?`.
    pub fn setup_for_testing(max_degree: usize) -> Result<Self> {
        //生成随机数
        let mut rng = thread_rng();
        let tau = Fr::rand(&mut rng);

        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_power = Fr::from(1u64);
        let g1_generator = G1::generator();
        // 计算 [tau^i]_1 直到 i = max_degree。
        for _ in 0..=max_degree {
            g1_powers.push((g1_generator * tau_power).into_affine());
            tau_power *= tau;
        }

        let g2_generator = G2::generator();
        let g2_powers = vec![
            g2_generator.into_affine(),
            (g2_generator * tau).into_affine(),
        ];

        let srs = Self {
            g1_powers,
            g2_powers,
        };
        srs.validate_shape()?;
        Ok(srs)
    }

    /// Function: return the largest supported polynomial degree.
    /// Input: none.
    /// Output: max degree supported by this SRS.
    /// Example: if `g1_powers.len() == 9`, returns `8`.
    pub fn max_degree(&self) -> usize {
        self.g1_powers.len().saturating_sub(1)
    }

    /// Function: validate internal SRS vector shape.
    /// Input: none.
    /// Output: `Ok(())` if shape is valid, otherwise an error.
    /// Example: rejects empty `g1_powers` or non-2-length `g2_powers`.
    pub fn validate_shape(&self) -> Result<()> {
        ensure(!self.g1_powers.is_empty(), "kzg srs g1_powers must be non-empty")?;
        ensure(
            self.g2_powers.len() == 2,
            "kzg srs g2_powers must contain [1]_2 and [tau]_2",
        )?;
        Ok(())
    }

    /// Function: enforce degree bound against this SRS.
    /// Input: polynomial degree.
    /// Output: `Ok(())` if `degree <= max_degree`, otherwise an error.
    /// Example: degree 17 fails when `max_degree()` is 16.
    pub fn validate_polynomial_degree(&self, degree: usize) -> Result<()> {
        self.validate_shape()?;
        ensure(
            degree <= self.max_degree(),
            "polynomial degree exceeds kzg srs max_degree",
        )?;
        Ok(())
    }
}
