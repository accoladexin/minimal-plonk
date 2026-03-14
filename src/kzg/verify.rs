//! Step 6.2: explicit pairing verification for KZG opening.

use ark_ec::{AffineRepr, CurveGroup, Group, pairing::Pairing};

use crate::{
    curve::{Curve, Fr, G1},
    error::Result,
    kzg::{open::KzgOpeningProof, srs::KzgSrs},
    types::Commitment,
};

/// Function: verify one KZG opening at one point.
/// Input: commitment, point, claimed value, proof, and SRS.
/// Output: `true` if verification succeeds, otherwise `false`.
/// Example: `verify_opening(&commitment, z, value, &proof, &srs)?`.
pub fn verify_opening(
    commitment: &Commitment,
    point: Fr,
    value: Fr,
    proof: &KzgOpeningProof,
    srs: &KzgSrs,
) -> Result<bool> {
    srs.validate_shape()?;

    let g2_generator = srs.g2_powers[0];
    let tau_g2 = srs.g2_powers[1];

    let left_g1 = commitment.point.into_group() - (G1::generator() * value);
    let right_g2 = tau_g2.into_group() - (g2_generator.into_group() * point);

    // Explicit KZG pairing equation:
    // e(C - y*G1, G2) == e(pi, tau*G2 - z*G2)
    let left_pairing = Curve::pairing(left_g1.into_affine(), g2_generator);
    let right_pairing = Curve::pairing(proof.witness_commitment.point, right_g2.into_affine());

    Ok(left_pairing == right_pairing)
}
