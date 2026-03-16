//! Step 7.1 acceptance tests for transcript integration.

use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use minimal_plonk::{
    curve::{Fr, G1},
    transcript::{Transcript, TranscriptChallenges},
    types::{Commitment, EvaluationsAtZeta, OpeningProof, PlonkProof, ShiftedEvaluations},
};

/// Builds a deterministic commitment for transcript tests.
fn sample_commitment(multiplier: u64) -> Commitment {
    let mut point = G1::generator();
    point *= Fr::from(multiplier);
    Commitment::from_projective(point)
}

/// Builds a frozen Step 7.1 proof with distinct values in every transcript slot.
fn sample_proof() -> PlonkProof {
    PlonkProof::new(
        [
            sample_commitment(1),
            sample_commitment(2),
            sample_commitment(3),
        ],
        sample_commitment(4),
        sample_commitment(5),
        vec![Fr::from(11u64), Fr::from(13u64)],
        EvaluationsAtZeta::new(
            Fr::from(17u64),
            Fr::from(19u64),
            Fr::from(23u64),
            Fr::from(29u64),
            Fr::from(31u64),
        ),
        ShiftedEvaluations::new(Fr::from(37u64)),
        OpeningProof::new(sample_commitment(6)),
        OpeningProof::new(sample_commitment(7)),
    )
}

/// Replays the fixed Step 7.1 schedule through the convenience API.
fn replay_as_verifier(proof: &PlonkProof) -> TranscriptChallenges {
    let mut transcript = Transcript::default();
    transcript.replay_plonk_proof(proof)
}

/// Replays the fixed Step 7.1 schedule round by round.
fn replay_as_prover(proof: &PlonkProof) -> TranscriptChallenges {
    let mut transcript = Transcript::default();
    transcript.absorb_plonk_wire_commitments(&proof.wire_commitments);
    transcript.absorb_plonk_public_inputs(&proof.public_inputs);
    let beta = transcript.challenge_scalar(b"beta");
    let gamma = transcript.challenge_scalar(b"gamma");

    transcript.absorb_plonk_grand_product_commitment(&proof.grand_product_commitment);
    let alpha = transcript.challenge_scalar(b"alpha");

    transcript.absorb_plonk_quotient_commitment(&proof.quotient_commitment);
    let zeta = transcript.challenge_scalar(b"zeta");

    transcript.absorb_plonk_evaluations(&proof.evaluations_at_zeta, &proof.shifted_evaluations);
    let v = transcript.challenge_scalar(b"v");

    TranscriptChallenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
    }
}

/// Replays the transcript with the evaluation absorption order intentionally broken.
fn replay_with_wrong_evaluation_order(proof: &PlonkProof) -> Fr {
    let mut transcript = Transcript::default();
    transcript.absorb_plonk_wire_commitments(&proof.wire_commitments);
    let _beta = transcript.challenge_scalar(b"beta");
    let _gamma = transcript.challenge_scalar(b"gamma");

    transcript.absorb_plonk_grand_product_commitment(&proof.grand_product_commitment);
    let _alpha = transcript.challenge_scalar(b"alpha");

    transcript.absorb_plonk_quotient_commitment(&proof.quotient_commitment);
    let _zeta = transcript.challenge_scalar(b"zeta");

    transcript.append_scalar(b"b_eval_at_zeta", &proof.evaluations_at_zeta.wire_b);
    transcript.append_scalar(b"a_eval_at_zeta", &proof.evaluations_at_zeta.wire_a);
    transcript.append_scalar(b"c_eval_at_zeta", &proof.evaluations_at_zeta.wire_c);
    transcript.append_scalar(
        b"grand_product_eval_at_zeta",
        &proof.evaluations_at_zeta.grand_product,
    );
    transcript.append_scalar(
        b"quotient_eval_at_zeta",
        &proof.evaluations_at_zeta.quotient,
    );
    transcript.append_scalar(
        b"grand_product_eval_at_shifted_zeta",
        &proof.shifted_evaluations.grand_product_next,
    );

    transcript.challenge_scalar(b"v")
}

/// Same proof input must replay to the same challenge sequence.
#[test]
fn transcript_replay_is_deterministic_for_same_proof() {
    let proof = sample_proof();

    assert_eq!(replay_as_verifier(&proof), replay_as_verifier(&proof));
}

/// Changing the commitment order must change the commitment-derived challenges.
#[test]
fn transcript_challenges_change_when_commitment_order_changes() {
    let original = sample_proof();
    let mut reordered = sample_proof();
    reordered.wire_commitments.swap(0, 1);

    let original_challenges = replay_as_verifier(&original);
    let reordered_challenges = replay_as_verifier(&reordered);

    assert_ne!(original_challenges.beta, reordered_challenges.beta);
    assert_ne!(original_challenges.gamma, reordered_challenges.gamma);
}

/// Changing only the public inputs must change the early challenges.
#[test]
fn transcript_challenges_change_when_public_inputs_change() {
    let original = sample_proof();
    let mut changed = sample_proof();
    changed.public_inputs[0] += Fr::from(1u64);

    let original_challenges = replay_as_verifier(&original);
    let changed_challenges = replay_as_verifier(&changed);

    assert_ne!(original_challenges.beta, changed_challenges.beta);
    assert_ne!(original_challenges.gamma, changed_challenges.gamma);
}

/// Changing the evaluation absorption order must change `v`.
#[test]
fn transcript_v_changes_when_evaluation_order_changes() {
    let proof = sample_proof();
    let correct_v = replay_as_verifier(&proof).v;
    let wrong_v = replay_with_wrong_evaluation_order(&proof);

    assert_ne!(correct_v, wrong_v);
}

/// Proof round-trip serialization must preserve transcript replay.
#[test]
fn transcript_replay_is_stable_after_proof_round_trip() {
    let proof = sample_proof();
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("serializing proof should succeed");

    let decoded = PlonkProof::deserialize_compressed(bytes.as_slice())
        .expect("deserializing proof should succeed");

    assert_eq!(replay_as_verifier(&proof), replay_as_verifier(&decoded));
}

/// Prover-side round replay and verifier-side proof replay must match exactly.
#[test]
fn prover_and_verifier_replay_the_same_challenges() {
    let proof = sample_proof();

    assert_eq!(replay_as_prover(&proof), replay_as_verifier(&proof));
}
