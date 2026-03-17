//! Step 7.1 acceptance tests for transcript integration.

use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use minimal_plonk::{
    curve::{Fr, G1},
    transcript::{Phase9TranscriptChallenges, Transcript},
    types::{
        Commitment, DomainParams, EvaluationsAtZeta, OpeningCommitments, PlonkProof,
        QuotientChunkCommitments, ShiftedEvaluations, TranscriptPreprocessedInput,
        VerifierProtocolParams,
    },
};

/// Builds a deterministic commitment for transcript tests.
fn sample_commitment(multiplier: u64) -> Commitment {
    let mut point = G1::generator();
    point *= Fr::from(multiplier);
    Commitment::from_projective(point)
}

/// Builds a fixed preprocessed input used by transcript replay.
fn sample_preprocessed_input() -> TranscriptPreprocessedInput {
    TranscriptPreprocessedInput::new(
        DomainParams::new(8, 3, Fr::from(5u64)),
        [
            sample_commitment(101),
            sample_commitment(102),
            sample_commitment(103),
            sample_commitment(104),
            sample_commitment(105),
        ],
        [
            sample_commitment(201),
            sample_commitment(202),
            sample_commitment(203),
        ],
        VerifierProtocolParams::new(3, [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]),
    )
}

/// Builds a frozen Phase 9 proof with distinct values in every transcript slot.
fn sample_proof() -> PlonkProof {
    PlonkProof::new(
        [
            sample_commitment(1),
            sample_commitment(2),
            sample_commitment(3),
        ],
        sample_commitment(4),
        QuotientChunkCommitments::new(
            sample_commitment(5),
            sample_commitment(6),
            sample_commitment(7),
        ),
        OpeningCommitments::new(sample_commitment(8), sample_commitment(9)),
        EvaluationsAtZeta::new(
            Fr::from(17u64),
            Fr::from(19u64),
            Fr::from(23u64),
            Fr::from(29u64),
            Fr::from(31u64),
        ),
        ShiftedEvaluations::new(Fr::from(37u64)),
    )
}

/// Replays the fixed Phase 9 schedule through the convenience API.
fn replay_as_verifier(
    proof: &PlonkProof,
    public_inputs: &[Fr],
    preprocessed_input: &TranscriptPreprocessedInput,
) -> Phase9TranscriptChallenges {
    let mut transcript = Transcript::default();
    transcript.replay_phase_9_proof(proof, public_inputs, preprocessed_input)
}

/// Replays the fixed Phase 9 schedule round by round.
fn replay_as_prover(
    proof: &PlonkProof,
    public_inputs: &[Fr],
    preprocessed_input: &TranscriptPreprocessedInput,
) -> Phase9TranscriptChallenges {
    let mut transcript = Transcript::default();
    transcript.absorb_phase_9_preprocessed_input(preprocessed_input);
    transcript.absorb_plonk_public_inputs(public_inputs);
    transcript.absorb_plonk_wire_commitments(&proof.wire_commitments);
    let beta = transcript.challenge_scalar(b"beta");
    let gamma = transcript.challenge_scalar(b"gamma");

    transcript.absorb_plonk_grand_product_commitment(&proof.grand_product_commitment);
    let alpha = transcript.challenge_scalar(b"alpha");

    transcript.absorb_phase_9_quotient_chunk_commitments(&proof.quotient_chunk_commitments);
    let zeta = transcript.challenge_scalar(b"zeta");

    transcript.absorb_phase_9_evaluations(&proof.evaluations_at_zeta, &proof.shifted_evaluations);
    let v = transcript.challenge_scalar(b"v");

    transcript.absorb_phase_9_opening_commitments(&proof.opening_commitments);
    let u = transcript.challenge_scalar(b"u");

    Phase9TranscriptChallenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    }
}

/// Replays the transcript with the evaluation absorption order intentionally broken.
fn replay_with_wrong_evaluation_order(
    proof: &PlonkProof,
    public_inputs: &[Fr],
    preprocessed_input: &TranscriptPreprocessedInput,
) -> Fr {
    let mut transcript = Transcript::default();
    transcript.absorb_phase_9_preprocessed_input(preprocessed_input);
    transcript.absorb_plonk_public_inputs(public_inputs);
    transcript.absorb_plonk_wire_commitments(&proof.wire_commitments);
    let _beta = transcript.challenge_scalar(b"beta");
    let _gamma = transcript.challenge_scalar(b"gamma");

    transcript.absorb_plonk_grand_product_commitment(&proof.grand_product_commitment);
    let _alpha = transcript.challenge_scalar(b"alpha");

    transcript.absorb_phase_9_quotient_chunk_commitments(&proof.quotient_chunk_commitments);
    let _zeta = transcript.challenge_scalar(b"zeta");

    transcript.append_scalar(b"b_eval_at_zeta", &proof.evaluations_at_zeta.wire_b);
    transcript.append_scalar(b"a_eval_at_zeta", &proof.evaluations_at_zeta.wire_a);
    transcript.append_scalar(b"c_eval_at_zeta", &proof.evaluations_at_zeta.wire_c);
    transcript.append_scalar(b"s_sigma1_eval_at_zeta", &proof.evaluations_at_zeta.sigma_1);
    transcript.append_scalar(b"s_sigma2_eval_at_zeta", &proof.evaluations_at_zeta.sigma_2);
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
    let public_inputs = vec![Fr::from(11u64), Fr::from(13u64)];
    let preprocessed_input = sample_preprocessed_input();

    assert_eq!(
        replay_as_verifier(&proof, &public_inputs, &preprocessed_input),
        replay_as_verifier(&proof, &public_inputs, &preprocessed_input)
    );
}

/// Changing the commitment order must change the commitment-derived challenges.
#[test]
fn transcript_challenges_change_when_commitment_order_changes() {
    let original = sample_proof();
    let mut reordered = sample_proof();
    let public_inputs = vec![Fr::from(11u64), Fr::from(13u64)];
    let preprocessed_input = sample_preprocessed_input();
    reordered.wire_commitments.swap(0, 1);

    let original_challenges = replay_as_verifier(&original, &public_inputs, &preprocessed_input);
    let reordered_challenges = replay_as_verifier(&reordered, &public_inputs, &preprocessed_input);

    assert_ne!(original_challenges.beta, reordered_challenges.beta);
    assert_ne!(original_challenges.gamma, reordered_challenges.gamma);
}

/// Changing only the external public inputs must change the early challenges.
#[test]
fn transcript_challenges_change_when_public_inputs_change() {
    let proof = sample_proof();
    let preprocessed_input = sample_preprocessed_input();
    let original_public_inputs = vec![Fr::from(11u64), Fr::from(13u64)];
    let changed_public_inputs = vec![Fr::from(12u64), Fr::from(13u64)];

    let original_challenges =
        replay_as_verifier(&proof, &original_public_inputs, &preprocessed_input);
    let changed_challenges =
        replay_as_verifier(&proof, &changed_public_inputs, &preprocessed_input);

    assert_ne!(original_challenges.beta, changed_challenges.beta);
    assert_ne!(original_challenges.gamma, changed_challenges.gamma);
}

/// Changing the evaluation absorption order must change `v`.
#[test]
fn transcript_v_changes_when_evaluation_order_changes() {
    let proof = sample_proof();
    let public_inputs = vec![Fr::from(11u64), Fr::from(13u64)];
    let preprocessed_input = sample_preprocessed_input();
    let correct_v = replay_as_verifier(&proof, &public_inputs, &preprocessed_input).v;
    let wrong_v = replay_with_wrong_evaluation_order(&proof, &public_inputs, &preprocessed_input);

    assert_ne!(correct_v, wrong_v);
}

/// Proof round-trip serialization must preserve transcript replay.
#[test]
fn transcript_replay_is_stable_after_proof_round_trip() {
    let proof = sample_proof();
    let public_inputs = vec![Fr::from(11u64), Fr::from(13u64)];
    let preprocessed_input = sample_preprocessed_input();
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("serializing proof should succeed");

    let decoded = PlonkProof::deserialize_compressed(bytes.as_slice())
        .expect("deserializing proof should succeed");

    assert_eq!(
        replay_as_verifier(&proof, &public_inputs, &preprocessed_input),
        replay_as_verifier(&decoded, &public_inputs, &preprocessed_input)
    );
}

/// Prover-side round replay and verifier-side proof replay must match exactly.
#[test]
fn prover_and_verifier_replay_the_same_challenges() {
    let proof = sample_proof();
    let public_inputs = vec![Fr::from(11u64), Fr::from(13u64)];
    let preprocessed_input = sample_preprocessed_input();

    assert_eq!(
        replay_as_prover(&proof, &public_inputs, &preprocessed_input),
        replay_as_verifier(&proof, &public_inputs, &preprocessed_input)
    );
}
