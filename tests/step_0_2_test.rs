//! Step 0.2 acceptance tests.
//! - transcript determinism and sensitivity
//! - canonical serialization for shared protocol types

use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use minimal_plonk::{
    curve::{Fr, G1},
    transcript::Transcript,
    types::{
        Commitment, DomainParams, EvaluationsAtZeta, OpeningCommitments, PlonkConfig, PlonkProof,
        QuotientChunkCommitments, TranscriptHash,
    },
};

/// Builds a transcript with stable sample inputs.
fn sample_transcript(hash: TranscriptHash) -> Transcript {
    let mut transcript = Transcript::new(b"minimal-plonk-test", hash);
    transcript.append_bytes(b"instance", b"toy-circuit");
    transcript.append_scalar(b"alpha", &Fr::from(7u64));
    transcript.append_commitment(b"wire_a", &sample_commitment(1));
    transcript
}

/// Builds a deterministic commitment for tests.
fn sample_commitment(multiplier: u64) -> Commitment {
    let mut point = G1::generator();
    point *= Fr::from(multiplier);
    Commitment::from_projective(point)
}

/// Builds a minimal Phase 9 proof for round-trip tests.
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
            Fr::from(8u64),
            Fr::from(13u64),
            Fr::from(21u64),
            Fr::from(34u64),
            Fr::from(55u64),
        ),
        Fr::from(89u64),
    )
}

/// Same input must produce the same challenge.
#[test]
fn transcript_is_deterministic_for_same_input() {
    let mut left = sample_transcript(TranscriptHash::Blake2b);
    let mut right = sample_transcript(TranscriptHash::Blake2b);

    assert_eq!(
        left.challenge_scalar(b"beta"),
        right.challenge_scalar(b"beta")
    );
}

/// Any input change must change the derived challenge.
#[test]
fn transcript_challenge_changes_when_input_changes() {
    let mut original = sample_transcript(TranscriptHash::Blake2b);
    let mut modified = sample_transcript(TranscriptHash::Blake2b);
    modified.append_bytes(b"extra", b"changed");

    assert_ne!(
        original.challenge_scalar(b"beta"),
        modified.challenge_scalar(b"beta")
    );
}

/// The alternative SHA256 backend should still work end to end.
#[test]
fn transcript_supports_sha256_as_an_alternative_hash() {
    let mut transcript = sample_transcript(TranscriptHash::Sha256);
    let challenge = transcript.challenge_scalar(b"beta");

    assert_ne!(challenge, Fr::from(0u64));
}

/// Commitments must support canonical round-trip serialization.
#[test]
fn commitment_supports_canonical_round_trip() {
    let commitment = sample_commitment(9);
    let mut bytes = Vec::new();

    commitment
        .serialize_compressed(&mut bytes)
        .expect("serializing commitment should succeed");

    let decoded = Commitment::deserialize_compressed(bytes.as_slice())
        .expect("deserializing commitment should succeed");

    assert_eq!(commitment, decoded);
}

/// The frozen proof type must support canonical round-trip serialization.
#[test]
fn plonk_proof_supports_canonical_round_trip() {
    let proof = sample_proof();
    let mut bytes = Vec::new();

    proof
        .serialize_compressed(&mut bytes)
        .expect("serializing plonk proof should succeed");

    let decoded = PlonkProof::deserialize_compressed(bytes.as_slice())
        .expect("deserializing plonk proof should succeed");

    assert_eq!(proof, decoded);
}

/// Domain parameters and config must stay canonically serializable.
#[test]
fn config_and_domain_params_support_canonical_round_trip() {
    let domain = DomainParams::new(8, 3, Fr::from(5u64));
    let config = PlonkConfig::new(16, 3, TranscriptHash::Blake2b);

    let mut domain_bytes = Vec::new();
    domain
        .serialize_compressed(&mut domain_bytes)
        .expect("serializing domain params should succeed");
    let decoded_domain = DomainParams::deserialize_compressed(domain_bytes.as_slice())
        .expect("deserializing domain params should succeed");

    let mut config_bytes = Vec::new();
    config
        .serialize_compressed(&mut config_bytes)
        .expect("serializing config should succeed");
    let decoded_config = PlonkConfig::deserialize_compressed(config_bytes.as_slice())
        .expect("deserializing config should succeed");

    assert_eq!(domain, decoded_domain);
    assert_eq!(config, decoded_config);
}
