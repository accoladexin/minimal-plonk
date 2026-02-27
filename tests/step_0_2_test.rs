//! Step 0.2 验收测试：
//! - transcript 的确定性与敏感性
//! - 公共类型的 canonical serialize / deserialize

use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use minimal_plonk::{
    curve::{Fr, G1},
    transcript::Transcript,
    types::{Commitment, DomainParams, PlonkConfig, ProofSkeleton, TranscriptHash},
};

/// 构造一份固定输入的 transcript，方便多个测试复用。
fn sample_transcript(hash: TranscriptHash) -> Transcript {
    let mut transcript = Transcript::new(b"minimal-plonk-test", hash);
    transcript.append_bytes(b"instance", b"toy-circuit");
    transcript.append_scalar(b"alpha", &Fr::from(7u64));
    transcript.append_commitment(b"wire_a", &sample_commitment());
    transcript
}

/// 构造一个稳定的测试承诺。
fn sample_commitment() -> Commitment {
    Commitment::from_projective(G1::generator())
}

/// 构造一份最小 proof skeleton，专门用于 round-trip 测试。
fn sample_proof() -> ProofSkeleton {
    ProofSkeleton {
        wire_commitments: vec![sample_commitment()],
        quotient_commitment: Some(sample_commitment()),
        grand_product_commitment: Some(sample_commitment()),
        opening_proof: Some(sample_commitment()),
        public_inputs: vec![Fr::from(3u64), Fr::from(5u64)],
        evaluations: vec![Fr::from(8u64), Fr::from(13u64)],
    }
}

/// 同样输入必须导出同样 challenge。
#[test]
fn transcript_is_deterministic_for_same_input() {
    let mut left = sample_transcript(TranscriptHash::Blake2b);
    let mut right = sample_transcript(TranscriptHash::Blake2b);

    assert_eq!(
        left.challenge_scalar(b"beta"),
        right.challenge_scalar(b"beta")
    );
}

/// 只要输入变化，challenge 就必须变化。
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

/// 不同哈希配置应当走通同一套流程。
#[test]
fn transcript_supports_sha256_as_an_alternative_hash() {
    let mut transcript = sample_transcript(TranscriptHash::Sha256);
    let challenge = transcript.challenge_scalar(b"beta");

    assert_ne!(challenge, Fr::from(0u64));
}

/// 单个 Commitment 必须能稳定 round-trip。
#[test]
fn commitment_supports_canonical_round_trip() {
    let commitment = sample_commitment();
    let mut bytes = Vec::new();

    commitment
        .serialize_compressed(&mut bytes)
        .expect("serializing commitment should succeed");

    let decoded = Commitment::deserialize_compressed(bytes.as_slice())
        .expect("deserializing commitment should succeed");

    assert_eq!(commitment, decoded);
}

/// ProofSkeleton 必须能稳定 round-trip。
#[test]
fn proof_skeleton_supports_canonical_round_trip() {
    let proof = sample_proof();
    let mut bytes = Vec::new();

    proof
        .serialize_compressed(&mut bytes)
        .expect("serializing proof skeleton should succeed");

    let decoded = ProofSkeleton::deserialize_compressed(bytes.as_slice())
        .expect("deserializing proof skeleton should succeed");

    assert_eq!(proof, decoded);
}

/// DomainParams 与 PlonkConfig 也应具有稳定序列化行为。
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
