//! Fiat-Shamir transcript helpers.
//!
//! The generic append methods stay available as low-level primitives.
//! Step 7.1 adds fixed Plonk replay helpers so prover and verifier cannot
//! improvise labels or absorption order.

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest as BlakeDigest};
use sha2::Sha256;

use crate::{
    curve::Fr,
    types::{
        Commitment, EvaluationsAtZeta, PlonkProof, ShiftedEvaluations, TranscriptHash,
    },
};

const TAG_BYTES: u8 = 0;
const TAG_SCALAR: u8 = 1;
const TAG_COMMITMENT: u8 = 2;
const TAG_CHALLENGE: u8 = 3;

const WIRE_A_COMMITMENT_LABEL: &[u8] = b"wire_a_commitment";
const WIRE_B_COMMITMENT_LABEL: &[u8] = b"wire_b_commitment";
const WIRE_C_COMMITMENT_LABEL: &[u8] = b"wire_c_commitment";
const PUBLIC_INPUT_LABEL_PREFIX: &[u8] = b"public_input_";
const GRAND_PRODUCT_COMMITMENT_LABEL: &[u8] = b"grand_product_commitment";
const QUOTIENT_COMMITMENT_LABEL: &[u8] = b"quotient_commitment";

const A_EVAL_AT_ZETA_LABEL: &[u8] = b"a_eval_at_zeta";
const B_EVAL_AT_ZETA_LABEL: &[u8] = b"b_eval_at_zeta";
const C_EVAL_AT_ZETA_LABEL: &[u8] = b"c_eval_at_zeta";
const Z_EVAL_AT_ZETA_LABEL: &[u8] = b"grand_product_eval_at_zeta";
const T_EVAL_AT_ZETA_LABEL: &[u8] = b"quotient_eval_at_zeta";
const Z_SHIFTED_EVAL_LABEL: &[u8] = b"grand_product_eval_at_shifted_zeta";

const BETA_CHALLENGE_LABEL: &[u8] = b"beta";
const GAMMA_CHALLENGE_LABEL: &[u8] = b"gamma";
const ALPHA_CHALLENGE_LABEL: &[u8] = b"alpha";
const ZETA_CHALLENGE_LABEL: &[u8] = b"zeta";
const V_CHALLENGE_LABEL: &[u8] = b"v";

/// Challenges replayed from the fixed Step 7.1 transcript schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptChallenges {
    pub beta: Fr,
    pub gamma: Fr,
    pub alpha: Fr,
    pub zeta: Fr,
    pub v: Fr,
}

/// Minimal transcript state.
#[derive(Clone, Debug)]
pub struct Transcript {
    hash: TranscriptHash,
    state: Vec<u8>,
    challenge_counter: u64,
}

impl Transcript {
    /// Creates a transcript and writes the protocol-domain separator first.
    ///
    /// Input: protocol label and hash backend.
    /// Output: an empty transcript with the domain separator absorbed.
    /// Example: `Transcript::new(b"minimal-plonk", TranscriptHash::Blake2b)`.
    pub fn new(protocol_label: &[u8], hash: TranscriptHash) -> Self {
        let mut transcript = Self {
            hash,
            state: Vec::new(),
            challenge_counter: 0,
        };
        transcript.append_frame(TAG_BYTES, b"protocol", protocol_label);
        transcript
    }

    /// Absorbs raw bytes into the transcript.
    ///
    /// Input: an application label and byte payload.
    /// Output: updates transcript state in place.
    /// Example: `transcript.append_bytes(b"instance", instance_bytes)`.
    pub fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_frame(TAG_BYTES, label, bytes);
    }

    /// Absorbs one field element using canonical serialization.
    ///
    /// Input: an application label and one scalar.
    /// Output: updates transcript state in place.
    /// Example: `transcript.append_scalar(b"alpha", &scalar)`.
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Fr) {
        let scalar_bytes = serialize_to_bytes(scalar);
        self.append_frame(TAG_SCALAR, label, &scalar_bytes);
    }

    /// Absorbs one commitment using canonical serialization.
    ///
    /// Input: an application label and one commitment.
    /// Output: updates transcript state in place.
    /// Example: `transcript.append_commitment(b"wire_a", &commitment)`.
    pub fn append_commitment(&mut self, label: &[u8], commitment: &Commitment) {
        let commitment_bytes = serialize_to_bytes(commitment);
        self.append_frame(TAG_COMMITMENT, label, &commitment_bytes);
    }

    /// Derives one scalar challenge from the current state.
    ///
    /// Input: the fixed challenge label for the next round.
    /// Output: one field element challenge.
    /// Example: `let beta = transcript.challenge_scalar(b"beta");`.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Fr {
        let digest = self.hash_current_state(label);
        let challenge = Fr::from_le_bytes_mod_order(&digest);
        self.append_frame(TAG_CHALLENGE, label, &digest);
        self.challenge_counter += 1;
        challenge
    }

    /// Absorbs the fixed `[A, B, C]` wire commitments for Step 7.1.
    ///
    /// Input: the three wire commitments in canonical protocol order.
    /// Output: updates transcript state in place.
    /// Example: used immediately before deriving `beta` and `gamma`.
    pub fn absorb_plonk_wire_commitments(&mut self, wire_commitments: &[Commitment; 3]) {
        // Paper mapping: transcript state after Prover Round 1 commitments.
        self.append_commitment(WIRE_A_COMMITMENT_LABEL, &wire_commitments[0]);
        self.append_commitment(WIRE_B_COMMITMENT_LABEL, &wire_commitments[1]);
        self.append_commitment(WIRE_C_COMMITMENT_LABEL, &wire_commitments[2]);
    }

    /// 功能说明：按固定顺序吸收 Step 7.1 的 public inputs。
    ///
    /// 输入：按固定 statement 顺序排列的 `public_inputs` 切片；prover 当前会把同一份值写进 proof。
    /// 输出：把每个 public input 按固定标签和固定位置写入 transcript 状态。
    /// 示例：该方法应在 wire commitments 之后、`beta/gamma` 之前调用。
    pub fn absorb_plonk_public_inputs(&mut self, public_inputs: &[Fr]) {
        // Paper mapping: bind the statement before beta/gamma so all later rounds depend on it.
        for (index, public_input) in public_inputs.iter().enumerate() {
            let label = public_input_label(index);
            self.append_scalar(label.as_slice(), public_input);
        }
    }

    /// Absorbs the fixed grand-product commitment for Step 7.1.
    ///
    /// Input: the commitment to `Z(X)`.
    /// Output: updates transcript state in place.
    /// Example: used immediately before deriving `alpha`.
    pub fn absorb_plonk_grand_product_commitment(&mut self, commitment: &Commitment) {
        // Paper mapping: transcript transition into alpha after the Round 2 Z commitment.
        self.append_commitment(GRAND_PRODUCT_COMMITMENT_LABEL, commitment);
    }

    /// Absorbs the fixed quotient commitment for Step 7.1.
    ///
    /// Input: the commitment to `t(X)`.
    /// Output: updates transcript state in place.
    /// Example: used immediately before deriving `zeta`.
    pub fn absorb_plonk_quotient_commitment(&mut self, commitment: &Commitment) {
        // Paper mapping: transcript transition into zeta after the Round 3 T commitment.
        self.append_commitment(QUOTIENT_COMMITMENT_LABEL, commitment);
    }

    /// Absorbs the fixed claimed evaluations for Step 7.1.
    ///
    /// Input: all evaluations at `zeta` plus `Z(omega * zeta)`.
    /// Output: updates transcript state in place.
    /// Example: used immediately before deriving `v`.
    pub fn absorb_plonk_evaluations(
        &mut self,
        evaluations_at_zeta: &EvaluationsAtZeta,
        shifted_evaluations: &ShiftedEvaluations,
    ) {
        // Paper mapping: bind Round 4 claimed evaluations before deriving the batch challenge v.
        self.append_scalar(A_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.wire_a);
        self.append_scalar(B_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.wire_b);
        self.append_scalar(C_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.wire_c);
        self.append_scalar(Z_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.grand_product);
        self.append_scalar(T_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.quotient);
        self.append_scalar(
            Z_SHIFTED_EVAL_LABEL,
            &shifted_evaluations.grand_product_next,
        );
    }

    /// Replays the full fixed Step 7.1 transcript schedule for one proof.
    ///
    /// Input: one frozen Step 7.1 proof object.
    /// Output: the five replayed challenges.
    /// Example: prover and verifier should both call this with the same proof.
    pub fn replay_plonk_proof(&mut self, proof: &PlonkProof) -> TranscriptChallenges {
        // Paper mapping: full Fiat-Shamir replay beta/gamma -> alpha -> zeta -> v.
        self.absorb_plonk_wire_commitments(&proof.wire_commitments);
        self.absorb_plonk_public_inputs(&proof.public_inputs);
        let beta = self.challenge_scalar(BETA_CHALLENGE_LABEL);
        let gamma = self.challenge_scalar(GAMMA_CHALLENGE_LABEL);

        self.absorb_plonk_grand_product_commitment(&proof.grand_product_commitment);
        let alpha = self.challenge_scalar(ALPHA_CHALLENGE_LABEL);

        self.absorb_plonk_quotient_commitment(&proof.quotient_commitment);
        let zeta = self.challenge_scalar(ZETA_CHALLENGE_LABEL);

        self.absorb_plonk_evaluations(&proof.evaluations_at_zeta, &proof.shifted_evaluations);
        let v = self.challenge_scalar(V_CHALLENGE_LABEL);

        TranscriptChallenges {
            beta,
            gamma,
            alpha,
            zeta,
            v,
        }
    }

    /// Writes one framed payload into the transcript state.
    ///
    /// Input: tag, label, and payload bytes.
    /// Output: updates transcript state in place.
    /// Example: all public append helpers delegate to this method.
    fn append_frame(&mut self, tag: u8, label: &[u8], payload: &[u8]) {
        self.state.push(tag);
        self.state
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state
            .extend_from_slice(&(payload.len() as u64).to_le_bytes());
        self.state.extend_from_slice(payload);
    }

    /// Hashes the current transcript state for one labeled challenge.
    ///
    /// Input: the next challenge label.
    /// Output: the challenge digest bytes before field reduction.
    /// Example: called internally by `challenge_scalar`.
    fn hash_current_state(&self, label: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(self.state.len() + label.len() + 16);
        preimage.extend_from_slice(&self.state);
        preimage.extend_from_slice(&(label.len() as u64).to_le_bytes());
        preimage.extend_from_slice(label);
        preimage.extend_from_slice(&self.challenge_counter.to_le_bytes());

        match self.hash {
            TranscriptHash::Blake2b => Blake2b512::digest(preimage).to_vec(),
            TranscriptHash::Sha256 => Sha256::digest(preimage).to_vec(),
        }
    }
}

impl Default for Transcript {
    /// Builds the default transcript used by the current tests.
    fn default() -> Self {
        Self::new(b"minimal-plonk", TranscriptHash::default())
    }
}

/// Serializes any canonical object into stable bytes.
///
/// Input: one value that supports arkworks canonical serialization.
/// Output: the canonical compressed byte encoding.
/// Example: used for transcript absorption of scalars and commitments.
fn serialize_to_bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    // Paper mapping: canonical bytes are part of the transcript contract between prover and verifier.
    let mut bytes = Vec::with_capacity(value.serialized_size(ark_serialize::Compress::Yes));
    value
        .serialize_compressed(&mut bytes)
        .expect("serializing into a Vec<u8> should not fail");
    bytes
}

/// 功能说明：为第 `index` 个 public input 生成固定且可审计的 transcript 标签。
///
/// 输入：public input 在 proof 中的固定位置索引。
/// 输出：一个形如 `public_input_0` 的稳定标签字节串。
/// 示例：`public_input_label(2)` 会返回 `b"public_input_2"`。
fn public_input_label(index: usize) -> Vec<u8> {
    let mut label = PUBLIC_INPUT_LABEL_PREFIX.to_vec();
    label.extend_from_slice(index.to_string().as_bytes());
    label
}
