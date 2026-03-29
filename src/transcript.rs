//! Fiat-Shamir transcript helpers.
//!
//! The generic append methods stay available as low-level primitives.
//! This module exposes the frozen Phase 9 replay helper used by Step 9.3 prover
//! and Step 9.4 verifier.

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest as BlakeDigest};
use sha2::Sha256;

use crate::{
    curve::Fr,
    types::{
        Commitment, EvaluationsAtZeta, OpeningCommitments, PlonkProof, QuotientChunkCommitments,
        TranscriptHash, TranscriptPreprocessedInput,
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
const T_LO_COMMITMENT_LABEL: &[u8] = b"t_lo_commitment";
const T_MID_COMMITMENT_LABEL: &[u8] = b"t_mid_commitment";
const T_HI_COMMITMENT_LABEL: &[u8] = b"t_hi_commitment";
const W_Z_COMMITMENT_LABEL: &[u8] = b"w_z_commitment";
const W_Z_OMEGA_COMMITMENT_LABEL: &[u8] = b"w_z_omega_commitment";

const DOMAIN_LABEL: &[u8] = b"domain_params";
const Q_M_COMMITMENT_LABEL: &[u8] = b"q_m_commitment";
const Q_L_COMMITMENT_LABEL: &[u8] = b"q_l_commitment";
const Q_R_COMMITMENT_LABEL: &[u8] = b"q_r_commitment";
const Q_O_COMMITMENT_LABEL: &[u8] = b"q_o_commitment";
const Q_C_COMMITMENT_LABEL: &[u8] = b"q_c_commitment";
const SIGMA_1_COMMITMENT_LABEL: &[u8] = b"s_sigma1_commitment";
const SIGMA_2_COMMITMENT_LABEL: &[u8] = b"s_sigma2_commitment";
const SIGMA_3_COMMITMENT_LABEL: &[u8] = b"s_sigma3_commitment";
const K1_LABEL: &[u8] = b"k1";
const K2_LABEL: &[u8] = b"k2";
const NUM_WIRE_COLUMNS_LABEL: &[u8] = b"num_wire_columns";

const A_EVAL_AT_ZETA_LABEL: &[u8] = b"a_eval_at_zeta";
const B_EVAL_AT_ZETA_LABEL: &[u8] = b"b_eval_at_zeta";
const C_EVAL_AT_ZETA_LABEL: &[u8] = b"c_eval_at_zeta";
const S_SIGMA1_EVAL_AT_ZETA_LABEL: &[u8] = b"s_sigma1_eval_at_zeta";
const S_SIGMA2_EVAL_AT_ZETA_LABEL: &[u8] = b"s_sigma2_eval_at_zeta";
const Z_SHIFTED_EVAL_LABEL: &[u8] = b"grand_product_eval_at_shifted_zeta";

const BETA_CHALLENGE_LABEL: &[u8] = b"beta";
const GAMMA_CHALLENGE_LABEL: &[u8] = b"gamma";
const ALPHA_CHALLENGE_LABEL: &[u8] = b"alpha";
const ZETA_CHALLENGE_LABEL: &[u8] = b"zeta";
const V_CHALLENGE_LABEL: &[u8] = b"v";
const U_CHALLENGE_LABEL: &[u8] = b"u";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase9TranscriptChallenges {
    pub beta: Fr,
    pub gamma: Fr,
    pub alpha: Fr,
    pub zeta: Fr,
    pub v: Fr,
    pub u: Fr,
}

/// Minimal transcript state.
#[derive(Clone, Debug)]
pub struct Transcript {
    hash: TranscriptHash,
    state: Vec<u8>,
    challenge_counter: u64,
}

impl Transcript {
    /// Create a transcript and absorb the protocol separator first.
    pub fn new(protocol_label: &[u8], hash: TranscriptHash) -> Self {
        let mut transcript = Self {
            hash,
            state: Vec::new(),
            challenge_counter: 0,
        };
        transcript.append_frame(TAG_BYTES, b"protocol", protocol_label);
        transcript
    }

    /// Absorb raw bytes under a fixed label.
    pub fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_frame(TAG_BYTES, label, bytes);
    }

    /// Absorb one field element under a fixed label.
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Fr) {
        let scalar_bytes = serialize_to_bytes(scalar);
        self.append_frame(TAG_SCALAR, label, &scalar_bytes);
    }

    /// Absorb one commitment under a fixed label.
    pub fn append_commitment(&mut self, label: &[u8], commitment: &Commitment) {
        let commitment_bytes = serialize_to_bytes(commitment);
        self.append_frame(TAG_COMMITMENT, label, &commitment_bytes);
    }

    /// Derive one challenge from the current transcript state.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Fr {
        let digest = self.hash_current_state(label);
        let challenge = Fr::from_le_bytes_mod_order(&digest);
        self.append_frame(TAG_CHALLENGE, label, &digest);
        self.challenge_counter += 1;
        challenge
    }

    /// Absorb the fixed-order witness commitments `[A, B, C]`.
    pub fn absorb_plonk_wire_commitments(&mut self, wire_commitments: &[Commitment; 3]) {
        self.append_commitment(WIRE_A_COMMITMENT_LABEL, &wire_commitments[0]);
        self.append_commitment(WIRE_B_COMMITMENT_LABEL, &wire_commitments[1]);
        self.append_commitment(WIRE_C_COMMITMENT_LABEL, &wire_commitments[2]);
    }

    /// Absorb public inputs in statement order.
    pub fn absorb_plonk_public_inputs(&mut self, public_inputs: &[Fr]) {
        for (index, public_input) in public_inputs.iter().enumerate() {
            let label = public_input_label(index);
            self.append_scalar(label.as_slice(), public_input);
        }
    }

    /// Absorb the grand-product commitment `[Z]`.
    pub fn absorb_plonk_grand_product_commitment(&mut self, commitment: &Commitment) {
        self.append_commitment(GRAND_PRODUCT_COMMITMENT_LABEL, commitment);
    }

    /// Absorb the commitments-based fixed input frozen by Phase 9.
    pub fn absorb_phase_9_preprocessed_input(
        &mut self,
        preprocessed_input: &TranscriptPreprocessedInput,
    ) {
        self.append_bytes(DOMAIN_LABEL, &serialize_to_bytes(&preprocessed_input.domain));
        self.append_commitment(Q_M_COMMITMENT_LABEL, &preprocessed_input.selector_commitments[0]);
        self.append_commitment(Q_L_COMMITMENT_LABEL, &preprocessed_input.selector_commitments[1]);
        self.append_commitment(Q_R_COMMITMENT_LABEL, &preprocessed_input.selector_commitments[2]);
        self.append_commitment(Q_O_COMMITMENT_LABEL, &preprocessed_input.selector_commitments[3]);
        self.append_commitment(Q_C_COMMITMENT_LABEL, &preprocessed_input.selector_commitments[4]);
        self.append_commitment(SIGMA_1_COMMITMENT_LABEL, &preprocessed_input.sigma_commitments[0]);
        self.append_commitment(SIGMA_2_COMMITMENT_LABEL, &preprocessed_input.sigma_commitments[1]);
        self.append_commitment(SIGMA_3_COMMITMENT_LABEL, &preprocessed_input.sigma_commitments[2]);
        self.append_scalar(
            K1_LABEL,
            &preprocessed_input.protocol_params.permutation_column_factors[1],
        );
        self.append_scalar(
            K2_LABEL,
            &preprocessed_input.protocol_params.permutation_column_factors[2],
        );
        self.append_bytes(
            NUM_WIRE_COLUMNS_LABEL,
            &preprocessed_input.protocol_params.num_wire_columns.to_le_bytes(),
        );
    }

    /// Absorb the Phase 9 quotient chunk commitments `[T_lo, T_mid, T_hi]`.
    pub fn absorb_phase_9_quotient_chunk_commitments(
        &mut self,
        commitments: &QuotientChunkCommitments,
    ) {
        self.append_commitment(T_LO_COMMITMENT_LABEL, &commitments.t_lo);
        self.append_commitment(T_MID_COMMITMENT_LABEL, &commitments.t_mid);
        self.append_commitment(T_HI_COMMITMENT_LABEL, &commitments.t_hi);
    }

    /// Absorb the Phase 9 evaluation payload before deriving `v`.
    pub fn absorb_phase_9_evaluations(
        &mut self,
        evaluations_at_zeta: &EvaluationsAtZeta,
        grand_product_at_zeta_omega: &Fr,
    ) {
        self.append_scalar(A_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.wire_a);
        self.append_scalar(B_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.wire_b);
        self.append_scalar(C_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.wire_c);
        self.append_scalar(S_SIGMA1_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.sigma_1);
        self.append_scalar(S_SIGMA2_EVAL_AT_ZETA_LABEL, &evaluations_at_zeta.sigma_2);
        self.append_scalar(Z_SHIFTED_EVAL_LABEL, grand_product_at_zeta_omega);
    }

    /// Absorb the Phase 9 opening commitments `[W_z]` and `[W_{z omega}]`.
    pub fn absorb_phase_9_opening_commitments(&mut self, commitments: &OpeningCommitments) {
        self.append_commitment(W_Z_COMMITMENT_LABEL, &commitments.at_zeta);
        self.append_commitment(W_Z_OMEGA_COMMITMENT_LABEL, &commitments.at_shifted_zeta);
    }

    /// Replay a Phase 9 proof using the Step 9.2 frozen transcript order.
    pub fn replay_phase_9_proof(
        &mut self,
        proof: &PlonkProof,
        public_inputs: &[Fr],
        preprocessed_input: &TranscriptPreprocessedInput,
    ) -> Phase9TranscriptChallenges {
        self.absorb_phase_9_preprocessed_input(preprocessed_input);
        self.absorb_plonk_public_inputs(public_inputs);
        self.absorb_plonk_wire_commitments(&proof.wire_commitments);
        let beta = self.challenge_scalar(BETA_CHALLENGE_LABEL);
        let gamma = self.challenge_scalar(GAMMA_CHALLENGE_LABEL);

        self.absorb_plonk_grand_product_commitment(&proof.grand_product_commitment);
        let alpha = self.challenge_scalar(ALPHA_CHALLENGE_LABEL);

        self.absorb_phase_9_quotient_chunk_commitments(&proof.quotient_chunk_commitments);
        let zeta = self.challenge_scalar(ZETA_CHALLENGE_LABEL);

        self.absorb_phase_9_evaluations(
            &proof.evaluations_at_zeta,
            &proof.grand_product_at_zeta_omega,
        );
        let v = self.challenge_scalar(V_CHALLENGE_LABEL);

        self.absorb_phase_9_opening_commitments(&proof.opening_commitments);
        let u = self.challenge_scalar(U_CHALLENGE_LABEL);

        Phase9TranscriptChallenges {
            beta,
            gamma,
            alpha,
            zeta,
            v,
            u,
        }
    }

    /// Append one tagged frame to the transcript state.
    fn append_frame(&mut self, tag: u8, label: &[u8], payload: &[u8]) {
        self.state.push(tag);
        self.state
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state
            .extend_from_slice(&(payload.len() as u64).to_le_bytes());
        self.state.extend_from_slice(payload);
    }

    /// Hash the current transcript state for the next challenge.
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
    /// Build the repository default transcript.
    fn default() -> Self {
        Self::new(b"minimal-plonk", TranscriptHash::default())
    }
}

/// Serialize any canonical object into stable compressed bytes.
fn serialize_to_bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.serialized_size(ark_serialize::Compress::Yes));
    value
        .serialize_compressed(&mut bytes)
        .expect("serializing into Vec<u8> should not fail");
    bytes
}

/// Build the fixed transcript label for one public input index.
fn public_input_label(index: usize) -> Vec<u8> {
    let mut label = PUBLIC_INPUT_LABEL_PREFIX.to_vec();
    label.extend_from_slice(index.to_string().as_bytes());
    label
}
