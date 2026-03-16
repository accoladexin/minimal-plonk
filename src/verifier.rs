//! Step 8.2: minimal Plonk verifier orchestration.
//!
//! This module keeps verifier-side protocol steps explicit and auditable:
//! 1) transcript replay
//! 2) main algebraic identity check at zeta
//! 3) KZG opening verification

use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Polynomial};

use crate::{
    curve::{Fr, G1},
    domain::{PlonkDomain, build_domain_from_size},
    error::Result,
    kzg::{KzgSrs, verify_opening},
    transcript::{Transcript, TranscriptChallenges},
    types::{Commitment, PlonkProof, VerifierPreprocessedInput},
};

#[derive(Clone, Debug)]
struct FixedEvaluationsAtZeta {
    q_l: Fr,
    q_r: Fr,
    q_o: Fr,
    q_m: Fr,
    q_c: Fr,
    sigma_a: Fr,
    sigma_b: Fr,
    sigma_c: Fr,
    l_0: Fr,
    l_n_minus_1: Fr,
    z_h: Fr,
    public_input_term: Fr,
}

/// 功能说明：按 Step 8.2 固定顺序验证 Step 8.1 产出的最小 proof。
/// 输入：proof、外部 public_inputs、verifier 固定预处理输入、KZG SRS。
/// 输出：全部检查通过返回 `Ok(true)`；任意检查失败返回 `Ok(false)`。
/// 示例：`let ok = verify(&proof, &public_inputs, &verifier_input, &srs)?;`
pub fn verify(
    proof: &PlonkProof,
    public_inputs: &[Fr],
    verifier_input: &VerifierPreprocessedInput,
    srs: &KzgSrs,
) -> Result<bool> {
    if !validate_basic_inputs(public_inputs, verifier_input, srs) {
        return Ok(false);
    }

    // Repo role: 当前最小协议保留 proof 内副本，verifier 仍以外部 statement 为准。
    if proof.public_inputs.as_slice() != public_inputs {
        return Ok(false);
    }

    let domain_size = match usize::try_from(verifier_input.domain.size) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let domain = match build_domain_from_size(domain_size) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    // 检查重建的domain是否一样
    if !is_domain_consistent_with_preprocessed_input(&domain, verifier_input) {
        return Ok(false);
    }

    // Paper mapping: step 4, verifier replay of Fiat-Shamir challenges.
    let challenges = replay_transcript_with_statement(proof, public_inputs);
    let shifted_zeta = domain.element(1) * challenges.zeta;

    let fixed_evaluations =
        evaluate_fixed_polynomials_at_zeta(&domain, public_inputs, verifier_input, challenges.zeta);
    if fixed_evaluations.z_h.is_zero() {
        return Ok(false);
    }

    // Paper mapping: main quotient identity check at zeta.
    if !verify_main_quotient_identity(proof, &challenges, &fixed_evaluations, verifier_input) {
        return Ok(false);
    }

    // Paper mapping: same-point batch opening check for A, B, C, Z, T.
    if !verify_opening_at_zeta(proof, &challenges, srs)? {
        return Ok(false);
    }

    // Paper mapping: separate opening check for Z(omega * zeta).
    if !verify_opening(
        &proof.grand_product_commitment,
        shifted_zeta,
        proof.shifted_evaluations.grand_product_next,
        &proof.opening_proof_at_shifted_zeta,
        srs,
    )? {
        return Ok(false);
    }

    Ok(true)
}

/// 功能说明：按固定顺序重放 Step 7.1 transcript，并显式绑定外部 statement。
/// 输入：proof 中的承诺/评估字段与 verifier 外部 public_inputs。
/// 输出：`beta, gamma, alpha, zeta, v`。
/// 示例：verifier 使用此函数确保挑战由外部 statement 驱动。
fn replay_transcript_with_statement(
    proof: &PlonkProof,
    public_inputs: &[Fr],
) -> TranscriptChallenges {
    let mut transcript = Transcript::default();
    transcript.absorb_plonk_wire_commitments(&proof.wire_commitments);
    transcript.absorb_plonk_public_inputs(public_inputs);
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

/// 功能说明：执行 verifier 的最小输入边界校验。
/// 输入：外部 public_inputs、verifier 固定数据、SRS。
/// 输出：边界条件合法返回 `true`，否则返回 `false`。
/// 示例：`verify()` 入口第一步调用此函数。
fn validate_basic_inputs(
    public_inputs: &[Fr],
    verifier_input: &VerifierPreprocessedInput,
    srs: &KzgSrs,
) -> bool {
    if srs.validate_shape().is_err() {
        return false;
    }
    if verifier_input.protocol_params.num_wire_columns != 3 {
        return false;
    }

    let domain_size = match usize::try_from(verifier_input.domain.size) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if domain_size == 0 {
        return false;
    }

    public_inputs.len() <= domain_size
}

/// 功能说明：检查 verifier 固定输入里的 domain 参数是否与重建 domain 一致。
/// 输入：由 size 重建的 domain 和 verifier 预处理输入。
/// 输出：一致返回 `true`，不一致返回 `false`。
/// 示例：篡改 domain generator 后应返回 `false`。
fn is_domain_consistent_with_preprocessed_input(
    domain: &PlonkDomain,
    verifier_input: &VerifierPreprocessedInput,
) -> bool {
    verifier_input.domain.size == domain.size() as u64
        && verifier_input.domain.log_size == domain.log_size_of_group() as u32
        && verifier_input.domain.generator == domain.group_gen()
}

/// 功能说明：在 `zeta` 计算主恒等式需要的固定多项式评估值。
/// 输入：domain、外部 public_inputs、verifier 固定预处理输入、`zeta`。
/// 输出：selector/sigma/Lagrange/vanishing/public-input term 的评估值。
/// 示例：其结果直接供主恒等式检查使用。
fn evaluate_fixed_polynomials_at_zeta(
    domain: &PlonkDomain,
    public_inputs: &[Fr],
    verifier_input: &VerifierPreprocessedInput,
    zeta: Fr,
) -> FixedEvaluationsAtZeta {
    let lagrange_values = domain.evaluate_all_lagrange_coefficients(zeta);
    let mut public_input_term = Fr::zero();
    for (index, input) in public_inputs.iter().enumerate() {
        public_input_term += *input * lagrange_values[index];
    }

    FixedEvaluationsAtZeta {
        q_l: verifier_input.selector_polynomials.q_l.evaluate(&zeta),
        q_r: verifier_input.selector_polynomials.q_r.evaluate(&zeta),
        q_o: verifier_input.selector_polynomials.q_o.evaluate(&zeta),
        q_m: verifier_input.selector_polynomials.q_m.evaluate(&zeta),
        q_c: verifier_input.selector_polynomials.q_c.evaluate(&zeta),
        sigma_a: verifier_input.sigma_tag_polynomials.wire_a.evaluate(&zeta),
        sigma_b: verifier_input.sigma_tag_polynomials.wire_b.evaluate(&zeta),
        sigma_c: verifier_input.sigma_tag_polynomials.wire_c.evaluate(&zeta),
        l_0: lagrange_values[0],
        l_n_minus_1: lagrange_values[lagrange_values.len() - 1],
        z_h: domain.evaluate_vanishing_polynomial(zeta),
        public_input_term,
    }
}

/// 功能说明：显式检查 Step 8.2 的主代数恒等式。
/// 输入：proof、重放挑战、固定多项式评估值、协议固定参数。
/// 输出：恒等式成立返回 `true`，否则返回 `false`。
/// 示例：篡改 `a(zeta)`、`t(zeta)` 或 `Z(omega*zeta)` 都应导致失败。
fn verify_main_quotient_identity(
    proof: &PlonkProof,
    challenges: &TranscriptChallenges,
    fixed: &FixedEvaluationsAtZeta,
    verifier_input: &VerifierPreprocessedInput,
) -> bool {
    let a = proof.evaluations_at_zeta.wire_a;
    let b = proof.evaluations_at_zeta.wire_b;
    let c = proof.evaluations_at_zeta.wire_c;
    let z_at_zeta = proof.evaluations_at_zeta.grand_product;
    let t_at_zeta = proof.evaluations_at_zeta.quotient;
    let z_at_shifted_zeta = proof.shifted_evaluations.grand_product_next;

    let gate_term = fixed.q_m * a * b + fixed.q_l * a + fixed.q_r * b + fixed.q_o * c + fixed.q_c;

    let factors = verifier_input.protocol_params.permutation_column_factors;
    let permutation_numerator =
        (a + challenges.beta * factors[0] * challenges.zeta + challenges.gamma)
            * (b + challenges.beta * factors[1] * challenges.zeta + challenges.gamma)
            * (c + challenges.beta * factors[2] * challenges.zeta + challenges.gamma);
    let permutation_denominator = (a + challenges.beta * fixed.sigma_a + challenges.gamma)
        * (b + challenges.beta * fixed.sigma_b + challenges.gamma)
        * (c + challenges.beta * fixed.sigma_c + challenges.gamma);
    let permutation_term =
        z_at_zeta * permutation_numerator - z_at_shifted_zeta * permutation_denominator;

    // Paper mapping: permutation boundary check via L_0 and L_{n-1}.
    let boundary_term_1 = (z_at_zeta - Fr::from(1u64)) * fixed.l_0;
    let boundary_term_2 = (z_at_shifted_zeta - Fr::from(1u64)) * fixed.l_n_minus_1;

    let alpha_square = challenges.alpha * challenges.alpha;
    let alpha_cube = alpha_square * challenges.alpha;
    let right_hand_side = gate_term
        + fixed.public_input_term
        + challenges.alpha * permutation_term
        + alpha_square * boundary_term_1
        + alpha_cube * boundary_term_2;
    let left_hand_side = t_at_zeta * fixed.z_h;

    left_hand_side == right_hand_side
}

/// 功能说明：执行 `zeta` 处的 same-point batch opening 验证。
/// 输入：proof、重放挑战、SRS。
/// 输出：batch opening 通过返回 `Ok(true)`，失败返回 `Ok(false)`。
/// 示例：篡改 `opening_proof_at_zeta` 后应返回 `Ok(false)`。
fn verify_opening_at_zeta(
    proof: &PlonkProof,
    challenges: &TranscriptChallenges,
    srs: &KzgSrs,
) -> Result<bool> {
    let commitments = [
        proof.wire_commitments[0].clone(),
        proof.wire_commitments[1].clone(),
        proof.wire_commitments[2].clone(),
        proof.grand_product_commitment.clone(),
        proof.quotient_commitment.clone(),
    ];
    let values = [
        proof.evaluations_at_zeta.wire_a,
        proof.evaluations_at_zeta.wire_b,
        proof.evaluations_at_zeta.wire_c,
        proof.evaluations_at_zeta.grand_product,
        proof.evaluations_at_zeta.quotient,
    ];

    // Repo role: 在 verifier 侧显式构造批量聚合，再进入 KZG pairing 检查。
    let aggregated_commitment = aggregate_commitments(&commitments, challenges.v);
    let aggregated_value = aggregate_values(&values, challenges.v);

    verify_opening(
        &aggregated_commitment,
        challenges.zeta,
        aggregated_value,
        &proof.opening_proof_at_zeta,
        srs,
    )
}

/// 功能说明：按固定输入顺序计算 `sum_i v^i * C_i`。
/// 输入：commitment 列表与聚合挑战 `v`。
/// 输出：聚合后的 commitment。
/// 示例：用于 `zeta` 处 same-point batch opening 的 verifier 聚合。
fn aggregate_commitments(commitments: &[Commitment], challenge: Fr) -> Commitment {
    let mut aggregated = G1::zero();
    let mut weight = Fr::from(1u64);
    for commitment in commitments {
        let mut term = commitment.point.into_group();
        term *= weight;
        aggregated += term;
        weight *= challenge;
    }
    Commitment::from_projective(aggregated)
}

/// 功能说明：按固定输入顺序计算 `sum_i v^i * y_i`。
/// 输入：标量值列表与聚合挑战 `v`。
/// 输出：聚合后的标量值。
/// 示例：与 `aggregate_commitments` 对齐使用。
fn aggregate_values(values: &[Fr], challenge: Fr) -> Fr {
    let mut aggregated = Fr::zero();
    let mut weight = Fr::from(1u64);
    for value in values {
        aggregated += weight * value;
        weight *= challenge;
    }
    aggregated
}
