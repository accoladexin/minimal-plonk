//! Step 9.4: paper-aligned verifier orchestration.
//!
//! This module keeps the verifier flow readable:
//! 1. transcript replay
//! 2. quotient chunk reconstruction
//! 3. linearization commitment/value assembly
//! 4. `W_z / W_{z omega} + u` opening check

use ark_ec::{AffineRepr, CurveGroup, Group, pairing::Pairing};
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, Polynomial};

use crate::{
    curve::{Curve, Fr, G1},
    domain::{PlonkDomain, build_domain_from_size},
    error::Result,
    kzg::KzgSrs,
    quotient::evaluate_public_input_polynomial_at_point,
    transcript::Transcript,
    types::{Commitment, PlonkProof, TranscriptPreprocessedInput, VerifierPreprocessedInput},
};

/// Verify a Phase 9 proof against external `public_inputs` and verifier fixed data.
pub fn verify(
    proof: &PlonkProof,
    public_inputs: &[Fr],
    verifier_input: &VerifierPreprocessedInput,
    srs: &KzgSrs,
) -> Result<bool> {

    // 检查domain是否和v给的一直，需要说明的是，这个domain的阶是n
    let domain = match build_and_validate_domain(verifier_input) {
        Some(domain) => domain,
        None => return Ok(false),
    };

    if !validate_verifier_inputs(public_inputs, verifier_input, &domain) {
        return Ok(false);
    }

    let transcript_input = match verifier_input.to_transcript_preprocessed_input(srs) {
        Ok(input) => input,
        Err(_) => return Ok(false),
    };
    // 获取所有的challenges
    let challenges =
        Transcript::default().replay_phase_9_proof(proof, public_inputs, &transcript_input);

    // 这里的是可忽略的概率为0
    // mapping step 5
    if domain
        .evaluate_vanishing_polynomial(challenges.zeta)
        .is_zero()
    {
        return Ok(false);
    }


    // 这里和原文的plonk有点出入
    // 这是是严格按照kzg的去计算的，这是计算r(x)的commint，原文是r'(x)其中，r‘(x)=r(x)-常数项目的
    let linearization_commitment = build_linearization_commitment(
        proof,
        verifier_input,
        &transcript_input,
        &domain,
        public_inputs,
        challenges.alpha,
        challenges.beta,
        challenges.gamma,
        challenges.zeta,
    );
    // step 10 ，其中r(x)这一个部分
    let same_point_commitment = build_same_point_commitment(
        &linearization_commitment,
        proof,
        &transcript_input,
        challenges.v,
    );


    // step 11 ，r'(x) 这一个部分
    let same_point_value = build_same_point_value(proof, challenges.v);

    // Paper mapping: the linearization relation claims `r(zeta) = 0`.
    // Repo role: the current Step 9.3 landing keeps the `boundary_2` image on the scalar side,
    // so verifier must reconstruct that exact claimed `r(zeta)` value instead of forcing zero.
    // 计算- alpha^3 * (Z(omega * zeta) - 1) * L_{n-1}(zeta)
    // 我就是我自己添加的这一项，都是常数项目 也就是scalar
    let linearization_value =
        evaluate_linearization_value(proof, challenges.alpha, challenges.zeta, &domain);

    // 自己添加+论文的这一项
    let expected_same_point_value = linearization_value + same_point_value;

    let _a = same_point_commitment.point.into_group()
        - (G1::generator() * expected_same_point_value);


    let shifted_zeta = domain.group_gen() * challenges.zeta;


    // Paper mapping: aggregate the `zeta` and `omega * zeta` openings with transcript challenge `u`.
    // Implementation note: this keeps the `W_z / W_{z omega} + u` structure readable instead of
    // hiding it behind a Step 8 style helper.
    let left_group = same_point_commitment.point.into_group()
        - (G1::generator() * expected_same_point_value)
        + scale_commitment_group(&proof.grand_product_commitment, challenges.u)
        - (G1::generator() * (challenges.u * proof.shifted_evaluations.grand_product_next))
        + scale_commitment_group(&proof.opening_commitments.at_zeta, challenges.zeta)
        + scale_commitment_group(
            &proof.opening_commitments.at_shifted_zeta,
            challenges.u * shifted_zeta,
        );
    let right_group = proof.opening_commitments.at_zeta.point.into_group()
        + scale_commitment_group(&proof.opening_commitments.at_shifted_zeta, challenges.u);

    // 现在开始拆分左边了
    let left_pairing = Curve::pairing(left_group.into_affine(), srs.g2_powers[0]);
    // 右边没有问题
    let right_pairing = Curve::pairing(right_group.into_affine(), srs.g2_powers[1]);

    Ok(left_pairing == right_pairing)
}

/// Reconstruct the scalar-side `r(zeta)` value expected by the landed Step 9.3 prover.
///  功能：重建线性化多项式 r(X) 在挑战点 zeta 处的纯标量分量。
//  背景：
//  线性化多项式 r(X) = Gate(X) + alpha*Perm(X) + alpha^2*Bound1(X) + alpha^3*Bound2(X) - t(X)Z_H(X)。
//  其中，某些项在 Verifier 看来已经是确定的常数了。
fn evaluate_linearization_value(
    proof: &PlonkProof,
    alpha: Fr,
    zeta: Fr,
    domain: &PlonkDomain,
) -> Fr {
    // Paper mapping: this is the scalar image of the part not carried inside `[R]`.
    // Implementation note: Step 9.3 keeps the `boundary_2` term here, so Step 9.4 must
    // replay the same landed prover boundary instead of silently changing it.
    // 1. 获取全套拉格朗日基函数在 zeta 点的值。
    // 这就像是在随机点 zeta 处放置了 n 个探针，测量每一行的“权重”。
    let lagrange_values = domain.evaluate_all_lagrange_coefficients(zeta);

    // 2. 提取最后一行（第 n-1 行）的拉格朗日系数 L_{n-1}(zeta)。
    // 作用：它是“收尾约束”的开关。只有在这一项，我们检查 Z 累乘是否回到了 1。

    let l_n_minus_1_at_zeta = lagrange_values[domain.size() - 1];

    // 3. 计算聚合挑战值 alpha 的 3 次方。
    // 对应聚合公式中的第四项：alpha^3 * (Z(omega * X) - 1) * L_{n-1}(X)。
    let alpha_cube = alpha * alpha * alpha;

    // 4. 计算纯标量项的结果：
    // 公式：- alpha^3 * (Z(omega * zeta) - 1) * L_{n-1}(zeta)
    //
    // 为什么是负号？：因为在 linearized 承诺 [R] 的构造中，通常把 Numerator - t*ZH
    // 里的某些项挪到了 scalar side 来进行最终求值。
    //
    // proof.shifted_evaluations.grand_product_next：就是 Z(omega * zeta) 的值，由 Prover 直接提供。
    -alpha_cube
        * (proof.shifted_evaluations.grand_product_next - Fr::from(1u64))
        * l_n_minus_1_at_zeta
}

/// Build and validate the domain reconstructed from verifier fixed data.
fn build_and_validate_domain(verifier_input: &VerifierPreprocessedInput) -> Option<PlonkDomain> {
    let domain_size = usize::try_from(verifier_input.domain.size).ok()?;
    let domain = build_domain_from_size(domain_size).ok()?;
    if verifier_input.domain.log_size != domain.log_size_of_group() as u32 {
        return None;
    }
    if verifier_input.domain.generator != domain.group_gen() {
        return None;
    }
    Some(domain)
}

/// Validate the minimal verifier-side input boundary before transcript replay.
fn validate_verifier_inputs(
    public_inputs: &[Fr],
    verifier_input: &VerifierPreprocessedInput,
    domain: &PlonkDomain,
) -> bool {
    if public_inputs.len() > domain.size() {
        return false;
    }

    if verifier_input.protocol_params.num_wire_columns != 3 {
        return false;
    }

    let factors = verifier_input.protocol_params.permutation_column_factors;
    if factors[0] != Fr::from(1u64) {
        return false;
    }
    if factors[1].is_zero() || factors[2].is_zero() {
        return false;
    }
    if factors[0] == factors[1] || factors[0] == factors[2] || factors[1] == factors[2] {
        return false;
    }

    true
}

/// Build the verifier-side linearization commitment `[R]`.
#[allow(clippy::too_many_arguments)]
fn build_linearization_commitment(
    proof: &PlonkProof,
    verifier_input: &VerifierPreprocessedInput,
    transcript_input: &TranscriptPreprocessedInput,
    domain: &PlonkDomain,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    zeta: Fr,
) -> Commitment {
    // Paper mapping: this is the verifier-side image of the prover linearization polynomial `r(X)`.
    // Repo role: we reconstruct `[R]` from fixed commitments plus proof commitments instead of
    // requiring the verifier to know witness polynomials.
    let selector_evaluations = evaluate_selector_polynomials_at_zeta(verifier_input, zeta);
    let public_input_at_zeta =
        evaluate_public_input_polynomial_at_point(domain, public_inputs, zeta);


    let l_0_at_zeta = domain.evaluate_all_lagrange_coefficients(zeta)[0];
    let z_h_at_zeta = domain.evaluate_vanishing_polynomial(zeta);
    let domain_size = domain.size();

    let point_to_n = zeta.pow([domain_size as u64]);
    let point_to_2n = point_to_n * point_to_n;


    // proof中的值，也就是kzg需要点值，即（x，f（x））
    let a_at_zeta = proof.evaluations_at_zeta.wire_a;
    let b_at_zeta = proof.evaluations_at_zeta.wire_b;
    let c_at_zeta = proof.evaluations_at_zeta.wire_c;
    let sigma_1_at_zeta = proof.evaluations_at_zeta.sigma_1;
    let sigma_2_at_zeta = proof.evaluations_at_zeta.sigma_2;
    let z_at_omega_zeta = proof.shifted_evaluations.grand_product_next;

    // 在通用多项式中 qm*a*b
    let gate_scalar_q_m = a_at_zeta * b_at_zeta;
    // ql*a
    let gate_scalar_q_l = a_at_zeta;
    // qr*b
    let gate_scalar_q_r = b_at_zeta;
    let gate_scalar_q_o = c_at_zeta;


    // mapp to paper step 9，中间第二行，左边这边
    let permutation_scalar = alpha
        * (a_at_zeta + beta * zeta + gamma)
        * (b_at_zeta
            + beta * verifier_input.protocol_params.permutation_column_factors[1] * zeta
            + gamma)
        * (c_at_zeta
            + beta * verifier_input.protocol_params.permutation_column_factors[2] * zeta
            + gamma);
    // mapping to paper step 8和step 9重合部分
    let sigma_scalar = -alpha
        * (a_at_zeta + beta * sigma_1_at_zeta + gamma)
        * (b_at_zeta + beta * sigma_2_at_zeta + gamma);

    // mapping step9 第三行部分
    let sigma_linear_scalar = beta * sigma_scalar * z_at_omega_zeta;

    // mapping to paper step 8 末尾
    let sigma_constant = (c_at_zeta + gamma) * sigma_scalar * z_at_omega_zeta;

    // `into_group()` 就是将数据从**“压缩存储格式”**转换为**“高性能计算格式”**的标志性动作。
    // mapping paper to step 9最后一行
    let quotient_commitment_group = proof.quotient_chunk_commitments.t_lo.point.into_group()
        + proof.quotient_chunk_commitments.t_mid.point.into_group() * point_to_n
        + proof.quotient_chunk_commitments.t_hi.point.into_group() * point_to_2n;

    // scale_commitment_group 里面的元素相乘
    let linearization_group =
    // step9 第一行 +  step 8 第一行   总体就是gate约束
        scale_commitment_group(&transcript_input.selector_commitments[0], gate_scalar_q_m)
            + scale_commitment_group(&transcript_input.selector_commitments[1], gate_scalar_q_l)
            + scale_commitment_group(&transcript_input.selector_commitments[2], gate_scalar_q_r)
            + scale_commitment_group(&transcript_input.selector_commitments[3], gate_scalar_q_o)
            + scale_commitment_group(&transcript_input.selector_commitments[4], Fr::from(1u64))
            + commitment_from_scalar(public_input_at_zeta)

            //step 9 第二行一部分
            + scale_commitment_group(&proof.grand_product_commitment, permutation_scalar)
            // step9 第三行所有
            + scale_commitment_group(&transcript_input.sigma_commitments[2], sigma_linear_scalar)
            // 第8行末尾的值放到g1上去
            + commitment_from_scalar(sigma_constant)
            // step 9 第二行 中间
            + scale_commitment_group(&proof.grand_product_commitment, alpha * alpha * l_0_at_zeta)
            // step 8 中间 到g1
            + commitment_from_scalar(-alpha * alpha * l_0_at_zeta)
            // step step 9 末尾
            - (quotient_commitment_group * z_h_at_zeta);

    // 返回的就是step8和step9 - step9 第二行的末尾
    Commitment::from_projective(linearization_group)
}

/// Evaluate all selector polynomials at `zeta`.
fn evaluate_selector_polynomials_at_zeta(
    verifier_input: &VerifierPreprocessedInput,
    zeta: Fr,
) -> SelectorEvaluationsAtZeta {
    SelectorEvaluationsAtZeta {
        q_l: verifier_input.selector_polynomials.q_l.evaluate(&zeta),
        q_r: verifier_input.selector_polynomials.q_r.evaluate(&zeta),
        q_o: verifier_input.selector_polynomials.q_o.evaluate(&zeta),
        q_m: verifier_input.selector_polynomials.q_m.evaluate(&zeta),
        q_c: verifier_input.selector_polynomials.q_c.evaluate(&zeta),
    }
}

/// Aggregate `[R]` with the same-point commitments opened at `zeta`.
/// step10，对于第一个第一组多项式的commint组合
fn build_same_point_commitment(
    linearization_commitment: &Commitment,
    proof: &PlonkProof,
    transcript_input: &TranscriptPreprocessedInput,
    v: Fr,
) -> Commitment {
    // Paper mapping: `[R] + v[A] + v^2[B] + v^3[C] + v^4[S_sigma1] + v^5[S_sigma2]`.
    Commitment::from_projective(
        linearization_commitment.point.into_group()
            + scale_commitment_group(&proof.wire_commitments[0], v)
            + scale_commitment_group(&proof.wire_commitments[1], v * v)
            + scale_commitment_group(&proof.wire_commitments[2], v * v * v)
            + scale_commitment_group(&transcript_input.sigma_commitments[0], v * v * v * v)
            + scale_commitment_group(&transcript_input.sigma_commitments[1], v * v * v * v * v),
    )
}

/// Build the same-point scalar aggregate at `zeta`, excluding `r(zeta)`.
fn build_same_point_value(proof: &PlonkProof, v: Fr) -> Fr {
    // Paper mapping: `r(zeta) + v*a(zeta) + ... + v^5*S_sigma2(zeta)`.
    v * proof.evaluations_at_zeta.wire_a
        + v * v * proof.evaluations_at_zeta.wire_b
        + v * v * v * proof.evaluations_at_zeta.wire_c
        + v * v * v * v * proof.evaluations_at_zeta.sigma_1
        + v * v * v * v * v * proof.evaluations_at_zeta.sigma_2
}

/// Scale a commitment by a scalar and return the projective G1 point.
fn scale_commitment_group(commitment: &Commitment, scalar: Fr) -> G1 {
    commitment.point.into_group() * scalar
}

/// Embed a scalar constant into the G1 generator direction.
fn commitment_from_scalar(scalar: Fr) -> G1 {
    G1::generator() * scalar
}

/// Small bundle of selector evaluations reused in verifier aggregation code.
struct SelectorEvaluationsAtZeta {
    q_l: Fr,
    q_r: Fr,
    q_o: Fr,
    q_m: Fr,
    q_c: Fr,
}

