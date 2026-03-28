//! Step 9.3: paper-aligned prover orchestration.
//!
//! This module keeps the prover flow readable:
//! 1. witness commitments
//! 2. grand product commitment
//! 3. quotient chunk commitments
//! 4. linearization polynomial
//! 5. `W_z / W_{z omega}` opening commitments

use ark_ff::Zero;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, univariate::DensePolynomial};
use ark_std::UniformRand;
use rand::thread_rng;

use crate::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    error::Result,
    kzg::{KzgSrs, build_witness_polynomial, commit_polynomial},
    permutation::{
        CopyConstraint, K1, K2, build_sigma_from_copy_constraints,
        compute_grand_product_evaluations,
        grand_product::compute_sigma_tag_evaluations_for_quotient,
        interpolate_grand_product_evaluations,
    },
    quotient::{
        QuotientChunkPolynomials, blind_grand_product_polynomial, blind_witness_polynomial,
        build_linearization_polynomial, compute_blinded_quotient_polynomial, compute_step_5_1,
        rerandomize_quotient_chunks, split_quotient_polynomial,
    },
    transcript::Transcript,
    types::{
        Commitment, EvaluationsAtZeta, OpeningCommitments, PlonkProof, QuotientChunkCommitments,
        QuotientInputs, SelectorPolynomials, ShiftedEvaluations, SigmaTagPolynomials,
        TranscriptPreprocessedInput, VerifierProtocolParams,
    },
    validate::ensure,
    witness::{
        WitnessColumns, WitnessPolynomials, interpolate_column_evaluations,
        interpolate_witness_column_polynomials,
    },
};

/// 功能说明：按 Step 9.3 冻结边界生成 paper-aligned prover proof。
/// 输入：已冻结电路、copy constraints、外部 `public_inputs` 与 KZG SRS。
/// 输出：一个 `PlonkProof`。
/// 示例：`let proof = prove(&circuit, &copy_constraints, public_inputs, &srs)?;`
/// 按 Step 9.3 冻结边界生成 paper-aligned prover proof。
pub fn prove(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
    public_inputs: Vec<Fr>,
    srs: &KzgSrs,
) -> Result<PlonkProof> {
    // 确保电路是扩展到2**n的
    ensure(
        circuit.is_frozen(),
        "circuit must call pad_to_domain() before prove()",
    )?;

    let domain_size = circuit
        .domain_size()
        .expect("frozen circuit must record domain size");
    let domain = build_domain_from_size(domain_size)?;

    // Repo role: materialize all row-wise data in the shared H-domain view.
    // 应该是eval形式
    let witness_columns = WitnessColumns::from_padded_circuit(circuit)?;
    let selector_columns = SelectorColumns::from_padded_circuit(circuit)?;
    let raw_wire_polynomials = interpolate_witness_column_polynomials(&domain, &witness_columns)?;
    //  生成随机随机seed
    let blinding_scalars = sample_blinding_scalars();
    // Paper mapping: witness polynomials are blinded before Round 1 commitments.
    // Repo role: use minimal `(r0 + r1 X) * Z_H(X)` terms so H-domain rows stay unchanged.
    let wire_polynomials =
        blind_wire_polynomials(&raw_wire_polynomials, domain_size, &blinding_scalars)?;

    // round1
    let wire_commitments = commit_wire_polynomials(&wire_polynomials, srs)?;

    // 只返回一个3n的位置映射
    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)?;
    let selector_polynomials = build_selector_polynomials(&domain, &selector_columns)?;
    // S_sigma1/S_sigma2/S_sigma3 多项式
    let sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping)?;
    // 初始化
    let transcript_input = build_transcript_preprocessed_input(
        &domain,
        &selector_polynomials,
        &sigma_tag_polynomials,
        srs,
    )?;

    // Paper mapping: transcript binds common preprocessed input and statement before Round 1 outputs.
    let mut transcript = Transcript::default();
    transcript.absorb_phase_9_preprocessed_input(&transcript_input);
    transcript.absorb_plonk_public_inputs(&public_inputs);
    transcript.absorb_plonk_wire_commitments(&wire_commitments);
    let beta = transcript.challenge_scalar(b"beta");
    let gamma = transcript.challenge_scalar(b"gamma");

    // Paper mapping: Prover Round 2, compute and commit grand product Z(X).
    let grand_product_evaluations = compute_grand_product_evaluations(
        &witness_columns.wire_a_evaluations,
        &witness_columns.wire_b_evaluations,
        &witness_columns.wire_c_evaluations,
        &sigma_mapping,
        beta,
        gamma,
    )?;
    let grand_product_polynomial = interpolate_grand_product_evaluations(
        &grand_product_evaluations.grand_product_evaluations,
        domain_size,
    )?;
    // Paper mapping: Z(X) also becomes a blinded prover-side object before commitment/opening.
    // Repo role: follow the paper's quadratic Round 2 masking shape `(b7 X^2 + b8 X + b9) * Z_H(X)`.
    let grand_product_polynomial = blind_grand_product_polynomial(
        &grand_product_polynomial,
        domain_size,
        blinding_scalars.grand_product_constant,
        blinding_scalars.grand_product_linear,
        blinding_scalars.grand_product_quadratic,
    )?;
    // round 2
    let grand_product_commitment = commit_polynomial(&grand_product_polynomial, srs)?;
    transcript.absorb_plonk_grand_product_commitment(&grand_product_commitment);
    let alpha = transcript.challenge_scalar(b"alpha");

    // Paper mapping: Prover Round 3, build the full quotient witness and then chunk it.
    let quotient_inputs = QuotientInputs::new(
        witness_columns,
        selector_columns,
        sigma_mapping,
        grand_product_evaluations,
    )?;
    let quotient_output = compute_step_5_1(
        &quotient_inputs,
        public_inputs.as_slice(),
        alpha,
        beta,
        gamma,
    )?;
    ensure(
        quotient_output
            .h_domain
            .numerator_evaluations
            .iter()
            .all(|value| value.is_zero()),
        "circuit witness, copy constraints, and public_inputs must satisfy Plonk constraints",
    )?;

    // 这个才是正在的round3 round1和round2带上了blinding terms
    let quotient_polynomial = compute_blinded_quotient_polynomial(
        &quotient_inputs,
        public_inputs.as_slice(),
        alpha,
        beta,
        gamma,
        &wire_polynomials,
        &grand_product_polynomial,
    )?;

    // Repo role: re-randomize only the committed chunks, while keeping reconstructed `t(X)` unchanged.
    // &split_quotient_polynomial(&quotient_polynomial, domain_size)?, 切分为3个多项式
    let quotient_chunks = rerandomize_quotient_chunks(
        &split_quotient_polynomial(&quotient_polynomial, domain_size)?,
        domain_size,
        blinding_scalars.quotient_first,
        blinding_scalars.quotient_second,
    )?;
    // round3的commit
    let quotient_chunk_commitments =
        commit_quotient_chunks(&quotient_chunks, &quotient_polynomial, srs)?;

    transcript.absorb_phase_9_quotient_chunk_commitments(&quotient_chunk_commitments);
    let zeta = transcript.challenge_scalar(b"zeta");

    // Paper mapping: Prover Round 4, publish evaluation payload for the future verifier relation.
    let shifted_zeta = domain.element(1) * zeta;
    //计算点值
    let evaluations_at_zeta =
        evaluate_opening_payload(&wire_polynomials, &sigma_tag_polynomials, zeta);
    let shifted_evaluations =
        ShiftedEvaluations::new(grand_product_polynomial.evaluate(&shifted_zeta));


    transcript.absorb_phase_9_evaluations(&evaluations_at_zeta, &shifted_evaluations);
    let v = transcript.challenge_scalar(b"v");

    // Paper mapping: Prover Round 5, construct the explicit linearization polynomial r(X).
    let linearization_polynomial = build_linearization_polynomial(
        &domain,
        &selector_polynomials.q_l,
        &selector_polynomials.q_r,
        &selector_polynomials.q_o,
        &selector_polynomials.q_m,
        &selector_polynomials.q_c,
        &sigma_tag_polynomials.wire_c,
        &grand_product_polynomial,
        &quotient_chunks,
        public_inputs.as_slice(),
        alpha,
        beta,
        gamma,
        zeta,
        evaluations_at_zeta.wire_a,
        evaluations_at_zeta.wire_b,
        evaluations_at_zeta.wire_c,
        evaluations_at_zeta.sigma_1,
        evaluations_at_zeta.sigma_2,
        shifted_evaluations.grand_product_next,
    );
    let w_z_polynomial = build_w_z_polynomial(
        &linearization_polynomial,
        &wire_polynomials,
        &sigma_tag_polynomials,
        &evaluations_at_zeta,
        zeta,
        v,
    )?;
    let w_z_omega_polynomial = build_w_z_omega_polynomial(
        &grand_product_polynomial,
        shifted_zeta,
        shifted_evaluations.grand_product_next,
    )?;
    let opening_commitments = OpeningCommitments::new(
        commit_polynomial(&w_z_polynomial, srs)?,
        commit_polynomial(&w_z_omega_polynomial, srs)?,
    );
    transcript.absorb_phase_9_opening_commitments(&opening_commitments);
    let _u = transcript.challenge_scalar(b"u");

    Ok(PlonkProof::new(
        wire_commitments,
        grand_product_commitment,
        quotient_chunk_commitments,
        opening_commitments,
        evaluations_at_zeta,
        shifted_evaluations,
    ))
}

/// 功能说明：按固定顺序对 witness 三列做 KZG commitment。
/// 输入：`A(X)/B(X)/C(X)` 与 SRS。
/// 输出：`[A, B, C]` commitments。
/// 示例：`commit_wire_polynomials(&wire_polynomials, srs)?`。
fn commit_wire_polynomials(
    wire_polynomials: &WitnessPolynomials,
    srs: &KzgSrs,
) -> Result<[Commitment; 3]> {
    Ok([
        commit_polynomial(&wire_polynomials.wire_a_poly, srs)?,
        commit_polynomial(&wire_polynomials.wire_b_poly, srs)?,
        commit_polynomial(&wire_polynomials.wire_c_poly, srs)?,
    ])
}

/// 功能说明：把 selector evaluations 插值成多项式，供 quotient 与 transcript 复用。
/// 输入：domain 与 `SelectorColumns`。
/// 输出：`SelectorPolynomials`。
/// 示例：`build_selector_polynomials(&domain, &selector_columns)?`。
fn build_selector_polynomials(
    domain: &PlonkDomain,
    selector_columns: &SelectorColumns,
) -> Result<SelectorPolynomials> {
    Ok(SelectorPolynomials::new(
        interpolate_column_evaluations(domain, &selector_columns.q_l_evaluations)?,
        interpolate_column_evaluations(domain, &selector_columns.q_r_evaluations)?,
        interpolate_column_evaluations(domain, &selector_columns.q_o_evaluations)?,
        interpolate_column_evaluations(domain, &selector_columns.q_m_evaluations)?,
        interpolate_column_evaluations(domain, &selector_columns.q_c_evaluations)?,
    ))
}

/// 功能说明：把 sigma tag evaluations 插值成 `S_sigma1/S_sigma2/S_sigma3` 主要是IFFT。
/// 输入：domain 与 sigma mapping。
/// 输出：`SigmaTagPolynomials`。
/// 示例：`build_sigma_tag_polynomials(&domain, &sigma_mapping)?`。
fn build_sigma_tag_polynomials(
    domain: &PlonkDomain,
    sigma_mapping: &crate::permutation::SigmaMapping,
) -> Result<SigmaTagPolynomials> {
    let sigma_tag_evaluations = compute_sigma_tag_evaluations_for_quotient(domain, sigma_mapping)?;
    Ok(SigmaTagPolynomials::new(
        interpolate_column_evaluations(domain, &sigma_tag_evaluations.sigma_a_evaluations)?,
        interpolate_column_evaluations(domain, &sigma_tag_evaluations.sigma_b_evaluations)?,
        interpolate_column_evaluations(domain, &sigma_tag_evaluations.sigma_c_evaluations)?,
    ))
}

/// 功能说明：为 Phase 9 transcript 构造 commitments-based fixed input。
/// 输入：domain、selector polynomials、sigma polynomials 与 SRS。
/// 输出：`TranscriptPreprocessedInput`。
/// 示例：新的 transcript replay 会显式吸收该对象。
fn build_transcript_preprocessed_input(
    domain: &PlonkDomain,
    selector_polynomials: &SelectorPolynomials,
    sigma_tag_polynomials: &SigmaTagPolynomials,
    srs: &KzgSrs,
) -> Result<TranscriptPreprocessedInput> {
    let selector_commitments = [
        commit_polynomial(&selector_polynomials.q_m, srs)?,
        commit_polynomial(&selector_polynomials.q_l, srs)?,
        commit_polynomial(&selector_polynomials.q_r, srs)?,
        commit_polynomial(&selector_polynomials.q_o, srs)?,
        commit_polynomial(&selector_polynomials.q_c, srs)?,
    ];
    let sigma_commitments = [
        commit_polynomial(&sigma_tag_polynomials.wire_a, srs)?,
        commit_polynomial(&sigma_tag_polynomials.wire_b, srs)?,
        commit_polynomial(&sigma_tag_polynomials.wire_c, srs)?,
    ];
    Ok(TranscriptPreprocessedInput::new(
        domain_params(domain),
        selector_commitments,
        sigma_commitments,
        VerifierProtocolParams::new(3, [Fr::from(1u64), Fr::from(K1), Fr::from(K2)]),
    ))
}

/// 功能说明：对 `T_lo/T_mid/T_hi` 分别做 commitment，并验证 chunk 重组没有偏移。
/// 输入：quotient chunks、完整 `T(X)` 与 SRS。
/// 输出：`QuotientChunkCommitments`。
/// 示例：`commit_quotient_chunks(&chunks, &t, srs)?`。
fn commit_quotient_chunks(
    quotient_chunks: &QuotientChunkPolynomials,
    full_quotient_polynomial: &DensePolynomial<Fr>,
    srs: &KzgSrs,
) -> Result<QuotientChunkCommitments> {
    srs.validate_polynomial_degree(full_quotient_polynomial.degree())?;
    Ok(QuotientChunkCommitments::new(
        commit_polynomial(&quotient_chunks.t_lo, srs)?,
        commit_polynomial(&quotient_chunks.t_mid, srs)?,
        commit_polynomial(&quotient_chunks.t_hi, srs)?,
    ))
}

/// 功能说明：计算 Phase 9 proof 在 `zeta` 的 evaluation payload。
/// 输入：wires、sigma tags、`Z(X)`、quotient chunks、domain 大小与 `zeta`。
/// 输出：`EvaluationsAtZeta`。
/// 示例：这些值会先进入 transcript，再导出 `v`。
fn evaluate_opening_payload(
    wire_polynomials: &WitnessPolynomials,
    sigma_tag_polynomials: &SigmaTagPolynomials,
    zeta: Fr,
) -> EvaluationsAtZeta {
    EvaluationsAtZeta::new(
        wire_polynomials.wire_a_poly.evaluate(&zeta),
        wire_polynomials.wire_b_poly.evaluate(&zeta),
        wire_polynomials.wire_c_poly.evaluate(&zeta),
        sigma_tag_polynomials.wire_a.evaluate(&zeta),
        sigma_tag_polynomials.wire_b.evaluate(&zeta),
    )
}

/// 功能说明：构造 paper-aligned 的 `W_z(X)` witness polynomial。
/// 输入：`r(X)`、wires、sigma polynomials、`zeta` 评估值、`zeta` 与 `v`。
/// 输出：`W_z(X)`。
/// 示例：`build_w_z_polynomial(&r, ..., zeta, v)?`。
fn build_w_z_polynomial(
    linearization_polynomial: &DensePolynomial<Fr>,
    wire_polynomials: &WitnessPolynomials,
    sigma_tag_polynomials: &SigmaTagPolynomials,
    evaluations_at_zeta: &EvaluationsAtZeta,
    zeta: Fr,
    v: Fr,
) -> Result<DensePolynomial<Fr>> {
    // Paper mapping: W_z batches r(X), a(X), b(X), c(X), S_sigma1(X), S_sigma2(X) at zeta.
    // Implementation note: this repository explicitly subtracts `r(zeta)` here so the
    // witness construction remains well-defined before Step 9.4 verifier lands.
    let numerator = (linearization_polynomial
        - &DensePolynomial::from_coefficients_vec(vec![linearization_polynomial.evaluate(&zeta)]))
        + build_centered_opening_term(&wire_polynomials.wire_a_poly, evaluations_at_zeta.wire_a, v)
        + build_centered_opening_term(
            &wire_polynomials.wire_b_poly,
            evaluations_at_zeta.wire_b,
            v * v,
        )
        + build_centered_opening_term(
            &wire_polynomials.wire_c_poly,
            evaluations_at_zeta.wire_c,
            v * v * v,
        )
        + build_centered_opening_term(
            &sigma_tag_polynomials.wire_a,
            evaluations_at_zeta.sigma_1,
            v * v * v * v,
        )
        + build_centered_opening_term(
            &sigma_tag_polynomials.wire_b,
            evaluations_at_zeta.sigma_2,
            v * v * v * v * v,
        );
    build_witness_polynomial(&numerator, zeta, Fr::zero())
}

/// 功能说明：构造 shifted opening 的 `W_{z omega}(X)`。
/// 输入：`Z(X)`、`omega*zeta` 与 `Z(omega*zeta)`。
/// 输出：`W_{z omega}(X)`。
/// 示例：`build_w_z_omega_polynomial(&z_poly, shifted_zeta, value)?`。
fn build_w_z_omega_polynomial(
    grand_product_polynomial: &DensePolynomial<Fr>,
    shifted_zeta: Fr,
    shifted_value: Fr,
) -> Result<DensePolynomial<Fr>> {
    // Paper mapping: the shifted witness only opens Z(X) at omega * zeta.
    build_witness_polynomial(grand_product_polynomial, shifted_zeta, shifted_value)
}

/// 功能说明：构造 `(p(X) - p(point)) * weight` 这一类同点 opening 项。
/// 输入：多项式、该点的评估值与聚合权重。
/// 输出：缩放后的居中多项式。
/// 示例：`build_centered_opening_term(&a_poly, a_at_zeta, v)`。
fn build_centered_opening_term(
    polynomial: &DensePolynomial<Fr>,
    value: Fr,
    weight: Fr,
) -> DensePolynomial<Fr> {
    scale_polynomial(
        &(polynomial - &DensePolynomial::from_coefficients_vec(vec![value])),
        weight,
    )
}

/// 功能说明：把一个多项式整体乘以一个标量。
/// 输入：多项式与标量。
/// 输出：缩放后的多项式。
/// 示例：`scale_polynomial(&poly, alpha)`。
fn scale_polynomial(polynomial: &DensePolynomial<Fr>, scalar: Fr) -> DensePolynomial<Fr> {
    if scalar.is_zero() || polynomial.is_zero() {
        return DensePolynomial::zero();
    }

    DensePolynomial::from_coefficients_vec(
        polynomial
            .coeffs
            .iter()
            .map(|coefficient| *coefficient * scalar)
            .collect(),
    )
}

/// 功能说明：收集 Step 10.2 prover 需要的最小 blinding randomness。
/// 输入：无。
/// 输出：本次 prove 使用的一组随机标量。
/// 示例：`let blinders = sample_blinding_scalars();`。
fn sample_blinding_scalars() -> ProverBlindingScalars {
    let mut rng = thread_rng();
    ProverBlindingScalars {
        wire_a_constant: Fr::rand(&mut rng),
        wire_a_linear: Fr::rand(&mut rng),
        wire_b_constant: Fr::rand(&mut rng),
        wire_b_linear: Fr::rand(&mut rng),
        wire_c_constant: Fr::rand(&mut rng),
        wire_c_linear: Fr::rand(&mut rng),
        grand_product_constant: Fr::rand(&mut rng),
        grand_product_linear: Fr::rand(&mut rng),
        grand_product_quadratic: Fr::rand(&mut rng),
        quotient_first: Fr::rand(&mut rng),
        quotient_second: Fr::rand(&mut rng),
    }
}

/// 功能说明：把 Step 10.2 witness blinding 应用到 `A/B/C`。
/// 输入：原始 witness polynomials、原始 domain 大小、blinding scalars。
/// 输出：blinded `A/B/C`。
/// 示例：`blind_wire_polynomials(&raw, n, &blinders)?`。
fn blind_wire_polynomials(
    wire_polynomials: &WitnessPolynomials,
    domain_size: usize,
    blinding_scalars: &ProverBlindingScalars,
) -> Result<WitnessPolynomials> {
    Ok(WitnessPolynomials {
        wire_a_poly: blind_witness_polynomial(
            &wire_polynomials.wire_a_poly,
            domain_size,
            blinding_scalars.wire_a_constant,
            blinding_scalars.wire_a_linear,
        )?,
        wire_b_poly: blind_witness_polynomial(
            &wire_polynomials.wire_b_poly,
            domain_size,
            blinding_scalars.wire_b_constant,
            blinding_scalars.wire_b_linear,
        )?,
        wire_c_poly: blind_witness_polynomial(
            &wire_polynomials.wire_c_poly,
            domain_size,
            blinding_scalars.wire_c_constant,
            blinding_scalars.wire_c_linear,
        )?,
    })
}

/// Step 10.2 prover-side random scalars.
struct ProverBlindingScalars {
    wire_a_constant: Fr,
    wire_a_linear: Fr,
    wire_b_constant: Fr,
    wire_b_linear: Fr,
    wire_c_constant: Fr,
    wire_c_linear: Fr,
    grand_product_constant: Fr,
    grand_product_linear: Fr,
    grand_product_quadratic: Fr,
    quotient_first: Fr,
    quotient_second: Fr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cs::Circuit,
        kzg::{KzgSrs, verify_opening},
        permutation::build_sigma_from_copy_constraints,
        quotient::{
            blind_grand_product_polynomial, compute_blinded_quotient_polynomial,
            rerandomize_quotient_chunks, split_quotient_polynomial,
        },
        types::{OpeningProof, VerifierPreprocessedInput, VerifierProtocolParams},
        verifier::verify,
    };
    use ark_ec::AffineRepr;

    #[test]
    fn verifier_style_same_point_commitment_matches_direct_polynomial_commitment() {
        let mut circuit = Circuit::new();
        circuit
            .add_gate(
                Fr::from(3u64),
                Fr::from(4u64),
                Fr::from(7u64),
                Fr::from(1u64),
                Fr::from(1u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit.pad_to_domain();

        let domain_size = circuit.domain_size().unwrap();
        let domain = build_domain_from_size(domain_size).unwrap();
        let srs = KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two()).unwrap();
        let witness_columns = WitnessColumns::from_padded_circuit(&circuit).unwrap();
        let selector_columns = SelectorColumns::from_padded_circuit(&circuit).unwrap();
        let raw_wire_polynomials =
            interpolate_witness_column_polynomials(&domain, &witness_columns).unwrap();
        let selector_polynomials = build_selector_polynomials(&domain, &selector_columns).unwrap();
        let sigma_mapping = build_sigma_from_copy_constraints(domain_size, &[]).unwrap();
        let sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping).unwrap();

        let wire_polynomials = WitnessPolynomials {
            wire_a_poly: blind_witness_polynomial(
                &raw_wire_polynomials.wire_a_poly,
                domain_size,
                Fr::from(11u64),
                Fr::from(0u64),
            )
            .unwrap(),
            wire_b_poly: blind_witness_polynomial(
                &raw_wire_polynomials.wire_b_poly,
                domain_size,
                Fr::from(13u64),
                Fr::from(0u64),
            )
            .unwrap(),
            wire_c_poly: blind_witness_polynomial(
                &raw_wire_polynomials.wire_c_poly,
                domain_size,
                Fr::from(17u64),
                Fr::from(0u64),
            )
            .unwrap(),
        };

        let beta = Fr::from(19u64);
        let gamma = Fr::from(23u64);
        let alpha = Fr::from(29u64);
        let zeta = Fr::from(31u64);
        let v = Fr::from(37u64);

        let grand_product_evaluations = compute_grand_product_evaluations(
            &witness_columns.wire_a_evaluations,
            &witness_columns.wire_b_evaluations,
            &witness_columns.wire_c_evaluations,
            &sigma_mapping,
            beta,
            gamma,
        )
        .unwrap();
        let raw_grand_product_polynomial = interpolate_grand_product_evaluations(
            &grand_product_evaluations.grand_product_evaluations,
            domain_size,
        )
        .unwrap();
        let grand_product_polynomial = blind_grand_product_polynomial(
            &raw_grand_product_polynomial,
            domain_size,
            Fr::from(41u64),
            Fr::from(43u64),
            Fr::from(47u64),
        )
        .unwrap();

        let quotient_inputs = QuotientInputs::new(
            witness_columns,
            selector_columns,
            sigma_mapping,
            grand_product_evaluations,
        )
        .unwrap();
        let quotient_polynomial = compute_blinded_quotient_polynomial(
            &quotient_inputs,
            &[],
            alpha,
            beta,
            gamma,
            &wire_polynomials,
            &grand_product_polynomial,
        )
        .unwrap();
        let quotient_chunks = rerandomize_quotient_chunks(
            &split_quotient_polynomial(&quotient_polynomial, domain_size).unwrap(),
            domain_size,
            Fr::from(53u64),
            Fr::from(59u64),
        )
        .unwrap();

        let shifted_zeta = domain.group_gen() * zeta;
        let evaluations_at_zeta =
            evaluate_opening_payload(&wire_polynomials, &sigma_tag_polynomials, zeta);
        let shifted_value = grand_product_polynomial.evaluate(&shifted_zeta);

        let linearization_polynomial = build_linearization_polynomial(
            &domain,
            &selector_polynomials.q_l,
            &selector_polynomials.q_r,
            &selector_polynomials.q_o,
            &selector_polynomials.q_m,
            &selector_polynomials.q_c,
            &sigma_tag_polynomials.wire_c,
            &grand_product_polynomial,
            &quotient_chunks,
            &[],
            alpha,
            beta,
            gamma,
            zeta,
            evaluations_at_zeta.wire_a,
            evaluations_at_zeta.wire_b,
            evaluations_at_zeta.wire_c,
            evaluations_at_zeta.sigma_1,
            evaluations_at_zeta.sigma_2,
            shifted_value,
        );
        let w_z_polynomial = build_w_z_polynomial(
            &linearization_polynomial,
            &wire_polynomials,
            &sigma_tag_polynomials,
            &evaluations_at_zeta,
            zeta,
            v,
        )
        .unwrap();

        let same_point_polynomial = linearization_polynomial.clone()
            + scale_polynomial(&wire_polynomials.wire_a_poly, v)
            + scale_polynomial(&wire_polynomials.wire_b_poly, v * v)
            + scale_polynomial(&wire_polynomials.wire_c_poly, v * v * v)
            + scale_polynomial(&sigma_tag_polynomials.wire_a, v * v * v * v)
            + scale_polynomial(&sigma_tag_polynomials.wire_b, v * v * v * v * v);
        let direct_commitment = commit_polynomial(&same_point_polynomial, &srs).unwrap();
        let verifier_style_commitment = Commitment::from_projective(
            commit_polynomial(&linearization_polynomial, &srs)
                .unwrap()
                .point
                .into_group()
                + commit_polynomial(&wire_polynomials.wire_a_poly, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * v
                + commit_polynomial(&wire_polynomials.wire_b_poly, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * (v * v)
                + commit_polynomial(&wire_polynomials.wire_c_poly, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * (v * v * v)
                + commit_polynomial(&sigma_tag_polynomials.wire_a, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * (v * v * v * v)
                + commit_polynomial(&sigma_tag_polynomials.wire_b, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * (v * v * v * v * v),
        );

        assert_eq!(direct_commitment, verifier_style_commitment);
        assert!(
            verify_opening(
                &direct_commitment,
                zeta,
                same_point_polynomial.evaluate(&zeta),
                &OpeningProof::new(commit_polynomial(&w_z_polynomial, &srs).unwrap()),
                &srs,
            )
            .unwrap()
        );
    }

    #[test]
    fn same_point_opening_stays_consistent_with_public_inputs_and_copy_constraints() {
        let left_public_input = Fr::from(5u64);
        let right_public_input = Fr::from(9u64);
        let public_inputs = vec![left_public_input, right_public_input];
        let sum = left_public_input + right_public_input;
        let mut circuit = Circuit::new();
        circuit
            .add_gate(
                left_public_input,
                Fr::from(0u64),
                Fr::from(0u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit
            .add_gate(
                right_public_input,
                Fr::from(0u64),
                Fr::from(0u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit
            .add_gate(
                left_public_input,
                right_public_input,
                sum,
                Fr::from(1u64),
                Fr::from(1u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit.pad_to_domain();

        let copy_constraints = vec![
            CopyConstraint {
                left: crate::permutation::Pos {
                    col: crate::permutation::Column::A,
                    row: 0,
                },
                right: crate::permutation::Pos {
                    col: crate::permutation::Column::A,
                    row: 2,
                },
            },
            CopyConstraint {
                left: crate::permutation::Pos {
                    col: crate::permutation::Column::A,
                    row: 1,
                },
                right: crate::permutation::Pos {
                    col: crate::permutation::Column::B,
                    row: 2,
                },
            },
        ];

        let domain_size = circuit.domain_size().unwrap();
        let domain = build_domain_from_size(domain_size).unwrap();
        let srs = KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two()).unwrap();
        let witness_columns = WitnessColumns::from_padded_circuit(&circuit).unwrap();
        let selector_columns = SelectorColumns::from_padded_circuit(&circuit).unwrap();
        let raw_wire_polynomials =
            interpolate_witness_column_polynomials(&domain, &witness_columns).unwrap();
        let selector_polynomials = build_selector_polynomials(&domain, &selector_columns).unwrap();
        let sigma_mapping =
            build_sigma_from_copy_constraints(domain_size, &copy_constraints).unwrap();
        let sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping).unwrap();

        let wire_polynomials = WitnessPolynomials {
            wire_a_poly: blind_witness_polynomial(
                &raw_wire_polynomials.wire_a_poly,
                domain_size,
                Fr::from(11u64),
                Fr::from(0u64),
            )
            .unwrap(),
            wire_b_poly: blind_witness_polynomial(
                &raw_wire_polynomials.wire_b_poly,
                domain_size,
                Fr::from(13u64),
                Fr::from(0u64),
            )
            .unwrap(),
            wire_c_poly: blind_witness_polynomial(
                &raw_wire_polynomials.wire_c_poly,
                domain_size,
                Fr::from(17u64),
                Fr::from(0u64),
            )
            .unwrap(),
        };

        let transcript_input = build_transcript_preprocessed_input(
            &domain,
            &selector_polynomials,
            &sigma_tag_polynomials,
            &srs,
        )
        .unwrap();
        let wire_commitments = commit_wire_polynomials(&wire_polynomials, &srs).unwrap();
        let mut transcript = Transcript::default();
        transcript.absorb_phase_9_preprocessed_input(&transcript_input);
        transcript.absorb_plonk_public_inputs(public_inputs.as_slice());
        transcript.absorb_plonk_wire_commitments(&wire_commitments);
        let beta = transcript.challenge_scalar(b"beta");
        let gamma = transcript.challenge_scalar(b"gamma");

        let grand_product_evaluations = compute_grand_product_evaluations(
            &witness_columns.wire_a_evaluations,
            &witness_columns.wire_b_evaluations,
            &witness_columns.wire_c_evaluations,
            &sigma_mapping,
            beta,
            gamma,
        )
        .unwrap();
        let raw_grand_product_polynomial = interpolate_grand_product_evaluations(
            &grand_product_evaluations.grand_product_evaluations,
            domain_size,
        )
        .unwrap();
        let grand_product_polynomial = blind_grand_product_polynomial(
            &raw_grand_product_polynomial,
            domain_size,
            Fr::from(41u64),
            Fr::from(43u64),
            Fr::from(47u64),
        )
        .unwrap();
        let grand_product_commitment = commit_polynomial(&grand_product_polynomial, &srs).unwrap();
        transcript.absorb_plonk_grand_product_commitment(&grand_product_commitment);
        let alpha = transcript.challenge_scalar(b"alpha");

        let quotient_inputs = QuotientInputs::new(
            witness_columns,
            selector_columns,
            sigma_mapping,
            grand_product_evaluations,
        )
        .unwrap();
        let quotient_polynomial = compute_blinded_quotient_polynomial(
            &quotient_inputs,
            public_inputs.as_slice(),
            alpha,
            beta,
            gamma,
            &wire_polynomials,
            &grand_product_polynomial,
        )
        .unwrap();
        let quotient_chunks = rerandomize_quotient_chunks(
            &split_quotient_polynomial(&quotient_polynomial, domain_size).unwrap(),
            domain_size,
            Fr::from(53u64),
            Fr::from(59u64),
        )
        .unwrap();
        let quotient_chunk_commitments =
            commit_quotient_chunks(&quotient_chunks, &quotient_polynomial, &srs).unwrap();
        transcript.absorb_phase_9_quotient_chunk_commitments(&quotient_chunk_commitments);
        let zeta = transcript.challenge_scalar(b"zeta");
        let shifted_zeta = domain.group_gen() * zeta;
        let evaluations_at_zeta =
            evaluate_opening_payload(&wire_polynomials, &sigma_tag_polynomials, zeta);
        let shifted_value = grand_product_polynomial.evaluate(&shifted_zeta);
        let shifted_evaluations = ShiftedEvaluations::new(shifted_value);
        transcript.absorb_phase_9_evaluations(&evaluations_at_zeta, &shifted_evaluations);
        let v = transcript.challenge_scalar(b"v");

        let linearization_polynomial = build_linearization_polynomial(
            &domain,
            &selector_polynomials.q_l,
            &selector_polynomials.q_r,
            &selector_polynomials.q_o,
            &selector_polynomials.q_m,
            &selector_polynomials.q_c,
            &sigma_tag_polynomials.wire_c,
            &grand_product_polynomial,
            &quotient_chunks,
            public_inputs.as_slice(),
            alpha,
            beta,
            gamma,
            zeta,
            evaluations_at_zeta.wire_a,
            evaluations_at_zeta.wire_b,
            evaluations_at_zeta.wire_c,
            evaluations_at_zeta.sigma_1,
            evaluations_at_zeta.sigma_2,
            shifted_value,
        );
        let w_z_polynomial = build_w_z_polynomial(
            &linearization_polynomial,
            &wire_polynomials,
            &sigma_tag_polynomials,
            &evaluations_at_zeta,
            zeta,
            v,
        )
        .unwrap();

        let same_point_polynomial = linearization_polynomial.clone()
            + scale_polynomial(&wire_polynomials.wire_a_poly, v)
            + scale_polynomial(&wire_polynomials.wire_b_poly, v * v)
            + scale_polynomial(&wire_polynomials.wire_c_poly, v * v * v)
            + scale_polynomial(&sigma_tag_polynomials.wire_a, v * v * v * v)
            + scale_polynomial(&sigma_tag_polynomials.wire_b, v * v * v * v * v);
        let verifier_style_commitment = Commitment::from_projective(
            commit_polynomial(&linearization_polynomial, &srs)
                .unwrap()
                .point
                .into_group()
                + wire_commitments[0].point.into_group() * v
                + wire_commitments[1].point.into_group() * (v * v)
                + wire_commitments[2].point.into_group() * (v * v * v)
                + commit_polynomial(&sigma_tag_polynomials.wire_a, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * (v * v * v * v)
                + commit_polynomial(&sigma_tag_polynomials.wire_b, &srs)
                    .unwrap()
                    .point
                    .into_group()
                    * (v * v * v * v * v),
        );
        let direct_commitment = commit_polynomial(&same_point_polynomial, &srs).unwrap();

        assert_eq!(direct_commitment, verifier_style_commitment);

        assert!(
            verify_opening(
                &direct_commitment,
                zeta,
                same_point_polynomial.evaluate(&zeta),
                &OpeningProof::new(commit_polynomial(&w_z_polynomial, &srs).unwrap()),
                &srs,
            )
            .unwrap()
        );
    }

    #[test]
    fn prove_and_verify_stay_consistent_with_prover_side_fixed_data_construction() {
        let left_public_input = Fr::from(5u64);
        let right_public_input = Fr::from(9u64);
        let public_inputs = vec![left_public_input, right_public_input];
        let sum = left_public_input + right_public_input;
        let mut circuit = Circuit::new();
        circuit
            .add_gate(
                left_public_input,
                Fr::from(0u64),
                Fr::from(0u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit
            .add_gate(
                right_public_input,
                Fr::from(0u64),
                Fr::from(0u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit
            .add_gate(
                left_public_input,
                right_public_input,
                sum,
                Fr::from(1u64),
                Fr::from(1u64),
                -Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(0u64),
            )
            .unwrap();
        circuit.pad_to_domain();

        let copy_constraints = vec![
            CopyConstraint {
                left: crate::permutation::Pos {
                    col: crate::permutation::Column::A,
                    row: 0,
                },
                right: crate::permutation::Pos {
                    col: crate::permutation::Column::A,
                    row: 2,
                },
            },
            CopyConstraint {
                left: crate::permutation::Pos {
                    col: crate::permutation::Column::A,
                    row: 1,
                },
                right: crate::permutation::Pos {
                    col: crate::permutation::Column::B,
                    row: 2,
                },
            },
        ];

        let domain_size = circuit.domain_size().unwrap();
        let domain = build_domain_from_size(domain_size).unwrap();
        let srs = KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two()).unwrap();
        let selector_columns = SelectorColumns::from_padded_circuit(&circuit).unwrap();
        let selector_polynomials = build_selector_polynomials(&domain, &selector_columns).unwrap();
        let sigma_mapping =
            build_sigma_from_copy_constraints(domain_size, &copy_constraints).unwrap();
        let sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping).unwrap();
        let verifier_input = VerifierPreprocessedInput::new(
            domain_params(&domain),
            selector_polynomials,
            sigma_tag_polynomials,
            VerifierProtocolParams::new(3, [Fr::from(1u64), Fr::from(K1), Fr::from(K2)]),
        );

        let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs).unwrap();
        assert!(verify(&proof, public_inputs.as_slice(), &verifier_input, &srs).unwrap());
    }
}
