//! Step 8.1: Plonk prover orchestration.
//!
//! This module only stitches together the components that were already
//! implemented in Phase 1-7. It does not reimplement quotient, permutation,
//! transcript, or KZG math.

use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Polynomial};

use crate::{
    cs::{Circuit, SelectorColumns},
    domain::{PlonkDomain, build_domain_from_size},
    error::Result,
    kzg::{KzgSrs, commit_polynomial, open_polynomial_at_point, open_polynomials_at_same_point},
    permutation::{
        CopyConstraint, build_sigma_from_copy_constraints, compute_grand_product_evaluations,
        grand_product::compute_sigma_tag_evaluations_for_quotient,
        interpolate_grand_product_evaluations,
    },
    quotient::compute_step_5_1,
    transcript::Transcript,
    types::{EvaluationsAtZeta, PlonkProof, QuotientInputs, ShiftedEvaluations, SigmaTagPolynomials},
    validate::ensure,
    witness::{
        WitnessColumns, WitnessPolynomials, interpolate_column_evaluations,
        interpolate_witness_column_polynomials,
    },
};

/// 功能说明：按 Step 8.1 固定流程生成当前版本的最小 `PlonkProof`。
/// 输入：已经 `pad_to_domain()` 并冻结的电路、copy constraints、公开输入和 KZG SRS。
/// 输出：符合 Step 7.1 冻结格式的 `PlonkProof`。
/// 示例：`let proof = prove(&circuit, &copy_constraints, public_inputs, &srs)?;`
pub fn prove(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint], // 只输入有连线的permutation约束，空白位置默认不连线。
    public_inputs: Vec<crate::curve::Fr>,
    srs: &KzgSrs,
) -> Result<PlonkProof> {
    // Paper mapping: prover preprocessing before transcript rounds.
    // Repo role: normalize the circuit into the fixed H-domain view used by later modules.
    // Step 8.1 的第一条基本要求：电路必须已经调用过 `pad_to_domain()` 进入冻结状态。
    ensure(
        circuit.is_frozen(),
        "circuit must call pad_to_domain() before prove()",
    )?;
    // Step 8.1 的第二条基本要求：电路必须在冻结时记录 domain 大小，供后续构建 domain 和 sigma tag 多项式使用。
    let domain_size = circuit
        .domain_size()
        .expect("frozen circuit must record domain size");
    let domain = build_domain_from_size(domain_size)?;
    //  evaluations 形式
    let witness_columns = WitnessColumns::from_padded_circuit(circuit)?;
    let selector_columns = SelectorColumns::from_padded_circuit(circuit)?;
    // 多项式形式
    let wire_polynomials = interpolate_witness_column_polynomials(&domain, &witness_columns)?;
    //
    // Paper mapping: Prover Round 1, witness commitments A(X), B(X), C(X).
    let wire_commitments = commit_wire_polynomials(&wire_polynomials, srs)?;

    // 
    let mut transcript = Transcript::default();
    transcript.absorb_plonk_wire_commitments(&wire_commitments);
    transcript.absorb_plonk_public_inputs(&public_inputs);
    // Paper mapping: transcript transition from Round 1 to Round 2, derive beta and gamma after A/B/C commitments.
    let beta = transcript.challenge_scalar(b"beta");
    let gamma = transcript.challenge_scalar(b"gamma");


    // sigma_mapping构建，这里面只是记录位置
    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)?;
    // 当前 Step 8.1 不把 sigma tag 放进 proof，但 prover 仍按固定数据流显式构造它们。

    // coeff形式 执行这一步仅仅构造/校验流程
    let _sigma_tag_polynomials = build_sigma_tag_polynomials(&domain, &sigma_mapping)?;

    // Paper mapping: Prover Round 2, grand product recurrence for permutation.
    //  evaluations，长度为 n + 1，最后一项要返回1
    let grand_product_evaluations = compute_grand_product_evaluations(
        &witness_columns.wire_a_evaluations,
        &witness_columns.wire_b_evaluations,
        &witness_columns.wire_c_evaluations,
        &sigma_mapping,
        beta,
        gamma,
    )?;
    // ifft到多项式（这里只用了前n个evaluations，最后一个1不参与IFFT）
    let grand_product_polynomial = interpolate_grand_product_evaluations(
        &grand_product_evaluations.grand_product_evaluations,
        domain_size,
    )?;
    // round的commit
    let grand_product_commitment = commit_polynomial(&grand_product_polynomial, srs)?;


    // Paper mapping: transcript transition from Round 2 to Round 3, derive alpha after Z commitment.
    transcript.absorb_plonk_grand_product_commitment(&grand_product_commitment);
    let alpha = transcript.challenge_scalar(b"alpha");

    // 
    let quotient_inputs = QuotientInputs::new(
        witness_columns,
        selector_columns,
        sigma_mapping,
        grand_product_evaluations,
    )?;
    // Paper mapping: Prover Round 3, quotient identity assembly.
    // Repo role: reuse Step 5.1 instead of reimplementing gate/permutation algebra here.
    let quotient_output =
        compute_step_5_1(&quotient_inputs, public_inputs.as_slice(), alpha, beta, gamma)?;
    ensure(
        quotient_output
            .h_domain
            .numerator_evaluations
            .iter()
            .all(|value| value.is_zero()),
        "circuit witness, copy constraints, and public_inputs must satisfy Plonk constraints",
    )?; // 确保在源domain上 T(X) 的 numerator 是零多项式，证明电路约束被满足。（因为此时还没有加上blinding项，如果加上了就无法验证了，因为不会直接在domain上计算）
    let quotient_polynomial = quotient_output.extended_domain.quotient_polynomial;
    // 当前版本只有单个 T(X) commitment，次数超出 SRS 时必须直接报错，不能临时分块。
    // 注意，原论文是允许分块的，但这会增加实现复杂度，且不符合我们 minimal 的初衷。但是后续的blinding步骤仍然需要分块，所以如果不分块的话，SRS的规模就必须足够大，才能支持足够大的电路。
    srs.validate_polynomial_degree(quotient_polynomial.degree())?;
    let quotient_commitment = commit_polynomial(&quotient_polynomial, srs)?;

    // Paper mapping: transcript transition from Round 3 to Round 4, derive zeta after T commitment.
    transcript.absorb_plonk_quotient_commitment(&quotient_commitment);
    let zeta = transcript.challenge_scalar(b"zeta");

    let omega = domain.element(1);
    let shifted_zeta = omega * zeta;
    // Paper mapping: Prover Round 4
    let (evaluations_at_zeta, shifted_evaluations) = evaluate_opening_points(
        &wire_polynomials,
        &grand_product_polynomial,
        &quotient_polynomial,
        zeta,
        shifted_zeta,
    );

    // Paper mapping: Prover Round 4 to 5。
    transcript.absorb_plonk_evaluations(&evaluations_at_zeta, &shifted_evaluations);
    let v = transcript.challenge_scalar(b"v");

    // Paper mapping: Prover Round 5, opening proofs prepared from the round-4 claims.
    let opening_at_zeta = open_polynomials_at_same_point(
        &[
            wire_polynomials.wire_a_poly.clone(),
            wire_polynomials.wire_b_poly.clone(),
            wire_polynomials.wire_c_poly.clone(),
            grand_product_polynomial.clone(),
            quotient_polynomial.clone(),
        ],
        zeta,
        v,
        srs,
    )?;
    let opening_at_shifted_zeta =
        open_polynomial_at_point(&grand_product_polynomial, shifted_zeta, srs)?;

    Ok(PlonkProof::new(
        wire_commitments,
        grand_product_commitment,
        quotient_commitment,
        public_inputs,
        evaluations_at_zeta,
        shifted_evaluations,
        opening_at_zeta.proof,
        opening_at_shifted_zeta.proof,
    ))
}

/// 功能说明：把 witness 三列多项式按固定顺序做 KZG commitment。
/// 输入：`A(X) / B(X) / C(X)` 三个 witness 多项式和 SRS。
/// 输出：固定顺序的 `[A_commitment, B_commitment, C_commitment]`。
/// 示例：该结果会先进入 transcript，再导出 `beta/gamma`。
fn commit_wire_polynomials(
    wire_polynomials: &WitnessPolynomials,
    srs: &KzgSrs,
) -> Result<[crate::types::Commitment; 3]> {
    // Paper mapping: fixed A/B/C commitment tuple that the transcript binds before beta/gamma.
    Ok([
        commit_polynomial(&wire_polynomials.wire_a_poly, srs)?,
        commit_polynomial(&wire_polynomials.wire_b_poly, srs)?,
        commit_polynomial(&wire_polynomials.wire_c_poly, srs)?,
    ])
}

/// 功能说明：把 sigma mapping 对应的三列 tag evaluations 插值成多项式。
/// 输入：原始 H-domain 和已经验证过的 sigma mapping。
/// 输出：`SigmaTagPolynomials`，供当前 prover 数据流和未来 verifier 固定输入边界复用。
/// 示例：Step 8.1 中它不进入 proof，但会在 prover 端被显式构造。
fn build_sigma_tag_polynomials(
    domain: &PlonkDomain,
    sigma_mapping: &crate::permutation::SigmaMapping,
) -> Result<SigmaTagPolynomials> {
    // Paper mapping: sigma tag polynomials used by the quotient's permutation relation.
    // 返回的是eval形式
    let sigma_tag_evaluations = compute_sigma_tag_evaluations_for_quotient(domain, sigma_mapping)?;
    Ok(SigmaTagPolynomials::new(
        // ifft为coeff形式
        interpolate_column_evaluations(domain, &sigma_tag_evaluations.sigma_a_evaluations)?,
        interpolate_column_evaluations(domain, &sigma_tag_evaluations.sigma_b_evaluations)?,
        interpolate_column_evaluations(domain, &sigma_tag_evaluations.sigma_c_evaluations)?,
    ))
}

/// 功能说明：计算当前 opening 计划需要写入 proof 的所有 claimed evaluations。
/// 输入：`A/B/C/Z/T` 多项式、主挑战点 `zeta` 和移位点 `omega * zeta`。
/// 输出：`EvaluationsAtZeta` 与 `ShiftedEvaluations` 两个固定结构。
/// 示例：这些值会先被 transcript 吸收，再导出 `v`。
fn evaluate_opening_points(
    wire_polynomials: &WitnessPolynomials,
    grand_product_polynomial: &ark_poly::univariate::DensePolynomial<crate::curve::Fr>,
    quotient_polynomial: &ark_poly::univariate::DensePolynomial<crate::curve::Fr>,
    zeta: crate::curve::Fr,
    shifted_zeta: crate::curve::Fr,
) -> (EvaluationsAtZeta, ShiftedEvaluations) {
    // Paper mapping: evaluation targets a(zeta), b(zeta), c(zeta), Z(zeta), T(zeta), Z(omega*zeta).
    (
        EvaluationsAtZeta::new(
            wire_polynomials.wire_a_poly.evaluate(&zeta),
            wire_polynomials.wire_b_poly.evaluate(&zeta),
            wire_polynomials.wire_c_poly.evaluate(&zeta),
            grand_product_polynomial.evaluate(&zeta),
            quotient_polynomial.evaluate(&zeta),
        ),
        ShiftedEvaluations::new(grand_product_polynomial.evaluate(&shifted_zeta)),
    )
}
