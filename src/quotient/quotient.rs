//! Step 5.1: quotient polynomial 的两层实现。
//!
//! 这一版明确分成两层：
//! 1) H-domain 约束检查层：只检查 gate / permutation / boundary 聚合后在 H 上是否为 0
//! 2) extended-domain quotient 构造层：在扩展 coset domain 上构造真实 numerator / quotient

use ark_ff::{FftField, Field, Zero};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, univariate::DensePolynomial};

use crate::{
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, evaluations_to_polynomial},
    error::{PlonkError, Result},
    permutation::{
        K1, K2, compute_row_terms_for_quotient,
        grand_product::compute_sigma_tag_evaluations_for_quotient,
        interpolate_grand_product_evaluations,
    },
    types::QuotientInputs,
    validate::ensure,
    witness::WitnessPolynomials as BlindedWitnessPolynomials,
};

/// Step 5.1 在原始 H-domain 上的约束检查输出。
///
/// 这层只回答一个问题：
/// “聚合后的 numerator 在 H 上是不是全为 0？”
///
/// 这里所有向量长度都等于原始 `n = inputs.domain_size`，
/// 它们对应的点是 `H = {omega^0, omega^1, ..., omega^(n-1)}`。
///
/// 注意：
/// - 这一层不能恢复真实的高次数 numerator polynomial
/// - 这一层也不做 quotient 除法
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HDomainConstraintEvaluations {
    /// 原始约束域 H 的大小。
    pub domain_size: usize,
    /// gate 约束在 H 上每个点的值。
    pub gate_term_evaluations: Vec<Fr>,
    pub public_input_term_evaluations: Vec<Fr>,
    /// permutation recursion 零化式在 H 上每个点的值。
    pub permutation_term_evaluations: Vec<Fr>,
    /// `Z(1) = 1` 这条 boundary 约束在 H 上的编码结果。
    pub boundary_term_1_evaluations: Vec<Fr>,
    /// `Z(omega^n) = 1` 这条 closing boundary 约束在 H 上的编码结果。
    pub boundary_term_2_evaluations: Vec<Fr>,
    /// 按 alpha 幂次聚合后的 numerator 在 H 上的值。
    pub numerator_evaluations: Vec<Fr>,
}

/// Step 5.1 在扩展 quotient domain 上的真实构造输出。
///
/// 这层负责真正构造 quotient：
/// - 在扩展 coset domain 上评估真实 numerator(X)
/// - 在同一组点上评估原始 H 的 vanishing polynomial `Z_H(X)`
/// - 做逐点除法得到 quotient evaluations
/// - 最后插值成 quotient polynomial
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedDomainQuotientComputation {
    /// 原始约束域 H 的大小，也就是电路 padding 后的行数。
    pub original_domain_size: usize,
    /// quotient 构造使用的扩展 coset domain 大小。
    pub extended_domain_size: usize,
    /// gate 约束在扩展 domain 上的 evaluations。
    pub gate_term_evaluations: Vec<Fr>,
    pub public_input_term_evaluations: Vec<Fr>,
    /// permutation 约束在扩展 domain 上的 evaluations。
    pub permutation_term_evaluations: Vec<Fr>,
    /// 第一个 boundary 约束在扩展 domain 上的 evaluations。
    pub boundary_term_1_evaluations: Vec<Fr>,
    /// 第二个 boundary 约束在扩展 domain 上的 evaluations。
    pub boundary_term_2_evaluations: Vec<Fr>,
    /// 聚合后的真实 numerator 在扩展 domain 上的 evaluations。
    pub numerator_evaluations: Vec<Fr>,
    /// 由扩展 domain 上的 numerator evaluations 插值得到的 numerator polynomial。
    pub numerator_polynomial: DensePolynomial<Fr>,
    /// 原始 H 的 vanishing polynomial 在扩展 domain 上的 evaluations。
    pub vanishing_evaluations: Vec<Fr>,
    /// pointwise `numerator / Z_H` 得到的 quotient evaluations。
    pub quotient_evaluations: Vec<Fr>, // （这个是在coset上评估的，不是原始H上的）
    /// 由 quotient evaluations 插值得到的 quotient polynomial。
    pub quotient_polynomial: DensePolynomial<Fr>,
}

/// Step 5.1 的总输出。
///
/// 它同时保留：
/// - H-domain 的零性检查结果
/// - extended-domain 的 quotient 构造结果
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step5_1QuotientOutput {
    pub h_domain: HDomainConstraintEvaluations,
    pub extended_domain: ExtendedDomainQuotientComputation,
}

/// Step 5.1 的内部辅助结构。
///
/// 它只服务于本文件内部的 quotient 构造流程，不作为长期公共 API 暴露。
#[derive(Clone, Debug, PartialEq, Eq)]
struct Step5_1Polynomials {
    witness_polynomials: WitnessPolynomials,
    selector_polynomials: SelectorPolynomials,
    public_input_polynomial: DensePolynomial<Fr>,
    sigma_tag_polynomials: SigmaTagPolynomials,
    z_polynomial: DensePolynomial<Fr>,
    l_0_polynomial: DensePolynomial<Fr>,
    l_n_minus_1_polynomial: DensePolynomial<Fr>,
}

/// witness 三列多项式。
#[derive(Clone, Debug, PartialEq, Eq)]
struct WitnessPolynomials {
    wire_a_polynomial: DensePolynomial<Fr>,
    wire_b_polynomial: DensePolynomial<Fr>,
    wire_c_polynomial: DensePolynomial<Fr>,
}

/// selector 五列多项式。
#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectorPolynomials {
    q_l_polynomial: DensePolynomial<Fr>,
    q_r_polynomial: DensePolynomial<Fr>,
    q_o_polynomial: DensePolynomial<Fr>,
    q_m_polynomial: DensePolynomial<Fr>,
    q_c_polynomial: DensePolynomial<Fr>,
}

/// sigma 三列 tag 多项式。
#[derive(Clone, Debug, PartialEq, Eq)]
struct SigmaTagPolynomials {
    sigma_a_polynomial: DensePolynomial<Fr>,
    sigma_b_polynomial: DensePolynomial<Fr>,
    sigma_c_polynomial: DensePolynomial<Fr>,
}

/// 功能说明：构造 quotient 计算专用的扩展 coset domain。
/// 输入：原始约束域大小 `n`。
/// 输出：大小为 `next_power_of_two(8 * n)` 的 coset domain。
/// 示例：当 `n = 8` 时，扩展大小为 64。
/// 功能说明：构造商多项式（t）计算专用的“扩展陪集域 (Extended Coset Domain)”。
/// 核心背景：
/// 1. Plonk 的约束包含 a(x)*b(x)*q_m(x)，阶数约为 3n，聚合后可能接近 4n。
/// 2. 我们要做除法 t(x) = Num(x) / (x^n - 1)，必须在点值上进行（速度快）。
pub fn build_extended_quotient_domain(domain_size: usize) -> Result<PlonkDomain> {
    // 安全检查：电路行数不能为 0
    ensure(domain_size > 0, "domain_size must be positive")?;

    // --- 第一步：确定“分辨率”（采样点数） ---
    // 为什么要乘 4？
    // 为了满足 FFT 的计算分辨率，采样点数必须 > 3n。为了代码方便，选 4n。
    let minimum_extended_size = domain_size
        .checked_mul(8)
        .ok_or(PlonkError::InvalidInput("扩展域计算规模溢出"))?;

    // --- 第二步：对齐到 2 的幂次 ---
    let extended_size = minimum_extended_size.next_power_of_two();

    // --- 第三步：创建基础子群 (Subgroup) ---
    // 此时建立的是一个标准坐标系 H_ext = {1, g, g^2, g^3, ... }
    // 其中 g 是一个单位原根，满足 g^extended_size = 1。
    let subgroup_domain = build_domain_from_size(extended_size)?;

    // --- 第四步：平移域（核心动作：get_coset） ---
    // 直接使用 Fr::GENERATOR 作为偏移因子，构造一个陪集域 H_ext' = {g^i * offset | i=0..extended_size-1}。
    // 注意：这个偏移因子必须不在原始 H 上，否则会导致扩展域与原始域重叠，无法正确进行商多项式计算。
    subgroup_domain
        .get_coset(Fr::GENERATOR)
        .ok_or(PlonkError::InvalidInput(
            "无法构造扩展陪集域（可能是由于偏移因子选取不当）",
        ))
}

/// 功能说明：在原始 H-domain 上计算 Step 5.1 的约束检查输出。
/// 输入：统一的 `QuotientInputs` 与 `alpha/beta/gamma`。
/// 输出：`HDomainConstraintEvaluations`。
/// 示例：正确 witness 时 `numerator_evaluations` 应在 H 上全为 0。
/// plonk的round3部分
pub fn compute_h_domain_constraint_evaluations(
    inputs: &QuotientInputs,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
) -> Result<HDomainConstraintEvaluations> {
    // Paper mapping: corresponds to the quotient-identity stage of the prover.
    // Repo role: this repository first checks the aggregated numerator directly on H for readability.
    let domain_size = inputs.domain_size;
    ensure(domain_size > 0, "domain_size must be positive")?;

    let z_evaluations = &inputs.grand_product_evaluations.grand_product_evaluations;
    ensure(
        z_evaluations.len() == domain_size + 1,
        "grand product evaluations length must equal domain_size + 1",
    )?;

    let original_domain = build_domain_from_size(domain_size)?;
    // gate约束
    let gate_term_evaluations = compute_gate_term_evaluations_on_h(inputs)?;
    let public_input_term_evaluations = build_public_input_evaluations(domain_size, public_inputs)?;
    // permutation约束
    let permutation_term_evaluations =
        compute_permutation_term_evaluations_on_h(inputs, &original_domain, beta, gamma)?;
    // boundary约束，比原文多了一个最后的校验点，确保 Z(omega^n) = 1 也被正确编码
    let (boundary_term_1_evaluations, boundary_term_2_evaluations) =
        compute_boundary_term_evaluations_on_h(inputs, &original_domain)?;

    let numerator_evaluations = aggregate_numerator_evaluations(
        &gate_term_evaluations,
        &public_input_term_evaluations,
        &permutation_term_evaluations,
        &boundary_term_1_evaluations,
        &boundary_term_2_evaluations,
        alpha,
    )?;

    Ok(HDomainConstraintEvaluations {
        domain_size,
        gate_term_evaluations,
        public_input_term_evaluations,
        permutation_term_evaluations,
        boundary_term_1_evaluations,
        boundary_term_2_evaluations,
        numerator_evaluations,
    })
}

/// 功能说明：在扩展 quotient domain 上构造真实 quotient。
/// 输入：统一的 `QuotientInputs` 与 `alpha/beta/gamma`。
/// 输出：`ExtendedDomainQuotientComputation`。
/// 示例：可用于检查 `quotient_poly * Z_H(X) == numerator_poly`。
pub fn compute_extended_domain_quotient(
    inputs: &QuotientInputs,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
) -> Result<ExtendedDomainQuotientComputation> {
    // Paper mapping: corresponds to the prover-side quotient witness T(X).
    // Repo role: this repository builds that witness on an extended domain after the separate H-domain check.
    let original_domain_size = inputs.domain_size;
    let original_domain = build_domain_from_size(original_domain_size)?;
    let extended_domain = build_extended_quotient_domain(original_domain_size)?;
    // 把所有点值插值成多项式，因为后续要在coset上评估，而不是在H上复用 evaluations 了。
    // 目前是在H上的多项式形式，包括了[1,0,0,...]和[0,0,...,1]的插值多项式。
    let polynomials = interpolate_step_5_1_polynomials(inputs, public_inputs, &original_domain)?;
    //gate约束
    let gate_term_evaluations =
        compute_gate_term_evaluations_on_extended_domain(&polynomials, &extended_domain);
    let public_input_term_evaluations =
        extend_poly_to_evals(&polynomials.public_input_polynomial, &extended_domain);
    //permutation约束
    let permutation_term_evaluations = compute_permutation_term_evaluations_on_extended_domain(
        &polynomials,
        &original_domain,
        &extended_domain,
        beta,
        gamma,
    );
    //boundary约束
    let (boundary_term_1_evaluations, boundary_term_2_evaluations) =
        compute_boundary_term_evaluations_on_extended_domain(
            &polynomials,
            &original_domain,
            &extended_domain,
        );
    // 分子
    let numerator_evaluations = aggregate_numerator_evaluations(
        &gate_term_evaluations,
        &public_input_term_evaluations,
        &permutation_term_evaluations,
        &boundary_term_1_evaluations,
        &boundary_term_2_evaluations,
        alpha,
    )?;
    // IFFT到多项式
    let numerator_polynomial = evaluations_to_polynomial(&extended_domain, &numerator_evaluations)?;

    // vanishing polynomial的 evaluations形式在coset上
    let vanishing_evaluations =
        evaluate_h_vanishing_on_extended_domain(&original_domain, &extended_domain);
    // 点值的逐点除法得到商多项式的 evaluations 形式
    let quotient_evaluations =
        compute_quotient_evaluations(&numerator_evaluations, &vanishing_evaluations)?;
    //IFFT得到商多项式的系数形式（即插值多项式）
    let quotient_polynomial = evaluations_to_polynomial(&extended_domain, &quotient_evaluations)?;

    Ok(ExtendedDomainQuotientComputation {
        original_domain_size,
        extended_domain_size: extended_domain.size(),
        gate_term_evaluations,
        public_input_term_evaluations,
        permutation_term_evaluations,
        boundary_term_1_evaluations,
        boundary_term_2_evaluations,
        numerator_evaluations,
        numerator_polynomial,
        vanishing_evaluations,
        quotient_evaluations,
        quotient_polynomial,
    })
}

/// 功能说明：执行 Step 5.1 的完整流程。
/// 输入：统一的 `QuotientInputs` 与 `alpha/beta/gamma`。
/// 输出：同时包含 H-domain 与 extended-domain 的结果。
/// 示例：测试中既可以检查 H 上全 0，也可以检查 quotient 重组关系。
pub fn compute_step_5_1(
    inputs: &QuotientInputs,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
) -> Result<Step5_1QuotientOutput> {
    // Paper mapping: corresponds to the quotient-identity stage of the prover.
    // Repo role: this repository groups an H-domain zero check together with the extended-domain T(X) witness.
    let h_domain =
        compute_h_domain_constraint_evaluations(inputs, public_inputs, alpha, beta, gamma)?;
    let extended_domain =
        compute_extended_domain_quotient(inputs, public_inputs, alpha, beta, gamma)?;

    Ok(Step5_1QuotientOutput {
        h_domain,
        extended_domain,
    })
}

/// 功能说明：使用 blinded `A/B/C` 与 blinded `Z(X)` 重新构造 prover 真实使用的 quotient polynomial。
/// 输入：Step 5.1 原始输入、外部 `public_inputs`、挑战、以及 blinded witness / grand-product polynomials。
/// 输出：与 blinded prover-side objects 一致的 `t(X)`。
/// 示例：Step 10.2 prover 在生成 blinded chunk commitments 前调用它。
pub fn compute_blinded_quotient_polynomial(
    inputs: &QuotientInputs,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    blinded_witness_polynomials: &BlindedWitnessPolynomials,
    blinded_grand_product_polynomial: &DensePolynomial<Fr>,
) -> Result<DensePolynomial<Fr>> {
    // Paper mapping: quotient witness must stay consistent with the blinded prover-side objects.
    // Repo role: keep the H-domain zero check unchanged, but rebuild the extended-domain quotient
    // from the blinded witness and grand-product polynomials.
    let original_domain = build_domain_from_size(inputs.domain_size)?;
    // 这个直接在coset extend群上了
    let extended_domain = build_extended_quotient_domain(inputs.domain_size)?;
    // （IFFT到原始 H 上）
    let mut polynomials =
        interpolate_step_5_1_polynomials(inputs, public_inputs, &original_domain)?;


    // 关键点，这里已经将round1和round2的多项式切换成了带上blinding了。
    // 修改round2和round1的多项式，因为加上blinding，所以次数会增加，只能在coset上计算。
    polynomials.witness_polynomials = WitnessPolynomials {
        wire_a_polynomial: blinded_witness_polynomials.wire_a_poly.clone(),
        wire_b_polynomial: blinded_witness_polynomials.wire_b_poly.clone(),
        wire_c_polynomial: blinded_witness_polynomials.wire_c_poly.clone(),
    };
    polynomials.z_polynomial = blinded_grand_product_polynomial.clone();

    // 计算第一行的点值（除了PI），但是没有多项式和分子
    let gate_term_evaluations =
        compute_gate_term_evaluations_on_extended_domain(&polynomials, &extended_domain);

    // public input的点值在coset上（应该也算第一行里面吧）
    let public_input_term_evaluations =
        extend_poly_to_evals(&polynomials.public_input_polynomial, &extended_domain);


    // 计算round3的第二行和第三行的evals，同理没有vanishing polynomial和alpha
    let permutation_term_evaluations = compute_permutation_term_evaluations_on_extended_domain(
        &polynomials,
        &original_domain,
        &extended_domain,
        beta,
        gamma,
    );

    // 计算round3的第四行，这个与原文稍微有一点出入，有两项，校验是不是一个cycle
    let (boundary_term_1_evaluations, boundary_term_2_evaluations) =
        compute_boundary_term_evaluations_on_extended_domain(
            &polynomials,
            &original_domain,
            &extended_domain,
        );



    // 计算整个分子
    let numerator_evaluations = aggregate_numerator_evaluations(
        &gate_term_evaluations,
        &public_input_term_evaluations,
        &permutation_term_evaluations,
        &boundary_term_1_evaluations,
        &boundary_term_2_evaluations,
        alpha,
    )?;
    // 计算分母了，也是点值
    let vanishing_evaluations =
        evaluate_h_vanishing_on_extended_domain(&original_domain, &extended_domain);




    // 还是点值
    let quotient_evaluations =
        compute_quotient_evaluations(&numerator_evaluations, &vanishing_evaluations)?;

    // IFFT
    evaluations_to_polynomial(&extended_domain, &quotient_evaluations)
}

/// 功能说明：把 Step 5.1 需要的各类 H-domain evaluations 插值成多项式。（IFFT到原始 H 上）
/// 输入：原始 `QuotientInputs` 与原始 H-domain。
/// 输出：内部使用的 `Step5_1Polynomials`。
/// 示例：extended-domain quotient 构造层会复用这些多项式。
fn interpolate_step_5_1_polynomials(
    inputs: &QuotientInputs,
    public_inputs: &[Fr],
    original_domain: &PlonkDomain,
) -> Result<Step5_1Polynomials> {
    // Paper mapping: prepares the polynomial inputs consumed by the quotient identity.
    // Repo role: converts row-wise data into polynomial form for the repository's extended-domain path.
    let witness_polynomials = WitnessPolynomials {
        wire_a_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.witness_columns.wire_a_evaluations,
        )?,
        wire_b_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.witness_columns.wire_b_evaluations,
        )?,
        wire_c_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.witness_columns.wire_c_evaluations,
        )?,
    };

    let selector_polynomials = SelectorPolynomials {
        q_l_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.selector_columns.q_l_evaluations,
        )?,
        q_r_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.selector_columns.q_r_evaluations,
        )?,
        q_o_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.selector_columns.q_o_evaluations,
        )?,
        q_m_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.selector_columns.q_m_evaluations,
        )?,
        q_c_polynomial: evaluations_to_polynomial(
            original_domain,
            &inputs.selector_columns.q_c_evaluations,
        )?,
    };

    let public_input_polynomial = evaluations_to_polynomial(
        original_domain,
        &build_public_input_evaluations(inputs.domain_size, public_inputs)?,
    )?;

    let sigma_tag_evaluations =
        compute_sigma_tag_evaluations_for_quotient(original_domain, &inputs.sigma_mapping)?;
    let sigma_tag_polynomials = SigmaTagPolynomials {
        sigma_a_polynomial: evaluations_to_polynomial(
            original_domain,
            &sigma_tag_evaluations.sigma_a_evaluations,
        )?,
        sigma_b_polynomial: evaluations_to_polynomial(
            original_domain,
            &sigma_tag_evaluations.sigma_b_evaluations,
        )?,
        sigma_c_polynomial: evaluations_to_polynomial(
            original_domain,
            &sigma_tag_evaluations.sigma_c_evaluations,
        )?,
    };

    let z_polynomial = interpolate_grand_product_evaluations(
        &inputs.grand_product_evaluations.grand_product_evaluations,
        inputs.domain_size,
    )?;

    //[1, 0, 0, 0, 0, 0, 0, 0] 和 [0, 0, 0, 0, 0, 0, 0, 1] 的插值多项式
    let l_0_polynomial = evaluations_to_polynomial(
        original_domain,
        &build_one_hot_selector(inputs.domain_size, 0)?,
    )?;
    let l_n_minus_1_polynomial = evaluations_to_polynomial(
        original_domain,
        &build_one_hot_selector(inputs.domain_size, inputs.domain_size - 1)?,
    )?;

    Ok(Step5_1Polynomials {
        witness_polynomials,
        selector_polynomials,
        public_input_polynomial,
        sigma_tag_polynomials,
        z_polynomial,
        l_0_polynomial,
        l_n_minus_1_polynomial,
    })
}

/// 功能说明：计算 gate 约束在 H 上的 evaluations。
/// 输入：`QuotientInputs`。
/// 输出：长度为 `n` 的 gate evaluations。
/// 示例：第 i 个位置对应第 i 行 gate 约束左边的值。
/// 鍔熻兘璇存槑锛氭寜褰撳墠鏈€灏忔柟妗堟瀯閫?public input contribution 鍦?H 涓婄殑 evaluations銆?///
/// 杈撳叆锛歞omain 澶у皬鍜屾寜 statement 椤哄簭鎺掑垪鐨?public inputs銆?///
/// 杈撳嚭锛氶暱搴︿负 `domain_size` 鐨?evaluations锛屽墠 `m` 涓偣鏄?public inputs锛屽叾浣欑偣涓?0銆?///
/// 绀轰緥锛氳嫢 `public_inputs = [7, 11]`锛屽垯 `PI(omega^0)=7, PI(omega^1)=11`銆?
fn build_public_input_evaluations(domain_size: usize, public_inputs: &[Fr]) -> Result<Vec<Fr>> {
    // Paper mapping: feeds the statement contribution into the quotient identity.
    // Implementation note: this is the repository's minimal public-input encoding, not a direct paper formula.
    ensure(
        public_inputs.len() <= domain_size,
        "public input length must not exceed domain_size",
    )?;

    let mut evaluations = vec![Fr::zero(); domain_size];
    for (index, public_input) in public_inputs.iter().enumerate() {
        evaluations[index] = *public_input;
    }
    Ok(evaluations)
}

fn compute_gate_term_evaluations_on_h(inputs: &QuotientInputs) -> Result<Vec<Fr>> {
    // Paper mapping: gate relation qM*a*b + qL*a + qR*b + qO*c + qC on each H row.
    let domain_size = inputs.domain_size;
    let witness = &inputs.witness_columns;
    let selector = &inputs.selector_columns;

    ensure(
        witness.wire_a_evaluations.len() == domain_size
            && witness.wire_b_evaluations.len() == domain_size
            && witness.wire_c_evaluations.len() == domain_size
            && selector.q_l_evaluations.len() == domain_size
            && selector.q_r_evaluations.len() == domain_size
            && selector.q_o_evaluations.len() == domain_size
            && selector.q_m_evaluations.len() == domain_size
            && selector.q_c_evaluations.len() == domain_size,
        "witness/selector evaluations must match domain_size",
    )?;

    let mut gate_term_evaluations = Vec::with_capacity(domain_size);
    for row_index in 0..domain_size {
        let a = witness.wire_a_evaluations[row_index];
        let b = witness.wire_b_evaluations[row_index];
        let c = witness.wire_c_evaluations[row_index];
        let q_l = selector.q_l_evaluations[row_index];
        let q_r = selector.q_r_evaluations[row_index];
        let q_o = selector.q_o_evaluations[row_index];
        let q_m = selector.q_m_evaluations[row_index];
        let q_c = selector.q_c_evaluations[row_index];
        gate_term_evaluations.push(q_m * a * b + q_l * a + q_r * b + q_o * c + q_c);
    }

    Ok(gate_term_evaluations)
}

/// 功能说明：在 H 上计算 permutation recursion 的零化式 evaluations。
/// 输入：`QuotientInputs`、原始 H-domain、`beta/gamma`。
/// 输出：长度为 `n` 的 permutation evaluations。
/// 示例：第 i 个位置是 `Z_eval[i+1] * denominator_i - Z_eval[i] * numerator_i`。
fn compute_permutation_term_evaluations_on_h(
    inputs: &QuotientInputs,
    original_domain: &PlonkDomain,
    beta: Fr,
    gamma: Fr,
) -> Result<Vec<Fr>> {
    // Paper mapping: grand product recurrence rewritten as a zero-check term on H.
    let domain_size = inputs.domain_size;
    let z_evaluations = &inputs.grand_product_evaluations.grand_product_evaluations;
    ensure(
        z_evaluations.len() == domain_size + 1,
        "grand product evaluations length must equal domain_size + 1",
    )?;

    let mut permutation_term_evaluations = Vec::with_capacity(domain_size);
    for row_index in 0..domain_size {
        let row_terms = compute_row_terms_for_quotient(
            original_domain,
            &inputs.sigma_mapping,
            row_index,
            inputs.witness_columns.wire_a_evaluations[row_index],
            inputs.witness_columns.wire_b_evaluations[row_index],
            inputs.witness_columns.wire_c_evaluations[row_index],
            beta,
            gamma,
        )?;
        permutation_term_evaluations.push(
            z_evaluations[row_index + 1] * row_terms.denominator
                - z_evaluations[row_index] * row_terms.numerator,
        );
    }

    Ok(permutation_term_evaluations)
}

/// 功能说明：在 H 上编码两个 boundary 约束。
/// 输入：`QuotientInputs` 与原始 H-domain。
/// 输出：两个长度为 `n` 的 boundary evaluations。
/// 示例：第二项只把 `Z_eval[n] - 1` 留在最后一个 H 点上。
fn compute_boundary_term_evaluations_on_h(
    inputs: &QuotientInputs,
    original_domain: &PlonkDomain,
) -> Result<(Vec<Fr>, Vec<Fr>)> {
    // Paper mapping: permutation boundary relations Z(1)=1 and Z(omega^n)=1.
    let domain_size = inputs.domain_size;
    let z_evaluations = &inputs.grand_product_evaluations.grand_product_evaluations;
    ensure(
        z_evaluations.len() == domain_size + 1,
        "grand product evaluations length must equal domain_size + 1",
    )?;
    let one = Fr::from(1u64);
    let l_0_evaluations = evaluate_selector_polynomial_on_original_domain(
        original_domain,
        &build_one_hot_selector(domain_size, 0)?,
    );
    let l_n_minus_1_evaluations = evaluate_selector_polynomial_on_original_domain(
        original_domain,
        &build_one_hot_selector(domain_size, domain_size - 1)?,
    );

    let mut boundary_term_1_evaluations = Vec::with_capacity(domain_size);
    let mut boundary_term_2_evaluations = Vec::with_capacity(domain_size);
    for row_index in 0..domain_size {
        let term_1 = (z_evaluations[row_index] - one) * l_0_evaluations[row_index];
        let term_2 = (z_evaluations[row_index + 1] - one) * l_n_minus_1_evaluations[row_index];
        boundary_term_1_evaluations.push(term_1);
        boundary_term_2_evaluations.push(term_2);
    }

    Ok((boundary_term_1_evaluations, boundary_term_2_evaluations))
}

/// 功能说明：在扩展 domain 上计算 gate 约束的真实 evaluations。
/// 输入：内部多项式包与扩展 domain。
/// 输出：长度为扩展域大小的 gate evaluations。
/// 示例：每个位置都通过直接评估多项式得到，而不是来自 H 上的复用。
/// 这个函数是便于理解，实际是用compute_gate_term_evaluations_on_extended_domain函数好点，这样会加快这个函数
fn compute_gate_term_evaluations_on_extended_domain_paper(
    polynomials: &Step5_1Polynomials,
    extended_domain: &PlonkDomain,
) -> Vec<Fr> {
    let mut gate_term_evaluations = Vec::with_capacity(extended_domain.size());
    for point in extended_domain.elements() {
        let a = polynomials
            .witness_polynomials
            .wire_a_polynomial
            .evaluate(&point);
        let b = polynomials
            .witness_polynomials
            .wire_b_polynomial
            .evaluate(&point);
        let c = polynomials
            .witness_polynomials
            .wire_c_polynomial
            .evaluate(&point);
        let q_l = polynomials
            .selector_polynomials
            .q_l_polynomial
            .evaluate(&point);
        let q_r = polynomials
            .selector_polynomials
            .q_r_polynomial
            .evaluate(&point);
        let q_o = polynomials
            .selector_polynomials
            .q_o_polynomial
            .evaluate(&point);
        let q_m = polynomials
            .selector_polynomials
            .q_m_polynomial
            .evaluate(&point);
        let q_c = polynomials
            .selector_polynomials
            .q_c_polynomial
            .evaluate(&point);
        gate_term_evaluations.push(q_m * a * b + q_l * a + q_r * b + q_o * c + q_c);
    }
    gate_term_evaluations
}
/// 辅助函数：把一个 n-1 阶多项式，扩展到 4n 的点值表示上。
/// 输入：poly 原始的多项式 domain 原始 H 的扩展 coset domain。
/// 输出：长度为扩展域大小的 evaluations。
fn extend_poly_to_evals(poly: &DensePolynomial<Fr>, domain: &PlonkDomain) -> Vec<Fr> {
    let mut coeffs = poly.coeffs.clone();
    // 关键细节：将系数向量补齐到扩展域的大小（例如从 8 补到 32）
    // 后面的位置补 0，代表 x^8, x^9... 的系数都是 0，多项式本身没变。
    coeffs.resize(domain.size(), Fr::zero());

    // 执行 FFT。因为 domain 是扩展域且是 coset，
    // 这里会计算出多项式在 {g, gω, gω², ...} 共 4n 个点上的取值。
    domain.fft(&coeffs)
}

fn compute_gate_term_evaluations_on_extended_domain(
    polynomials: &Step5_1Polynomials,
    extended_domain: &PlonkDomain,
) -> Vec<Fr> {
    // Paper mapping: the same gate identity, now sampled where quotient division is performed.
    // 1. 批量升维：所有的 $O(n \log n)$ 计算都在这一步完成
    let a_evals = extend_poly_to_evals(
        &polynomials.witness_polynomials.wire_a_polynomial,
        extended_domain,
    );
    let b_evals = extend_poly_to_evals(
        &polynomials.witness_polynomials.wire_b_polynomial,
        extended_domain,
    );
    let c_evals = extend_poly_to_evals(
        &polynomials.witness_polynomials.wire_c_polynomial,
        extended_domain,
    );

    let q_l_evals = extend_poly_to_evals(
        &polynomials.selector_polynomials.q_l_polynomial,
        extended_domain,
    );
    let q_r_evals = extend_poly_to_evals(
        &polynomials.selector_polynomials.q_r_polynomial,
        extended_domain,
    );
    let q_o_evals = extend_poly_to_evals(
        &polynomials.selector_polynomials.q_o_polynomial,
        extended_domain,
    );
    let q_m_evals = extend_poly_to_evals(
        &polynomials.selector_polynomials.q_m_polynomial,
        extended_domain,
    );
    let q_c_evals = extend_poly_to_evals(
        &polynomials.selector_polynomials.q_c_polynomial,
        extended_domain,
    );

    // 2. 点值计算：这里是纯粹的 $O(4n)$ 遍历
    (0..extended_domain.size())
        .map(|i| {
            q_m_evals[i] * a_evals[i] * b_evals[i]
                + q_l_evals[i] * a_evals[i]
                + q_r_evals[i] * b_evals[i]
                + q_o_evals[i] * c_evals[i]
                + q_c_evals[i]
        })
        .collect()
}
/// 功能说明：在扩展 domain 上计算 permutation 约束的真实 evaluations。
/// 输入：内部多项式包、原始 H-domain、扩展 domain、`beta/gamma`。
/// 输出：长度为扩展域大小的 permutation evaluations。
/// 示例：`Z(omega X)` 必须通过显式计算 `x_shifted = x * omega` 后再评估。
fn compute_permutation_term_evaluations_on_extended_domain(
    polynomials: &Step5_1Polynomials,
    original_domain: &PlonkDomain,
    extended_domain: &PlonkDomain,
    beta: Fr,
    gamma: Fr,
) -> Vec<Fr> {
    // Paper mapping: quotient permutation term evaluated at X and omega*X on the extended domain.

    //
    let omega = original_domain.group_gen();
    let k1 = Fr::from(K1);
    let k2 = Fr::from(K2);
    let mut permutation_term_evaluations = Vec::with_capacity(extended_domain.size());

    for point in extended_domain.elements() {
        let shifted_point = point * omega; // 下一行点 差点被误导了
        // 这个地方其实可以优化一下，用FFT计算，多项式多了会快很多，但为了清晰起见，这里直接逐点评估了。
        let a = polynomials
            .witness_polynomials
            .wire_a_polynomial
            .evaluate(&point);
        let b = polynomials
            .witness_polynomials
            .wire_b_polynomial
            .evaluate(&point);
        let c = polynomials
            .witness_polynomials
            .wire_c_polynomial
            .evaluate(&point);
        let z_at_x = polynomials.z_polynomial.evaluate(&point);
        let z_at_shifted_x = polynomials.z_polynomial.evaluate(&shifted_point);

        // round3的第二行
        let numerator = (a + beta * point + gamma)
            * (b + beta * k1 * point + gamma)
            * (c + beta * k2 * point + gamma);
        // round3的第三行
        let denominator = (a
            + beta
                * polynomials
                    .sigma_tag_polynomials
                    .sigma_a_polynomial
                    .evaluate(&point)
            + gamma)
            * (b + beta
                * polynomials
                    .sigma_tag_polynomials
                    .sigma_b_polynomial
                    .evaluate(&point)
                + gamma)
            * (c + beta
                * polynomials
                    .sigma_tag_polynomials
                    .sigma_c_polynomial
                    .evaluate(&point)
                + gamma);
        // 第二行-第三行
        permutation_term_evaluations.push(z_at_x * numerator - z_at_shifted_x * denominator);
    }

    permutation_term_evaluations
}

/// 功能说明：在扩展 domain 上计算两个 boundary 约束。
/// 输入：`QuotientInputs`、内部多项式包、原始 H-domain、扩展 domain。
/// 输出：两个长度为扩展域大小的 boundary evaluations。
/// 示例：这里使用的是原始 H-domain selector polynomial 在扩展域上的评估。
fn compute_boundary_term_evaluations_on_extended_domain(
    polynomials: &Step5_1Polynomials,
    original_domain: &PlonkDomain,
    extended_domain: &PlonkDomain,
) -> (Vec<Fr>, Vec<Fr>) {
    // Paper mapping: L_0(X) and L_{n-1}(X) gate the two permutation boundary checks inside the numerator.
    let omega = original_domain.group_gen();
    let one = Fr::from(1u64); // 黄金标准：边界值必须是 1
    let mut boundary_term_1_evaluations = Vec::with_capacity(extended_domain.size());
    let mut boundary_term_2_evaluations = Vec::with_capacity(extended_domain.size());

    for point in extended_domain.elements() {
        let shifted_point = point * omega; // 下一行
        let z_at_x = polynomials.z_polynomial.evaluate(&point); //z(x)
        let z_at_shifted_x = polynomials.z_polynomial.evaluate(&shifted_point); //z(omega*x)
        let l_0_at_x = polynomials.l_0_polynomial.evaluate(&point); // l_0(x)
        let l_n_minus_1_at_x = polynomials.l_n_minus_1_polynomial.evaluate(&point); // l_{n-1}(x)

        //( Z(X) - 1 ) * L_0(X)
        boundary_term_1_evaluations.push((z_at_x - one) * l_0_at_x);
        //约束项 2：( Z(ωX) - 1 ) * L_{n-1}(X)
        boundary_term_2_evaluations.push((z_at_shifted_x - one) * l_n_minus_1_at_x);
    }
    (boundary_term_1_evaluations, boundary_term_2_evaluations)
}

/// 功能说明：按固定顺序聚合各类约束 evaluations。
/// 输入：四类约束 evaluations 与 `alpha`。
/// 输出：聚合后的 numerator evaluations。
/// 示例：顺序固定为 gate + alpha*perm + alpha^2*boundary1 + alpha^3*boundary2。
/// 在domian上计算，只是确实了vanish多项式
fn aggregate_numerator_evaluations(
    gate_term_evaluations: &[Fr],
    public_input_term_evaluations: &[Fr],
    permutation_term_evaluations: &[Fr],
    boundary_term_1_evaluations: &[Fr],
    boundary_term_2_evaluations: &[Fr],
    alpha: Fr,
) -> Result<Vec<Fr>> {
    // Paper mapping: quotient aggregation term combining gate, permutation, and boundary relations.
    // Repo role: this repository also inserts its minimal public-input contribution here and keeps the order explicit.
    let length = gate_term_evaluations.len();
    ensure(
        public_input_term_evaluations.len() == length
            && permutation_term_evaluations.len() == length
            && boundary_term_1_evaluations.len() == length
            && boundary_term_2_evaluations.len() == length,
        "all term evaluations must have the same length",
    )?;

    let alpha_square = alpha * alpha;
    let alpha_cube = alpha_square * alpha;
    let mut numerator_evaluations = Vec::with_capacity(length);
    for row_index in 0..length {
        numerator_evaluations.push(
            gate_term_evaluations[row_index]
                + public_input_term_evaluations[row_index]
                + alpha * permutation_term_evaluations[row_index]
                + alpha_square * boundary_term_1_evaluations[row_index]
                + alpha_cube * boundary_term_2_evaluations[row_index],
        );
    }

    Ok(numerator_evaluations)
}

/// 功能说明：评估原始 H 的 vanishing polynomial 到扩展 coset domain 上。
/// 输入：原始 H-domain 与扩展 domain。
/// 输出：`Z_H(X)` 在扩展域每个点的值。
/// 示例：由于扩展域是 coset，这些值都不应为 0。
fn evaluate_h_vanishing_on_extended_domain(
    original_domain: &PlonkDomain,
    extended_domain: &PlonkDomain,
) -> Vec<Fr> {
    extended_domain
        .elements()
        .map(|point| original_domain.evaluate_vanishing_polynomial(point))
        .collect()
}

/// 功能说明：对扩展域上的 numerator / Z_H 做逐点除法。
/// 输入：numerator evaluations 与 vanishing evaluations。
/// 输出：quotient evaluations。
/// 示例：若某个 vanishing evaluation 为 0，会显式返回错误而不是做 0/0。
fn compute_quotient_evaluations(
    numerator_evaluations: &[Fr],
    vanishing_evaluations: &[Fr],
) -> Result<Vec<Fr>> {
    // Paper mapping: T(X) = numerator(X) / Z_H(X) as pointwise division on the extended domain.
    ensure(
        numerator_evaluations.len() == vanishing_evaluations.len(),
        "numerator and vanishing evaluations must have the same length",
    )?;

    let mut quotient_evaluations = Vec::with_capacity(numerator_evaluations.len());
    for index in 0..numerator_evaluations.len() {
        let vanishing_inverse =
            vanishing_evaluations[index]
                .inverse()
                .ok_or(PlonkError::InvalidInput(
                    "vanishing polynomial evaluates to zero on the extended quotient domain",
                ))?;
        quotient_evaluations.push(numerator_evaluations[index] * vanishing_inverse);
    }

    Ok(quotient_evaluations)
}

/// 功能说明：构造原始 H-domain 的 one-hot selector evaluations。
/// 输入：domain_size 与目标位置 index。
/// 输出：长度为 `domain_size` 的 one-hot 向量。
/// 示例：`index=0` 时输出 `[1,0,0,...]`。
fn build_one_hot_selector(domain_size: usize, index: usize) -> Result<Vec<Fr>> {
    ensure(domain_size > 0, "domain_size must be positive")?;
    ensure(index < domain_size, "selector index out of range")?;

    let mut selector = vec![Fr::from(0u64); domain_size];
    selector[index] = Fr::from(1u64);
    Ok(selector)
}

/// 功能说明：在原始 H-domain 上回传 selector evaluations。
/// 输入：原始 H-domain 与 selector 点值。
/// 输出：与输入相同的 selector evaluations。
/// 示例：这个函数只是让 H-domain 边界编码的语义更直接。
fn evaluate_selector_polynomial_on_original_domain(
    _original_domain: &PlonkDomain,
    selector_evaluations: &[Fr],
) -> Vec<Fr> {
    selector_evaluations.to_vec()
}

/// 功能说明：构造原始 H 的 vanishing polynomial `Z_H(X) = X^n - 1`。
/// 输入：原始 H-domain 大小 `n`。
/// 输出：稠密形式的 `Z_H(X)`。
/// 示例：用于测试 `quotient_poly * Z_H(X) == numerator_poly`。
pub fn build_h_vanishing_polynomial(domain_size: usize) -> DensePolynomial<Fr> {
    let mut coefficients = vec![Fr::from(0u64); domain_size + 1];
    coefficients[0] = -Fr::from(1u64);
    coefficients[domain_size] = Fr::from(1u64);
    DensePolynomial::from_coefficients_vec(coefficients)
}

/// 功能说明：判断多项式是否为零多项式。
/// 输入：`DensePolynomial`。
/// 输出：所有系数都为 0 时返回 `true`。
/// 示例：测试中可用来检查某个余项是否完全消失。
pub fn is_zero_polynomial(polynomial: &DensePolynomial<Fr>) -> bool {
    polynomial
        .coeffs
        .iter()
        .all(|coefficient| coefficient.is_zero())
}

/// 鍔熻兘璇存槑锛氭寜褰撳墠浠撳簱鐨?`PI(X)` 璇箟锛岀洿鎺ュ湪涓€鐐逛笂璇勪及 public-input contribution銆?
/// 杈撳叆锛氬師濮?domain銆佸閮?`public_inputs` 涓庤瘎浼扮偣銆?
/// 杈撳嚭锛歚PI(point)`銆?
/// 绀轰緥锛歚evaluate_public_input_polynomial_at_point(domain, public_inputs, zeta)`銆?
pub fn evaluate_public_input_polynomial_at_point(
    domain: &PlonkDomain,
    public_inputs: &[Fr],
    point: Fr,
) -> Fr {
    let lagrange_values = domain.evaluate_all_lagrange_coefficients(point);
    public_inputs
        .iter()
        .enumerate()
        .fold(Fr::zero(), |accumulator, (index, public_input)| {
            accumulator + (*public_input * lagrange_values[index])
        })
}

/// Phase 9 prover / verifier 使用的 quotient chunk 多项式。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotientChunkPolynomials {
    pub t_lo: DensePolynomial<Fr>,
    pub t_mid: DensePolynomial<Fr>,
    pub t_hi: DensePolynomial<Fr>,
}

/// 功能说明：把完整 `T(X)` 按 `t_lo + X^n t_mid + X^(2n) t_hi` 切成三个 chunk。
/// 输入：完整 quotient polynomial 与原始 domain 大小 `n`。
/// 输出：
/// - `T_lo` 持有 `[0, n)` 系数
/// - `T_mid` 持有 `[n, 2n)` 系数
/// - `T_hi` 持有 `[2n, ..)` 的完整高次尾部
///
/// 这样 Step 10.2 在引入更强 blinding 后，即使 `T(X)` 的次数超过 `3n - 1`，
/// 仍然不会把高次尾部静默截断。
/// 示例：`split_quotient_polynomial(&t, n)?`。
pub fn split_quotient_polynomial(
    quotient_polynomial: &DensePolynomial<Fr>,
    domain_size: usize,
) -> Result<QuotientChunkPolynomials> {
    ensure(domain_size > 0, "domain_size must be positive")?;

    // 闭包
    let take_fixed_chunk = |chunk_index: usize| {
        let start = chunk_index * domain_size;
        let mut coeffs = vec![Fr::zero(); domain_size];
        for (offset, coefficient) in quotient_polynomial
            .coeffs
            .iter()
            .skip(start)
            .take(domain_size)
            .enumerate()
        {
            coeffs[offset] = *coefficient;
        }
        // 闭包返回的值
        DensePolynomial::from_coefficients_vec(trim_trailing_zeros(coeffs))
    };

    // 定义一个不带参数的闭包 ||
    // 它会自动从环境中“捕获” quotient_polynomial 和 domain_size
    let take_tail_chunk = || {
        // 1. 确定起点：t_hi 应该从 X^{2n} 的系数开始拿
        let start = 2 * domain_size;

        // 2. 使用迭代器进行“手术采样”
        let coeffs: Vec<Fr> = quotient_polynomial
            .coeffs             // 访问原始多项式的系数向量 [c0, c1, c2, ...]
            .iter()             // 变成一个“传送带” (迭代器)
            .skip(start)        // 跳过前 2n 个系数（即跳过 t_lo 和 t_mid 的部分）
            .copied()           // 把 &Fr (引用) 复制成 Fr (值)，因为 collect 需要拥有所有权
            .collect();         // 把剩下的所有系数（从 2n 到末尾）收集进一个新的 Vec

        // 3. 边界处理：万一 t(X) 的阶数刚好小于 2n，后面没东西了
        if coeffs.is_empty() {
            // 返回一个常数 0 多项式，防止程序因为数组为空而崩溃
            DensePolynomial::from_coefficients_vec(vec![Fr::zero()])
        } else {
            // 4. 正常返回：构造新多项式，并顺便修剪掉末尾无用的零
            // trim_trailing_zeros 确保多项式的 degree() 返回的是真实有效的值
            // 去掉了0，也就是这个vec一定是n
            DensePolynomial::from_coefficients_vec(trim_trailing_zeros(coeffs))
        }
    };
    let result = QuotientChunkPolynomials {
        t_lo: take_fixed_chunk(0),
        t_mid: take_fixed_chunk(1),
        t_hi: take_tail_chunk(),
    };
    // --- 最终收尾校验 ---
    // 确保切开后的最高阶部分 t_hi，它的 degree 依然在 n 范围内（允许微量盲化 buffer）
    // 如果这里报错，说明即便之前的总长度没超，但这部分数据不对劲。
    ensure(domain_size > 0, "domain_size must be positive")?;
    ensure(
        result.t_hi.coeffs.len() <= domain_size + 8,
        "t_hi.coeffs is too big"
    )?;
    Ok(result)
}

/// 功能说明：给 witness polynomial 添加 `(c0 + c1 * X) * Z_H(X)` 形式的最小 blind。
/// 输入：原始多项式、原始 domain 大小、两个随机标量。
/// 输出：在 H 上取值不变、但承诺与随机点 opening 改变后的多项式。
/// 示例：`blind_witness_polynomial(&a_raw, n, r0, r1)`。
pub fn blind_witness_polynomial(
    polynomial: &DensePolynomial<Fr>, // 输入：原始多项式的引用（只读）
    domain_size: usize,               // 输入：Domain 的大小 n
    constant_blinder: Fr,             // 输入：随机标量 c0
    linear_blinder: Fr,               // 输入：随机标量 c1
) -> Result<DensePolynomial<Fr>> {
    // 返回：包装在 Result 中的新多项式
    // 1. 安全检查，防止 domain 为 0 导致溢出或错误
    ensure(domain_size > 0, "domain_size must be positive")?;

    // 2. 克隆原始系数。DensePolynomial 内部通常是一个 Vec<Fr>
    let mut coefficients = polynomial.coeffs.clone();

    // 3. 扩容。我们需要存到 X^{n+1} 项，所以向量长度需要是 n+2
    // 如果原多项式次数较低，这里会补 0
    coefficients.resize(domain_size + 2, Fr::zero());

    // 4. 根据数学公式修改系数：
    // 修改常数项 (X^0): a0 = a0 - c0
    coefficients[0] -= constant_blinder;
    // 修改一次项 (X^1): a1 = a1 - c1
    coefficients[1] -= linear_blinder;
    // 修改 n 次项 (X^n): an = an + c0
    coefficients[domain_size] += constant_blinder;
    // 修改 n+1 次项 (X^{n+1}): a_{n+1} = a_{n+1} + c1
    coefficients[domain_size + 1] += linear_blinder;

    // 5. 包装返回结果
    // trim_trailing_zeros 是为了删掉高位无意义的 0（减小空间）
    Ok(DensePolynomial::from_coefficients_vec(trim_trailing_zeros(
        coefficients,
    )))
}
/// 功能说明：给 grand product polynomial 添加 `(c0 + c1 * X + c2 * X^2) * Z_H(X)` 形式的 blind。
/// 输入：原始 `Z(X)`、原始 domain 大小、三个随机标量。
/// 输出：在 H 上保持同值的 blinded `Z(X)`。
/// 示例：`blind_grand_product_polynomial(&z_raw, n, c0, c1, c2)`。
pub fn blind_grand_product_polynomial(
    polynomial: &DensePolynomial<Fr>,
    domain_size: usize,
    constant_blinder: Fr,
    linear_blinder: Fr,
    quadratic_blinder: Fr,
) -> Result<DensePolynomial<Fr>> {
    ensure(domain_size > 0, "domain_size must be positive")?;

    let mut coefficients = polynomial.coeffs.clone();
    coefficients.resize(domain_size + 3, Fr::zero());
    coefficients[0] -= constant_blinder;
    coefficients[1] -= linear_blinder;
    coefficients[2] -= quadratic_blinder;
    coefficients[domain_size] += constant_blinder;
    coefficients[domain_size + 1] += linear_blinder;
    coefficients[domain_size + 2] += quadratic_blinder;

    Ok(DensePolynomial::from_coefficients_vec(trim_trailing_zeros(
        coefficients,
    )))
}

/// 功能说明：按 Step 10.1 冻结形式对 quotient chunks 做 re-randomization。
/// 输入：原始 chunks、原始 domain 大小、两个随机标量。
/// 输出：重组 `t(X)` 不变、但 chunk commitments 改变后的三块多项式。
/// 示例：`rerandomize_quotient_chunks(&chunks, n, r0, r1)?`。
pub fn rerandomize_quotient_chunks(
    quotient_chunks: &QuotientChunkPolynomials,
    domain_size: usize,
    first_blinder: Fr,
    second_blinder: Fr,
) -> Result<QuotientChunkPolynomials> {
    ensure(domain_size > 0, "domain_size must be positive")?;

    let mut t_lo_coefficients = quotient_chunks.t_lo.coeffs.clone();
    // 多项式系数提升增加了
    t_lo_coefficients.resize(domain_size + 1, Fr::zero());
    t_lo_coefficients[domain_size] += first_blinder;

    let mut t_mid_coefficients = quotient_chunks.t_mid.coeffs.clone();
    t_mid_coefficients.resize(domain_size + 1, Fr::zero());
    t_mid_coefficients[0] -= first_blinder;
    t_mid_coefficients[domain_size] += second_blinder;

    let mut t_hi_coefficients = quotient_chunks.t_hi.coeffs.clone();
    if t_hi_coefficients.is_empty() {
        t_hi_coefficients.push(Fr::zero());
    }
    t_hi_coefficients[0] -= second_blinder;

    Ok(QuotientChunkPolynomials {
        t_lo: DensePolynomial::from_coefficients_vec(trim_trailing_zeros(t_lo_coefficients)),
        t_mid: DensePolynomial::from_coefficients_vec(trim_trailing_zeros(t_mid_coefficients)),
        t_hi: DensePolynomial::from_coefficients_vec(trim_trailing_zeros(t_hi_coefficients)),
    })
}

/// 功能说明：按 `T_lo + X^n*T_mid + X^(2n)*T_hi` 重组并评估 quotient。
/// 输入：quotient chunks、domain 大小与评估点。
/// 输出：`T(point)`。
/// 示例：`evaluate_chunked_quotient(&chunks, n, zeta)`。
pub fn evaluate_chunked_quotient(
    quotient_chunks: &QuotientChunkPolynomials,
    domain_size: usize,
    point: Fr,
) -> Fr {
    let point_to_n = point.pow([domain_size as u64]);
    let point_to_2n = point_to_n * point_to_n;
    quotient_chunks.t_lo.evaluate(&point)
        + point_to_n * quotient_chunks.t_mid.evaluate(&point)
        + point_to_2n * quotient_chunks.t_hi.evaluate(&point)
}

/// 功能说明：构造 prover 在 `zeta` 处使用的 linearization polynomial `r(X)`。
/// 输入：固定多项式、`Z(X)`、quotient chunks、statement 与挑战/评估值。
/// 输出：显式可读的 `r(X)`。
/// 示例：Step 9.3 prover 会在构造 `W_z` 前调用它。
#[allow(clippy::too_many_arguments)]
pub fn build_linearization_polynomial(
    domain: &PlonkDomain,
    q_l_polynomial: &DensePolynomial<Fr>,
    q_r_polynomial: &DensePolynomial<Fr>,
    q_o_polynomial: &DensePolynomial<Fr>,
    q_m_polynomial: &DensePolynomial<Fr>,
    q_c_polynomial: &DensePolynomial<Fr>,
    sigma_3_polynomial: &DensePolynomial<Fr>,
    grand_product_polynomial: &DensePolynomial<Fr>,
    quotient_chunks: &QuotientChunkPolynomials,
    public_inputs: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    zeta: Fr,
    a_at_zeta: Fr,
    b_at_zeta: Fr,
    c_at_zeta: Fr,
    sigma_1_at_zeta: Fr,
    sigma_2_at_zeta: Fr,
    z_at_omega_zeta: Fr,
) -> DensePolynomial<Fr> {
    // Paper mapping: this is the prover-side linearization polynomial used before building W_z.
    let public_input_at_zeta =
        evaluate_public_input_polynomial_at_point(domain, public_inputs, zeta);
    let z_h_at_zeta = domain.evaluate_vanishing_polynomial(zeta);
    let l_0_at_zeta = domain.evaluate_all_lagrange_coefficients(zeta)[0];
    let point_to_n = zeta.pow([domain.size() as u64]);
    let point_to_2n = point_to_n * point_to_n;

    let gate_constant = scale_polynomial(q_m_polynomial, a_at_zeta * b_at_zeta)
        + scale_polynomial(q_l_polynomial, a_at_zeta)
        + scale_polynomial(q_r_polynomial, b_at_zeta)
        + scale_polynomial(q_o_polynomial, c_at_zeta)
        + scale_polynomial(q_c_polynomial, Fr::from(1u64))
        + DensePolynomial::from_coefficients_vec(vec![public_input_at_zeta]);

    let permutation_scalar = alpha
        * (a_at_zeta + beta * zeta + gamma)
        * (b_at_zeta + beta * Fr::from(K1) * zeta + gamma)
        * (c_at_zeta + beta * Fr::from(K2) * zeta + gamma);
    let permutation_z_term = scale_polynomial(grand_product_polynomial, permutation_scalar);

    let sigma_scalar = -alpha
        * (a_at_zeta + beta * sigma_1_at_zeta + gamma)
        * (b_at_zeta + beta * sigma_2_at_zeta + gamma);
    let sigma_linear = scale_polynomial(sigma_3_polynomial, beta * sigma_scalar * z_at_omega_zeta);
    let sigma_constant = DensePolynomial::from_coefficients_vec(vec![
        (c_at_zeta + gamma) * sigma_scalar * z_at_omega_zeta,
    ]);

    let boundary_linear = scale_polynomial(grand_product_polynomial, alpha * alpha * l_0_at_zeta);
    let boundary_constant =
        DensePolynomial::from_coefficients_vec(vec![-alpha * alpha * l_0_at_zeta]);

    let quotient_reconstruction = quotient_chunks.t_lo.clone()
        + scale_polynomial(&quotient_chunks.t_mid, point_to_n)
        + scale_polynomial(&quotient_chunks.t_hi, point_to_2n);
    let quotient_term = scale_polynomial(&quotient_reconstruction, -z_h_at_zeta);

    gate_constant
        + permutation_z_term
        + boundary_linear
        + sigma_linear
        + sigma_constant
        + boundary_constant
        + quotient_term
}

/// 功能说明：去掉系数向量尾部的 0，避免把 chunk 人为扩成高次零多项式。
/// 输入：一个系数向量。
/// 输出：裁剪后的系数向量；全零时保留一个 0。
/// 示例：`trim_trailing_zeros(vec![1, 0, 0])`。
fn trim_trailing_zeros(mut coefficients: Vec<Fr>) -> Vec<Fr> {
    while coefficients.len() > 1
        && coefficients
            .last()
            .is_some_and(|coefficient| coefficient.is_zero())
    {
        coefficients.pop();
    }
    coefficients
}

/// 功能说明：把多项式整体乘以一个标量。
/// 输入：多项式与标量。
/// 输出：缩放后的多项式。
/// 示例：`scale_polynomial(poly, alpha)`。
fn scale_polynomial(polynomial: &DensePolynomial<Fr>, scalar: Fr) -> DensePolynomial<Fr> {
    if scalar.is_zero() {
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
