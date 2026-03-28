//! Step 11.2: end-to-end Macrobench for Mini-Plonk prove / verify on BN254.

use std::time::{Duration, Instant};

use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use minimal_plonk::{
    cs::{Circuit, SelectorColumns},
    curve::Fr,
    domain::{PlonkDomain, build_domain_from_size, domain_params},
    kzg::KzgSrs,
    mimc::build_mimc_feistel_circuit,
    permutation::{CopyConstraint, SigmaMapping, build_sigma_from_copy_constraints},
    prover::prove,
    types::{
        PlonkProof, SelectorPolynomials, SigmaTagPolynomials, VerifierPreprocessedInput,
        VerifierProtocolParams,
    },
    verifier::verify,
    witness::interpolate_column_evaluations,
};

const MIMC_ROUNDS: [usize; 3] = [8, 16, 32];

/// 功能说明：保存单个 Macrobench 规模所需的固定输入和摘要指标。
/// 输入：无，字段由 `build_macro_fixture(...)` 统一填充。
/// 输出：可复用的 prove / verify benchmark fixture。
/// 示例：`let fixture = build_macro_fixture(64);`
struct MacroFixture {
    rounds: usize,
    domain_size: usize,
    srs_max_degree: usize,
    srs_g1_length: usize,
    public_inputs: Vec<Fr>,
    circuit: Circuit,
    copy_constraints: Vec<CopyConstraint>,
    verifier_input: VerifierPreprocessedInput,
    proof: PlonkProof,
    srs: KzgSrs,
    setup_time: Duration,
    prove_time: Duration,
    verify_time: Duration,
    proof_size_bytes: usize,
}

/// 功能说明：构造单个 Macrobench 规模的固定夹具与摘要信息。
/// 输入：MiMC rounds。
/// 输出：包含 circuit / SRS / verifier input / proof / 尺寸指标的 fixture。
/// 示例：`let fixture = build_macro_fixture(256);`
fn build_macro_fixture(rounds: usize) -> MacroFixture {
    let public_inputs = Vec::new();
    let copy_constraints = Vec::new();

    let setup_start = Instant::now();
    let build = build_mimc_feistel_circuit(Fr::from(7u64), rounds)
        .expect("macrobench MiMC circuit should build");
    let circuit = build.circuit;
    let domain_size = circuit
        .domain_size()
        .expect("macrobench circuit must be padded");
    let srs = sample_srs(domain_size);
    let verifier_input = build_verifier_input(&circuit, &copy_constraints);
    let setup_time = setup_start.elapsed();

    let prove_start = Instant::now();
    let proof = prove(&circuit, &copy_constraints, public_inputs.clone(), &srs)
        .expect("macrobench prove should succeed");
    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    let verified = verify(&proof, public_inputs.as_slice(), &verifier_input, &srs)
        .expect("macrobench verify should run");
    let verify_time = verify_start.elapsed();
    assert!(verified, "macrobench fixture proof must verify");

    let proof_size_bytes = serialized_proof_size_bytes(&proof);

    MacroFixture {
        rounds,
        domain_size,
        srs_max_degree: srs.max_degree(),
        srs_g1_length: srs.g1_powers.len(),
        public_inputs,
        circuit,
        copy_constraints,
        verifier_input,
        proof,
        srs,
        setup_time,
        prove_time,
        verify_time,
        proof_size_bytes,
    }
}

/// 功能说明：为当前 domain size 生成可覆盖 prove 内部多项式次数的测试 SRS。
/// 输入：电路的 padded domain size。
/// 输出：本轮 benchmark 使用的 KZG SRS。
/// 示例：`let srs = sample_srs(512);`
fn sample_srs(domain_size: usize) -> KzgSrs {
    KzgSrs::setup_for_testing((8 * domain_size).next_power_of_two())
        .expect("macrobench srs should build")
}

/// 功能说明：把 verifier 侧固定多项式输入组装成当前协议需要的最小边界。
/// 输入：已 pad 的电路与 copy constraints。
/// 输出：可直接送入 `verify(...)` 的 `VerifierPreprocessedInput`。
/// 示例：`let verifier_input = build_verifier_input(&circuit, &[]);`
fn build_verifier_input(
    circuit: &Circuit,
    copy_constraints: &[CopyConstraint],
) -> VerifierPreprocessedInput {
    let domain_size = circuit
        .domain_size()
        .expect("macrobench circuit must be padded");
    let domain = build_domain_from_size(domain_size).expect("macrobench domain should build");
    let selectors =
        SelectorColumns::from_padded_circuit(circuit).expect("selector columns should extract");
    let selector_polynomials = SelectorPolynomials::new(
        interpolate_column_evaluations(&domain, &selectors.q_l_evaluations)
            .expect("q_l interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_r_evaluations)
            .expect("q_r interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_o_evaluations)
            .expect("q_o interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_m_evaluations)
            .expect("q_m interpolation should succeed"),
        interpolate_column_evaluations(&domain, &selectors.q_c_evaluations)
            .expect("q_c interpolation should succeed"),
    );
    let sigma_mapping = build_sigma_from_copy_constraints(domain_size, copy_constraints)
        .expect("sigma mapping should build");
    let (sigma_a, sigma_b, sigma_c) = build_sigma_tag_evaluations(&domain, &sigma_mapping);
    let sigma_tag_polynomials = SigmaTagPolynomials::new(
        interpolate_column_evaluations(&domain, &sigma_a)
            .expect("sigma_1 interpolation should succeed"),
        interpolate_column_evaluations(&domain, &sigma_b)
            .expect("sigma_2 interpolation should succeed"),
        interpolate_column_evaluations(&domain, &sigma_c)
            .expect("sigma_3 interpolation should succeed"),
    );

    VerifierPreprocessedInput::new(
        domain_params(&domain),
        selector_polynomials,
        sigma_tag_polynomials,
        VerifierProtocolParams::default(),
    )
}

/// 功能说明：把 sigma mapping 转成 verifier 侧需要的三个 sigma tag evaluation 列。
/// 输入：Plonk domain 与已验证的 sigma mapping。
/// 输出：`(sigma_1, sigma_2, sigma_3)` evaluation 向量。
/// 示例：`let (a, b, c) = build_sigma_tag_evaluations(&domain, &sigma);`
fn build_sigma_tag_evaluations(
    domain: &PlonkDomain,
    sigma_mapping: &SigmaMapping,
) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let domain_size = domain.size();
    let mut sigma_a = Vec::with_capacity(domain_size);
    let mut sigma_b = Vec::with_capacity(domain_size);
    let mut sigma_c = Vec::with_capacity(domain_size);

    for row in 0..domain_size {
        sigma_a.push(target_tag_for_source(domain, sigma_mapping, row, 0));
        sigma_b.push(target_tag_for_source(domain, sigma_mapping, row, 1));
        sigma_c.push(target_tag_for_source(domain, sigma_mapping, row, 2));
    }

    (sigma_a, sigma_b, sigma_c)
}

/// 功能说明：计算单个 source wire position 经 sigma 映射后的目标 tag。
/// 输入：domain、sigma mapping、源 row、源列编号。
/// 输出：目标位置对应的列因子乘行标签。
/// 示例：`let tag = target_tag_for_source(&domain, &sigma, 3, 1);`
fn target_tag_for_source(
    domain: &PlonkDomain,
    sigma_mapping: &SigmaMapping,
    row: usize,
    column_index: usize,
) -> Fr {
    let domain_size = domain.size();
    let source_id = column_index * domain_size + row;
    let target_id = sigma_mapping
        .image_at(source_id)
        .expect("sigma image should exist");
    let target_column = target_id / domain_size;
    let target_row = target_id % domain_size;
    let column_factor = match target_column {
        0 => Fr::from(1u64),
        1 => Fr::from(2u64),
        2 => Fr::from(3u64),
        _ => panic!("target column index out of range"),
    };

    column_factor * domain.element(target_row)
}

/// 功能说明：统计 proof 的 canonical compressed 序列化字节数。
/// 输入：一份有效 `PlonkProof`。
/// 输出：proof bytes。
/// 示例：`let bytes = serialized_proof_size_bytes(&proof);`
fn serialized_proof_size_bytes(proof: &PlonkProof) -> usize {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("proof serialization should succeed");
    bytes.len()
}

/// 功能说明：生成 bench id 中的显式参数标签。
/// 输入：一份 Macrobench fixture。
/// 输出：包含 curve / rounds / domain / SRS 的字符串。
/// 示例：`let id = bench_case_id(&fixture);`
fn bench_case_id(fixture: &MacroFixture) -> String {
    format!(
        "curve_bn254_rounds_{}_domain_{}_srs_max_degree_{}",
        fixture.rounds, fixture.domain_size, fixture.srs_max_degree
    )
}

/// 功能说明：打印当前规模的 bench 元数据与 coarse-grained 摘要。
/// 输入：一份已经构造完成的 Macrobench fixture。
/// 输出：无；直接向 benchmark 日志打印摘要。
/// 示例：`print_fixture_summary(&fixture);`
fn print_fixture_summary(fixture: &MacroFixture) {
    let total = fixture.setup_time + fixture.prove_time + fixture.verify_time;
    let total_secs = total.as_secs_f64();
    let setup_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.setup_time.as_secs_f64() / total_secs * 100.0
    };
    let prove_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.prove_time.as_secs_f64() / total_secs * 100.0
    };
    let verify_share = if total_secs == 0.0 {
        0.0
    } else {
        fixture.verify_time.as_secs_f64() / total_secs * 100.0
    };

    eprintln!(
        "macrobench case: curve=BN254 rounds={} domain={} srs_max_degree={} srs_g1_len={} proof_size_bytes={} setup_ms={:.3} prove_ms={:.3} verify_ms={:.3} shares=setup:{:.1}%/prove:{:.1}%/verify:{:.1}%",
        fixture.rounds,
        fixture.domain_size,
        fixture.srs_max_degree,
        fixture.srs_g1_length,
        fixture.proof_size_bytes,
        fixture.setup_time.as_secs_f64() * 1_000.0,
        fixture.prove_time.as_secs_f64() * 1_000.0,
        fixture.verify_time.as_secs_f64() * 1_000.0,
        setup_share,
        prove_share,
        verify_share,
    );
}

/// 功能说明：注册端到端 prove / verify Macrobench。
/// 输入：Criterion 上下文。
/// 输出：无，直接向 benchmark runner 注册条目。
/// 示例：由 `criterion_group!` 调用。
fn bench_macro_plonk(c: &mut Criterion) {
    let fixtures: Vec<_> = MIMC_ROUNDS
        .into_iter()
        .map(build_macro_fixture)
        .collect();

    for fixture in &fixtures {
        print_fixture_summary(fixture);
    }

    let mut prove_group = c.benchmark_group("macro_plonk_prove_bn254");
    prove_group.sample_size(10);
    prove_group.warm_up_time(Duration::from_millis(500));
    prove_group.measurement_time(Duration::from_secs(2));
    for fixture in &fixtures {
        prove_group.bench_with_input(
            BenchmarkId::new("prove", bench_case_id(fixture)),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    let proof = prove(
                        &fixture.circuit,
                        &fixture.copy_constraints,
                        fixture.public_inputs.clone(),
                        &fixture.srs,
                    )
                    .expect("macrobench prove iteration should succeed");
                    black_box(proof);
                });
            },
        );
    }
    prove_group.finish();

    let mut verify_group = c.benchmark_group("macro_plonk_verify_bn254");
    verify_group.sample_size(10);
    verify_group.warm_up_time(Duration::from_millis(500));
    verify_group.measurement_time(Duration::from_secs(2));
    for fixture in &fixtures {
        verify_group.bench_with_input(
            BenchmarkId::new("verify", bench_case_id(fixture)),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    let result = verify(
                        black_box(&fixture.proof),
                        fixture.public_inputs.as_slice(),
                        &fixture.verifier_input,
                        &fixture.srs,
                    )
                    .expect("macrobench verify iteration should succeed");
                    black_box(result);
                });
            },
        );
    }
    verify_group.finish();
}

criterion_group!(macro_plonk_benches, bench_macro_plonk);
criterion_main!(macro_plonk_benches);
