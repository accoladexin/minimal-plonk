//! Step 11.1: microbench for KZG open / verify on BN254.

use std::time::Duration;

use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use minimal_plonk::{
    curve::Fr,
    kzg::{KzgSrs, commit_polynomial, open_polynomial_at_point, verify_opening},
};

const KZG_DEGREES: [usize; 3] = [255, 1023, 4095];

/// 功能说明：构造固定的 benchmark 多项式，避免把随机采样时间混入 benchmark。
/// 输入：多项式 degree。
/// 输出：一个 degree 不超过输入值的 BN254 稠密多项式。
/// 示例：`build_polynomial(1023)`。
fn build_polynomial(degree: usize) -> DensePolynomial<Fr> {
    let coefficients = (0..=degree)
        .map(|index| Fr::from((index as u64) + 3).square())
        .collect();
    DensePolynomial::from_coefficients_vec(coefficients)
}

/// 功能说明：注册 KZG open / verify microbench。
/// 输入：criterion 上下文。
/// 输出：无，直接向 benchmark runner 注册条目。
/// 示例：由 `criterion_group!` 调用。
fn bench_kzg(c: &mut Criterion) {
    let mut group = c.benchmark_group("micro_kzg_bn254");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(1));

    for degree in KZG_DEGREES {
        let polynomial = build_polynomial(degree);
        let srs = KzgSrs::setup_for_testing(degree).expect("kzg bench srs should build");
        let commitment = commit_polynomial(&polynomial, &srs).expect("commitment should succeed");
        let point = Fr::from((degree as u64) + 17);
        let opening =
            open_polynomial_at_point(&polynomial, point, &srs).expect("opening should succeed");

        group.bench_with_input(
            BenchmarkId::new(
                "open_curve_bn254_degree",
                format!("{degree}_srs_max_degree_{degree}"),
            ),
            &degree,
            |b, _| {
                b.iter(|| {
                    let output = open_polynomial_at_point(black_box(&polynomial), point, &srs)
                        .expect("kzg opening benchmark should succeed");
                    black_box(output);
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                "verify_curve_bn254_degree",
                format!("{degree}_srs_max_degree_{degree}"),
            ),
            &degree,
            |b, _| {
                b.iter(|| {
                    let result = verify_opening(
                        black_box(&commitment),
                        point,
                        opening.value,
                        black_box(&opening.proof),
                        &srs,
                    )
                    .expect("kzg verify benchmark should succeed");
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(micro_kzg_benches, bench_kzg);
criterion_main!(micro_kzg_benches);
