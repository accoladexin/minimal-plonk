//! Step 11.1: microbench for FFT / IFFT on BN254 radix-2 domains.

use std::time::Duration;

use ark_ff::Field;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use minimal_plonk::{
    curve::Fr,
    domain::{build_domain_from_size, fft, ifft},
};

const DOMAIN_LOG_SIZES: [u32; 4] = [8, 10, 12, 14];

/// 功能说明：构造固定的 FFT 输入系数，避免把随机采样时间混入 benchmark。
/// 输入：目标长度 `n`。
/// 输出：长度为 `n` 的 BN254 系数向量。
/// 示例：`build_coefficients(1 << 10)`。
fn build_coefficients(size: usize) -> Vec<Fr> {
    (0..size)
        .map(|index| Fr::from((index as u64) + 1).square())
        .collect()
}

/// 功能说明：注册 FFT microbench。
/// 输入：criterion 上下文。
/// 输出：无，直接向 benchmark runner 注册条目。
/// 示例：由 `criterion_group!` 调用。
fn bench_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("micro_fft_bn254");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(1));

    for log_size in DOMAIN_LOG_SIZES {
        let size = 1usize << log_size;
        let domain = build_domain_from_size(size).expect("fft bench domain should build");
        let coefficients = build_coefficients(size);
        let evaluations = fft(&domain, &coefficients).expect("fft bench input should be valid");

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("fft_curve_bn254_domain", format!("2^{log_size}")),
            &size,
            |b, _| {
                b.iter(|| {
                    let output = fft(&domain, black_box(&coefficients))
                        .expect("fft benchmark should succeed");
                    black_box(output);
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("ifft_curve_bn254_domain", format!("2^{log_size}")),
            &size,
            |b, _| {
                b.iter(|| {
                    let output =
                        ifft(&domain, black_box(&evaluations)).expect("ifft benchmark should succeed");
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(micro_fft_benches, bench_fft);
criterion_main!(micro_fft_benches);
