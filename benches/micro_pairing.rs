//! Step 11.1: microbench for explicit BN254 pairing.

use std::time::Duration;

use ark_ec::{CurveGroup, Group, pairing::Pairing};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use minimal_plonk::curve::{Curve, Fr, G1, G2};

/// 功能说明：构造固定的 pairing 输入点，避免把点生成时间混入 benchmark。
/// 输入：无。
/// 输出：一对可直接送入 pairing 的仿射点。
/// 示例：`let (p, q) = build_pairing_inputs();`。
fn build_pairing_inputs() -> (
    <Curve as Pairing>::G1Affine,
    <Curve as Pairing>::G2Affine,
) {
    let g1_point = (G1::generator() * Fr::from(5u64)).into_affine();
    let g2_point = (G2::generator() * Fr::from(7u64)).into_affine();
    (g1_point, g2_point)
}

/// 功能说明：注册单次 pairing microbench。
/// 输入：criterion 上下文。
/// 输出：无，直接向 benchmark runner 注册条目。
/// 示例：由 `criterion_group!` 调用。
fn bench_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group("micro_pairing_bn254");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(1));

    let (g1_point, g2_point) = build_pairing_inputs();
    group.bench_function("pairing_curve_bn254_single", |b| {
        b.iter(|| {
            let output = Curve::pairing(black_box(g1_point), black_box(g2_point));
            let _ = black_box(output);
        });
    });

    group.finish();
}

criterion_group!(micro_pairing_benches, bench_pairing);
criterion_main!(micro_pairing_benches);
