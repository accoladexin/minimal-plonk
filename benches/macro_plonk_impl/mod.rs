//! Criterion registration for the end-to-end Mini-Plonk macro benchmark.

mod fixture;
mod utils;

use criterion::{BenchmarkId, Criterion, black_box};
use fixture::build_macro_fixtures;
use minimal_plonk::{
    prover::prove,
    verifier::{prepare_verifier_input, verify_with_prepared_input},
};
use std::time::Duration;

pub fn bench_macro_plonk(c: &mut Criterion) {
    let fixtures = build_macro_fixtures();
    for fixture in &fixtures {
        utils::print_fixture_summary(fixture);
    }

    let mut preprocess_group = c.benchmark_group("macro_plonk_preprocess_bn254");
    preprocess_group.sample_size(10);
    preprocess_group.warm_up_time(Duration::from_millis(500));
    preprocess_group.measurement_time(Duration::from_secs(2));
    for fixture in &fixtures {
        preprocess_group.bench_with_input(
            BenchmarkId::new("verify_fixed_preprocess", fixture.case_id.as_str()),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    let prepared = prepare_verifier_input(&fixture.verifier_input, &fixture.srs)
                        .expect("macrobench preprocess iteration should succeed");
                    black_box(prepared);
                });
            },
        );
    }
    preprocess_group.finish();

    let mut prove_group = c.benchmark_group("macro_plonk_prove_bn254");
    prove_group.sample_size(10);
    prove_group.warm_up_time(Duration::from_millis(500));
    prove_group.measurement_time(Duration::from_secs(2));
    for fixture in &fixtures {
        prove_group.bench_with_input(
            BenchmarkId::new("prove", fixture.case_id.as_str()),
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
            BenchmarkId::new("verify_prepared", fixture.case_id.as_str()),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    let result = verify_with_prepared_input(
                        black_box(&fixture.proof),
                        fixture.public_inputs.as_slice(),
                        &fixture.verifier_input,
                        &fixture.prepared_verifier_input,
                        &fixture.srs,
                    )
                    .expect("macrobench prepared verify iteration should succeed");
                    black_box(result);
                });
            },
        );
    }
    verify_group.finish();
}
