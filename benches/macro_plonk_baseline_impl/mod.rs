//! Criterion registration for the primitive-aligned macro baseline bench.

mod fixture;
mod fixed_data;
mod prove_inputs;
mod utils;

use criterion::{BenchmarkId, Criterion, black_box};
use fixture::build_baseline_fixtures;
use minimal_plonk::kzg::{verify_opening, verify_polynomials_at_same_point};
use minimal_plonk::verifier::prepare_verifier_input;
use utils::run_primitive_prove;

/// Register the baseline preprocess, prove, and verify macro benches.
pub fn bench_macro_plonk_baseline(c: &mut Criterion) {
    let fixtures = build_baseline_fixtures();

    let mut preprocess_group = c.benchmark_group("macro_plonk_baseline_preprocess_bn254");
    preprocess_group.sample_size(10);
    preprocess_group.warm_up_time(std::time::Duration::from_millis(500));
    preprocess_group.measurement_time(std::time::Duration::from_secs(2));
    for fixture in &fixtures {
        preprocess_group.bench_with_input(BenchmarkId::new("fixed_preprocess", fixture.case_id.as_str()), fixture, |b, fixture| {
            b.iter(|| {
                let output = prepare_verifier_input(&fixture.verifier_input, &fixture.srs)
                    .expect("baseline preprocess should succeed");
                black_box(output);
            });
        });
    }
    preprocess_group.finish();

    let mut prove_group = c.benchmark_group("macro_plonk_baseline_prove_bn254");
    prove_group.sample_size(10);
    prove_group.warm_up_time(std::time::Duration::from_millis(500));
    prove_group.measurement_time(std::time::Duration::from_secs(2));
    for fixture in &fixtures {
        prove_group.bench_with_input(BenchmarkId::new("primitive_prove", fixture.case_id.as_str()), fixture, |b, fixture| {
            b.iter(|| {
                let artifacts = run_primitive_prove(&fixture.prove_inputs, &fixture.srs);
                black_box(artifacts);
            });
        });
    }
    prove_group.finish();

    let mut verify_group = c.benchmark_group("macro_plonk_baseline_verify_bn254");
    verify_group.sample_size(10);
    verify_group.warm_up_time(std::time::Duration::from_millis(500));
    verify_group.measurement_time(std::time::Duration::from_secs(2));
    for fixture in &fixtures {
        verify_group.bench_with_input(BenchmarkId::new("primitive_verify", fixture.case_id.as_str()), fixture, |b, fixture| {
            b.iter(|| {
                let same_point = verify_polynomials_at_same_point(
                    fixture.verify_inputs.same_point_commitments.as_slice(),
                    fixture.verify_inputs.zeta,
                    fixture.verify_inputs.same_point_values.as_slice(),
                    fixture.verify_inputs.v,
                    &fixture.verify_inputs.same_point_proof,
                    &fixture.srs,
                )
                .expect("baseline same-point verify should run");
                let shifted = verify_opening(
                    &fixture.verify_inputs.grand_product_commitment,
                    fixture.verify_inputs.shifted_zeta,
                    fixture.verify_inputs.shifted_value,
                    &fixture.verify_inputs.shifted_proof,
                    &fixture.srs,
                )
                .expect("baseline shifted verify should run");
                black_box((same_point, shifted));
            });
        });
    }
    verify_group.finish();
}
