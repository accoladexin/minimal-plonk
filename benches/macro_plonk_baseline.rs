//! Criterion entrypoint for the primitive-aligned macro baseline bench.

mod macro_plonk_baseline_impl;

use criterion::{criterion_group, criterion_main};
use macro_plonk_baseline_impl::bench_macro_plonk_baseline;

criterion_group!(macro_plonk_baseline_benches, bench_macro_plonk_baseline);
criterion_main!(macro_plonk_baseline_benches);
