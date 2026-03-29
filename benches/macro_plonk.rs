//! Criterion entrypoint for the end-to-end Mini-Plonk macro benchmark.

mod macro_plonk_impl;

use criterion::{criterion_group, criterion_main};
use macro_plonk_impl::bench_macro_plonk;

criterion_group!(macro_plonk_benches, bench_macro_plonk);
criterion_main!(macro_plonk_benches);
