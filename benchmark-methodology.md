# Benchmark Methodology and Limitations

## 1. Goal

The benchmark suite in this repository is designed for protocol engineering analysis of the current Minimal Plonk implementation. Its purpose is to explain where time is spent inside the landed prover and verifier paths, not to advertise a universally fast Plonk system and not to claim performance superiority over arkworks.

## 2. Environment

All reported benchmark snapshots in the repository should be interpreted together with the concrete execution environment:

- CPU model
- operating system
- Rust and Cargo versions
- active curve feature, currently `BN254` in the main README results
- build profile, typically Criterion `bench` profile
- exact benchmark command, such as `cargo bench --bench macro_plonk -- --nocapture`

This information is necessary because proof-system benchmarks are sensitive to machine, toolchain, curve, domain size, and build configuration.

## 3. Measured Workloads

The benchmark suite is divided into three layers.

### Microbench

The microbench layer isolates low-level primitives:

- FFT / IFFT
- KZG open / verify
- explicit pairing

These measurements are used to understand primitive costs and should not be read as end-to-end proof costs.

### Full macrobench

`macro_plonk` measures the current landed end-to-end prover and verifier path for this repository.

### Primitive-aligned baseline

`macro_plonk_baseline` measures a lower-bound style path built from the same proof boundary, curve family, domain scale, and SRS scale, but using a more direct primitive-oriented workflow.

## 4. Accounting Boundary

The verifier path is intentionally split into separate stages.

### Full path

- `verify_fixed_preprocess`
  - builds the transcript-bound fixed commitment view from verifier-side selector and sigma polynomials
- `verify_prepared`
  - measures per-proof verification after fixed preprocessing has already been performed

### Baseline path

- `fixed_preprocess`
  - measures the analogous fixed-data preprocessing for the baseline path
- `primitive_verify`
  - measures direct opening verification for the current proof boundary

### Comparison rule

Only the following verifier timings should be compared directly:

- `verify_prepared`
- `primitive_verify`

Fixed preprocessing must not be folded into the per-proof verifier gap. Earlier versions of the repository did mix these boundaries, and that interpretation was later corrected.

## 5. Benchmark Cases

The current macrobench suite includes two kinds of benchmark cases.

### Gate-dominant MiMC cases

- `mimc_gate_dominant_rounds_8`
- `mimc_gate_dominant_rounds_16`
- `mimc_gate_dominant_rounds_32`

These cases intentionally use:

- empty `public_inputs`
- empty `copy_constraints`

They are useful for studying gate-dominant scaling, but they do not represent a non-trivial statement-binding or permutation-heavy workload.

### Non-trivial public-input / copy-constraint case

- `public_input_copy_nontrivial`

This case explicitly includes:

- non-empty `public_inputs`
- non-empty `copy_constraints`

It is included so the benchmark suite does not only reflect trivial statement and permutation load.

## 6. Interpretation Rules

The benchmark results should be interpreted under the following rules:

- compare only runs with the same curve, domain size, and SRS bound
- do not combine microbench and macrobench numbers into a single direct conclusion
- do not describe the primitive baseline as an official arkworks Plonk prover/verifier
- do not generalize the results beyond the current implementation boundary without additional evidence

In particular, the primitive baseline is a primitive-aligned lower bound for the current repository boundary, not a separate full Plonk implementation from arkworks.

## 7. Limitations

The current benchmark suite has several explicit limitations.

### Limited protocol scope

The benchmarks only reflect the current repository scope. They do not include lookup arguments, recursion, aggregation, or production-grade proving infrastructure.

### Limited circuit diversity

The benchmark suite currently covers:

- MiMC gate-dominant cases
- one small non-trivial public-input / copy-constraint case

This is enough for a research engineering report, but not enough to claim broad circuit-level generality.

### Limited scale coverage

Only a small number of domain sizes and circuit scales are currently benchmarked. The results therefore show local scaling behavior, not a full asymptotic study.

### Baseline is not official arkworks Plonk

The primitive baseline should not be misread as an official arkworks end-to-end Plonk prover or verifier. It is only a lower-bound style comparison path under the same local proof boundary.

### Single-machine reporting

The benchmark snapshot currently reported in the repository comes from one local machine configuration. It is useful for reproducibility and engineering discussion, but it should not be treated as a hardware-independent performance claim.

## 8. Summary

The benchmark methodology in this repository is intended to be explicit, conservative, and reviewable. The main principle is that benchmark claims must follow the implementation boundary exactly. As a result, the benchmark suite is best understood as a measurement framework for the current Minimal Plonk engineering landing, rather than as a general performance statement about Plonk systems as a whole.
