# Technical Report: Minimal Plonk as an Auditable Research Engineering Implementation

## 1. Introduction

This repository implements a small but complete Plonk proof system in Rust on top of arkworks primitives. The project goal is not to build a production prover, nor to maximize feature coverage. Instead, the goal is to produce an implementation that is:

- mathematically coherent
- structurally auditable
- reproducible in testing and benchmarking
- suitable for research-oriented demonstration

The project focuses on the core Plonk proving pipeline:

- witness polynomials
- permutation argument via the grand-product polynomial
- quotient construction
- KZG commitments and openings
- Fiat-Shamir transcript replay
- end-to-end prover and verifier

The main engineering motivation is to make the protocol boundary explicit. In many high-level systems, the algebraic structure of the protocol, the transcript schedule, and the final verifier pairing logic are hidden behind library layers. This repository takes the opposite approach: the implementation keeps these boundaries readable and traceable, so the code can serve as both an executable system and an audit target.

## 2. Scope and Boundary

### 2.1 In Scope

The implementation currently covers:

- standard Plonk gate constraints with selector columns `qL / qR / qO / qM / qC`
- copy constraints compiled into a sigma permutation
- the permutation grand-product polynomial `Z(X)`
- quotient construction over the current proof boundary
- KZG commitment, opening, and explicit pairing-based verification
- Fiat-Shamir transcript replay for the current proof layout
- a paper-aligned prover and verifier flow
- zero-knowledge blinding alignment for the current minimal protocol boundary
- reproducible tests and Criterion benchmarks

### 2.2 Out of Scope

The implementation explicitly does not include:

- lookup arguments
- recursion, aggregation, or folding
- a production trusted setup workflow
- a full proving/verifying key framework
- production hardening, side-channel hardening, or deployment-focused ergonomics
- a general-purpose circuit DSL or gadget ecosystem

### 2.3 Statement and Proof Boundary

The current landed statement boundary is:

- external `public_inputs` only

The proof does not carry a duplicate statement copy. This keeps the statement semantics explicit and avoids ambiguity between prover-carried and verifier-supplied statement data.

The current landed proof boundary includes:

- wire commitments `[A, B, C]`
- grand-product commitment `[Z]`
- quotient chunk commitments `[T_lo, T_mid, T_hi]`
- opening commitments `[W_z]` and `[W_{z omega}]`
- evaluations `a(zeta), b(zeta), c(zeta), S_sigma1(zeta), S_sigma2(zeta), Z(omega * zeta)`

This boundary reflects the paper-aligned Phase 9/10 landing in the repository rather than the earlier minimal Step 8 proof shape.

## 3. Protocol Mapping

The main value of the repository is the explicit mapping from protocol objects to code modules.

| Protocol object | Role | Code location |
| --------------- | ---- | ------------- |
| radix-2 evaluation domain | subgroup `H`, FFT/IFFT, Lagrange, vanishing helpers | `src/domain/` |
| gate constraints | row-level Plonk equations | `src/cs/` |
| witness columns | `A/B/C` evaluations and interpolated witness polynomials | `src/witness/` |
| sigma permutation | copy-constraint permutation over wire positions | `src/permutation/sigma.rs` |
| grand-product polynomial | permutation argument `Z(X)` | `src/permutation/grand_product.rs` |
| quotient polynomial | aggregated Plonk constraints | `src/quotient/quotient.rs` |
| polynomial commitments | KZG commit/open/verify | `src/kzg/` |
| transcript | Fiat-Shamir replay and challenge derivation | `src/transcript.rs` |
| shared protocol types | proof objects and verifier fixed input | `src/types/` |
| prover orchestration | round ordering, commitments, openings, proof construction | `src/prover.rs` |
| verifier orchestration | transcript replay, linearization reconstruction, pairing check | `src/verifier.rs` |

The current transcript order is fixed as:

1. protocol separator
2. common preprocessed input
3. external `public_inputs`
4. wire commitments `[A, B, C]` leading to `beta, gamma`
5. grand-product commitment `[Z]` leading to `alpha`
6. quotient chunk commitments `[T_lo, T_mid, T_hi]` leading to `zeta`
7. evaluation payload leading to `v`
8. opening commitments `[W_z], [W_{z omega}]` leading to `u`

This ordering is important because it fixes how the prover and verifier derive the same challenges and prevents drift between paper semantics and implementation-specific helper structure.

## 4. Design Decisions

This section summarizes the most important design decisions in the repository.

### 4.1 External Public Inputs Only

Decision:

- keep `public_inputs` external to the proof

Alternative:

- store a copy of the public statement inside the proof

Why this was chosen:

- it keeps statement semantics explicit
- it avoids ambiguity over which statement source is authoritative
- it matches the intended verifier-side use of externally supplied public inputs

Tradeoff:

- the verifier API must always receive the external statement explicitly

### 4.2 Paper-Aligned Phase 9 Proof Boundary

Decision:

- move from an earlier minimal proof shape to the paper-aligned chunked quotient and explicit opening boundary

Alternative:

- keep the earlier single-quotient and simpler opening structure

Why this was chosen:

- it improves semantic alignment with standard Plonk structure
- it makes the prover/verifier flow more legible to someone reading against the paper
- it supports clearer benchmarking and protocol auditing

Tradeoff:

- the implementation becomes more verbose and structurally heavier than the earlier minimal landing

### 4.3 Explicit Pairing Logic in the Verifier

Decision:

- keep the final pairing equation visible inside verifier orchestration

Alternative:

- fully hide the final verification step behind a library call

Why this was chosen:

- verifier transparency is central to the repository goal
- it makes the final algebraic check inspectable
- it helps protocol review and research presentation

Tradeoff:

- slightly more implementation detail is kept in application code

### 4.4 Prepared Verifier Input as a Separate Stage

Decision:

- expose `prepare_verifier_input(...)` and measure verifier fixed preprocessing separately from per-proof verification

Alternative:

- keep all fixed-data preparation inside `verify()`

Why this was chosen:

- it aligns the full verifier benchmark boundary with the primitive baseline
- it avoids overstating verifier overhead
- it makes benchmark interpretation more honest and reproducible

Tradeoff:

- the verifier API surface becomes slightly larger

### 4.5 Minimal Acceptable ZK Instead of Full Paper-Style ZK

Decision:

- land witness, grand-product, and quotient blinding compatible with the current proof boundary
- do not expand the protocol toward a larger production-style hiding framework

Alternative:

- pursue a broader or more fully hardened ZK framework immediately

Why this was chosen:

- it keeps Phase 10 focused on the current landed prover/verifier boundary
- it avoids mixing protocol shape redesign with additional ZK machinery
- it satisfies the repository's minimal research-engineering target

Tradeoff:

- the current result should be described carefully as a minimal or practical ZK alignment, not as a fully hardened production ZK system

## 5. Zero-Knowledge Alignment

The current implementation includes the following prover-side masking behavior:

- witness blinding for `A(X), B(X), C(X)`
- grand-product blinding for `Z(X)`
- rerandomization of quotient chunks `T_lo / T_mid / T_hi`

These blinded objects are then used consistently in:

- transcript absorption
- evaluation generation
- linearization construction
- opening witness generation
- verifier-side checks

Just as importantly, the implementation does not introduce extra proof fields or new transcript challenges for Phase 10. The proof layout and transcript order remain stable while the prover-side objects become blinded.

However, the repository does not claim a fully closed perfect zero-knowledge story. The current permutation implementation still aborts if a denominator is zero. As discussed in the Plonk paper, such abort behavior leaks witness-dependent information and therefore downgrades the property from perfect ZK to a practical or statistical version of ZK under the current implementation boundary.

This distinction matters. For research presentation, it is better to state this limitation explicitly than to overclaim that the implementation has fully matched the strongest paper-level ZK semantics.

## 6. Benchmark Methodology

The benchmark suite is designed to support protocol analysis rather than raw performance advertising.

### 6.1 Microbench

The repository includes:

- FFT/IFFT microbench
- KZG open/verify microbench
- explicit pairing microbench

These benchmarks isolate primitive costs and provide a lower-level view of computation outside the full proof pipeline.

### 6.2 Full Macrobench

The full macrobench measures the current end-to-end prover and verifier path. The verifier side is intentionally split into:

- `verify_fixed_preprocess`
- `verify_prepared`

This separation matters because verifier-side fixed-data preprocessing is not a per-proof cost in the same sense as transcript replay and final pairing checks.

### 6.3 Primitive-Aligned Baseline

The repository also includes a primitive-aligned macro baseline. This baseline is not an "official arkworks Plonk prover/verifier". Instead, it measures a lower-bound style path using the same:

- curve
- proof boundary
- domain size
- SRS bound

The baseline separates:

- fixed preprocessing
- primitive proving work along the current proof boundary
- primitive opening verification

This makes it possible to compare the repository's full protocol orchestration against a more direct primitive path without claiming to benchmark against a separate official arkworks Plonk implementation.

### 6.4 Benchmark Cases

The macrobench suite currently includes:

- gate-dominant MiMC cases with trivial statement/permutation load
- a small non-trivial case with non-empty `public_inputs` and non-empty `copy_constraints`

This distinction is important because a benchmark suite that only includes gate-dominant trivial-permutation cases can understate the cost and audit significance of statement binding and permutation machinery.

## 7. Results and Observations

Several engineering observations emerged from the implementation and measurement process.

### 7.1 Prover Overhead Remains the Dominant Gap

The full prover path is consistently much heavier than the direct primitive path. This is expected: the full prover does more than commit and open polynomials. It also performs transcript scheduling, quotient construction, linearization construction, and proof assembly.

### 7.2 Verifier Boundary Alignment Changes the Interpretation

Before the verifier path was split into fixed preprocessing and prepared per-proof verification, the benchmark could misleadingly suggest that the full verifier was much heavier than the primitive verifier. After aligning the measurement boundary, the prepared full verifier is close to the primitive verification path on the current machine. This is a benchmark methodology result, not just a performance result.

### 7.3 Benchmark Scope Must Distinguish Trivial and Non-Trivial Cases

The gate-dominant MiMC benchmark is still useful, but it should not be read as a universal representative of the full protocol path. Adding the explicit non-trivial `public_input_copy_nontrivial` case improves the interpretability of the benchmark suite and makes the project stronger as a research demo.

### 7.4 Implementation Quality Includes Issue Tracking

The repository now keeps explicit issue tracking for benchmark fairness, architectural debt, and residual protocol caveats. This matters because a research engineering implementation should show not only what was built, but also what was audited, what was corrected, and what remains open.

## 8. Limitations and Residual Risks

The repository has several explicit limitations.

### 8.1 Not Production Grade

This is not a deployment-focused proving system. It does not include production hardening, operational trusted setup workflows, or broader ecosystem integration.

### 8.2 Residual ZK Caveat

The denominator-abort caveat described above remains open. The current implementation documents it, but does not yet remove it.

### 8.3 Remaining Structural Debt

Some large protocol files still need further decomposition, especially:

- `src/prover.rs`
- `src/quotient/quotient.rs`

This is not a correctness failure, but it remains relevant for auditability and maintainability.

### 8.4 Remaining Source Readability Debt

While several documentation files and some core source files have been repaired, parts of the source tree still need comment cleanup to fully satisfy the repository's readability rule.

### 8.5 Limited Benchmark Breadth

The benchmark suite is useful and reproducible, but still narrow:

- limited circuit families
- limited scale choices
- one-machine local snapshot

This is adequate for a research implementation report, but not enough for broad performance claims.

## 9. Conclusion

This repository should be understood as an auditable and reproducible research engineering implementation of a minimal Plonk system, not as a production prover and not as a mere tutorial exercise.

Its main contribution is not novelty in protocol design, but explicitness in protocol mapping:

- paper-aligned proof and transcript boundaries
- readable verifier pairing logic
- minimal zero-knowledge alignment over the landed prover/verifier path
- benchmark methodology that distinguishes fixed preprocessing from per-proof verification
- issue tracking and documentation that make the implementation reviewable

As a result, the project is well suited for research-oriented demonstration in zero-knowledge systems, applied cryptography engineering, and PhD application contexts where the ability to translate protocol semantics into a disciplined implementation is itself a meaningful signal.
