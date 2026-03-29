# Minimal Plonk

A small but complete Plonk proof system implemented in Rust with arkworks primitives.

## Overview

This project is a research-oriented implementation of a minimal Plonk system with:

- witness polynomials
- permutation argument via the grand-product polynomial
- quotient construction
- KZG commitments and openings
- Fiat-Shamir transcript replay
- end-to-end prover and verifier
- reproducible microbench and macrobench coverage

Artificial intelligence tools were used during development for drafting, refactoring support, and documentation assistance. All code committed to this project was reviewed by the author before being kept in the repository.

## What Is Implemented

The current repository includes:

- standard Plonk gates with `qL / qR / qO / qM / qC`
- copy constraints compiled into a sigma permutation
- grand-product polynomial `Z(X)`
- chunked quotient commitments `T_lo / T_mid / T_hi`
- explicit KZG commitment, opening, and pairing-based verification
- paper-aligned transcript and proof boundary
- minimal zero-knowledge blinding alignment for the landed prover/verifier path
- Criterion benchmarks for both primitive and end-to-end measurements

## Scope and Non-Goals

### In scope

- minimal but complete Plonk proving flow
- protocol clarity and auditability
- reproducible testing and benchmarking
- research-oriented engineering presentation

### Non-goals

- lookup arguments
- recursion, aggregation, or folding
- production trusted setup workflow
- production hardening
- full circuit DSL or gadget framework

## Quick Start

```bash
cargo test
cargo run --example mimc
cargo bench --no-run
cargo bench
```

## Benchmarks

The benchmark suite is designed for protocol engineering analysis, not for performance marketing.

It includes:

- microbench for FFT / IFFT
- microbench for KZG open / verify
- microbench for explicit pairing
- full macrobench for the landed prover / verifier path
- a primitive-aligned macro baseline measured under the same proof boundary

The verifier benchmark boundary is split into:

- fixed preprocessing
- prepared per-proof verification

This separation is intentional and is documented in the benchmark note below.

## Project Status

The core prover and verifier path is implemented and tested.

The repository currently represents:

- a paper-aligned Minimal Plonk implementation
- a reproducible research engineering artifact
- not a production proving system

## Further Reading

- [Technical Report](technical-report.md)
- [技术报告（中文）](technical-report.-zhmd)
- [Benchmark Methodology](benchmark-methodology.md)
- [Benchmark 方法说明（中文）](benchmark-methodology-zh.md)

