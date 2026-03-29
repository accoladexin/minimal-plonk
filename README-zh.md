# Minimal Plonk

一个基于 Rust 与 arkworks 原语实现的“小而完整”的 Plonk 证明系统。

## 项目概览

本项目是一个面向研究展示的 Minimal Plonk 实现，覆盖了：

- witness 多项式
- 基于 grand-product 多项式的 permutation argument
- quotient 构造
- KZG commitment 与 opening
- Fiat-Shamir transcript replay
- 端到端 prover 与 verifier
- 可复现的 microbench 与 macrobench

项目开发过程中借助了人工智能工具来辅助草稿整理、重构支持与文档编写，但仓库中保留的所有代码都经过作者本人审阅后才被接受。

## 已实现内容

当前仓库已经包含：

- 标准 Plonk gate，使用 `qL / qR / qO / qM / qC`
- 将 copy constraints 编译为 sigma permutation
- grand-product 多项式 `Z(X)`
- 分块 quotient commitments `T_lo / T_mid / T_hi`
- 显式 KZG commitment、opening 与 pairing 验证
- paper-aligned 的 transcript 与 proof boundary
- 面向当前 prover/verifier 边界的最小 zero-knowledge blinding 对齐
- 同时覆盖 primitive 与 end-to-end 路径的 Criterion benchmark

## 范围与非目标

### 项目范围

- 最小但完整的 Plonk 证明流程
- 强调协议清晰性与可审计性
- 可复现的测试与 benchmark
- 面向研究型工程展示

### 非目标

- lookup arguments
- recursion、aggregation 或 folding
- 生产环境 trusted setup 流程
- production hardening
- 完整 circuit DSL 或 gadget framework

## 快速开始

```bash
cargo test
cargo run --example mimc
cargo bench --no-run
cargo bench
```

## Benchmark

本仓库的 benchmark 目标是协议工程分析，而不是性能宣传。

当前包含：

- FFT / IFFT 的 microbench
- KZG open / verify 的 microbench
- 显式 pairing 的 microbench
- 当前 prover / verifier 路径的 full macrobench
- 在同一 proof boundary 下的 primitive-aligned macro baseline

其中 verifier benchmark 被拆成：

- fixed preprocessing
- prepared per-proof verification

这个拆分是有意为之，详细解释见下面的 benchmark 方法文档。

## 当前状态

核心 prover / verifier 主路径已经实现并通过测试。

当前仓库更适合被理解为：

- 一个 paper-aligned 的 Minimal Plonk 实现
- 一个可复现的研究型工程成果
- 而不是生产级 proving system

## 延伸阅读

- [Technical Report](technical-report.md)
- [技术报告（中文）](technical-report.-zhmd)
- [Benchmark Methodology](benchmark-methodology.md)
- [Benchmark 方法说明（中文）](benchmark-methodology-zh.md)

