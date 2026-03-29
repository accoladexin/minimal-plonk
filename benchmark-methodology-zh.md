# Benchmark 方法与限制说明

## 1. 目标

本仓库的 benchmark 套件用于分析当前 Minimal Plonk 实现中的协议工程开销。它的目标是解释当前 prover / verifier 路径中时间主要花在什么地方，而不是宣传一个“通用意义上更快”的 Plonk 系统，也不是宣称性能优于 arkworks。

## 2. 实验环境

仓库中记录的 benchmark 快照，都应当结合具体执行环境一起理解，包括：

- CPU 型号
- 操作系统
- Rust 与 Cargo 版本
- 当前启用的曲线 feature，README 主结果当前以 `BN254` 为准
- build profile，通常为 Criterion 的 `bench` profile
- 具体 benchmark 命令，例如 `cargo bench --bench macro_plonk -- --nocapture`

之所以必须写清这些信息，是因为证明系统 benchmark 对机器、工具链、曲线、domain size 以及编译配置都非常敏感。

## 3. 测量对象

本仓库的 benchmark 分成三层。

### Microbench

microbench 用来隔离底层原语开销，包括：

- FFT / IFFT
- KZG open / verify
- 显式 pairing

这些结果用于理解底层 primitive 成本，不能直接当作端到端 proof 成本来解读。

### Full macrobench

`macro_plonk` 测量本仓库当前已经落地的完整 prover / verifier 路径。

### Primitive-aligned baseline

`macro_plonk_baseline` 测量的是一个 lower-bound 风格的路径，它与当前仓库实现保持相同的：

- proof boundary
- 曲线
- domain 规模
- SRS 规模

但它采用更直接、更加 primitive-oriented 的 workflow。

## 4. 计量边界

verifier 路径被刻意拆成不同阶段。

### Full path

- `verify_fixed_preprocess`
  - 从 verifier 侧 selector / sigma 多项式构造 transcript 绑定的固定 commitment 视图
- `verify_prepared`
  - 在固定预处理已经完成之后，测量 per-proof verification 成本

### Baseline path

- `fixed_preprocess`
  - 测量 baseline 中对应的固定数据预处理
- `primitive_verify`
  - 测量当前 proof boundary 下的直接 opening verification

### 对比规则

只有下面两项 verifier 计时可以直接比较：

- `verify_prepared`
- `primitive_verify`

固定预处理不能再混入 per-proof verifier gap。仓库早期版本曾经混淆过这个边界，后续已经修正。

## 5. Benchmark Case 设计

当前 macrobench 套件包含两类 case。

### Gate-dominant 的 MiMC case

- `mimc_gate_dominant_rounds_8`
- `mimc_gate_dominant_rounds_16`
- `mimc_gate_dominant_rounds_32`

这些 case 有意使用：

- 空的 `public_inputs`
- 空的 `copy_constraints`

它们适合分析 gate-dominant 的规模变化，但不能代表非平凡 statement binding 或 permutation-heavy 的负载。

### 非平凡 public-input / copy-constraint case

- `public_input_copy_nontrivial`

这个 case 明确包含：

- 非空 `public_inputs`
- 非空 `copy_constraints`

加入它的目的，是避免整个 benchmark 套件只反映 trivial statement / permutation 的情况。

## 6. 结果解释规则

当前 benchmark 结果应按以下规则解读：

- 只比较相同曲线、相同 domain size、相同 SRS bound 的结果
- 不要把 microbench 和 macrobench 的数字混成一个直接结论
- 不要把 primitive baseline 表述成“官方 arkworks Plonk prover / verifier”
- 不要在没有额外证据的前提下，把结果外推成整个 Plonk 协议家族的通用性能结论

特别地，primitive baseline 的含义是“针对当前仓库 proof boundary 的 primitive-aligned lower bound”，而不是另一个来自 arkworks 的完整 Plonk 实现。

## 7. 局限性

当前 benchmark 套件存在若干明确限制。

### 协议范围有限

这些 benchmark 只反映当前仓库的实现范围，不包含 lookup、recursion、aggregation，或生产级 proving infrastructure。

### 电路多样性有限

目前 benchmark 只覆盖：

- MiMC gate-dominant case
- 一个小型的 non-trivial public-input / copy-constraint case

这对于研究工程报告已经足够，但不足以支撑广泛电路层面的泛化结论。

### 规模点有限

当前只覆盖了少量 domain size 与电路规模，因此这些结果更适合展示“局部规模行为”，而不是完整的渐近实验研究。

### Baseline 不是官方 arkworks Plonk

primitive baseline 不应被误读为 arkworks 官方端到端 Plonk prover / verifier。它只是当前本地 proof boundary 下的一个 lower-bound 风格对照路径。

### 当前结果主要来自单机

仓库中当前记录的 benchmark 快照来自单台本地机器配置。它适合做可复现性和工程讨论，但不应被解读为与硬件无关的性能声明。

## 8. 总结

本仓库的 benchmark 方法强调显式、保守和可审查。最核心的原则是：benchmark 结论必须严格服从当前实现边界。因此，这套 benchmark 最适合被理解为“用于分析当前 Minimal Plonk 工程落地结果的测量框架”，而不是对整个 Plonk 系统性能的通用结论。
