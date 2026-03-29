# Minimal Plonk（Rust + arkworks）

## 项目动机（Motivation）

本项目是在系统学习零知识证明协议，尤其是 Plonk 系列协议的过程中构建的。

与直接使用现成的高层框架不同，本项目的目标是：
- 从工程视角完整实现 Plonk 的核心协议流程
- 明确展示 permutation argument（grand product 多项式）的结构
- 在 verifier 中显式体现基于 pairing 的 KZG 验证逻辑
- 通过可复现的 benchmark，分析 Plonk 系统中的性能瓶颈

该项目旨在作为一个研究型工程实现，用于加深对 Plonk 协议、其工程权衡以及性能特征的理解。

> 注：本项目在文档中明确区分“已实现模块”与“规划模块”，以避免读者将整体架构设计误解为完整落地实现。

## 工程设计风格说明

本项目刻意避免在早期阶段一次性设计完整的错误体系、类型别名或通用工具集合。

相反，项目采用“按需渐进扩展”的工程策略：
- 仅在某一协议步骤被真实需求阻塞时，才引入新的共享定义
- 所有具有复用价值的定义集中管理，避免模块间重复与漂移
- 每一次扩展均可在文档中追踪其引入背景与用途

该策略旨在：
- 降低过早抽象带来的复杂性
- 保持实现与协议步骤之间的清晰对应关系
- 使工程结构随协议理解逐步演进

## 项目范围与非目标（Scope & Non-goals）

### 项目范围（In Scope）
- 标准 Plonk gate（`qL`, `qR`, `qO`, `qM`, `qC`）
- Permutation / copy constraints（grand product 多项式）
- 基于 KZG 的多项式承诺与打开（pairing-based）
- Fiat-Shamir 非交互化
- 可复现的性能 benchmark

### 非目标（Non-goals，刻意不做）
- Lookup arguments
- 递归证明、aggregation、folding
- 生产级可信设置（仅使用开发用 SRS）
- 完整电路 DSL 或 gadget 库

## 与 arkworks 的关系（Relation to arkworks）

本项目并非旨在超越或替代 arkworks。

arkworks 提供的底层原语（FFT、多项式、椭圆曲线与 pairing）被视为基准实现（baseline），本项目的实现与 benchmark 主要用于分析：
- Plonk 协议中各阶段的性能分布
- permutation argument 与 KZG 验证的工程成本
- 不同模块在整体 prover / verifier 中的占比

因此，所有 benchmark 结果仅用于分析与理解，而非性能宣传。

## 高层架构概览

当前仓库已经形成一条可运行、可审计、可 benchmark 的最小完整 Plonk 路径：

- `src/domain/`：`2^k` radix-2 domain、FFT / IFFT、Lagrange 与 vanishing helpers
- `src/cs/`：gate、circuit、padding/freeze 规则与 selector 提取
- `src/mimc/`：MiMC-Feistel reference 与示例电路构造
- `src/witness/`：`A/B/C` 三列 witness 点值与插值
- `src/permutation/`：copy constraints、sigma mapping 与 grand product `Z(X)`
- `src/quotient/`：quotient 聚合、`T_lo / T_mid / T_hi` chunking、linearization 相关工具
- `src/kzg/`：SRS、commit、open、显式 pairing verify
- `src/transcript.rs`：固定的 Fiat-Shamir transcript 顺序
- `src/prover.rs` / `src/verifier.rs`：当前协议边界下的端到端证明与验证编排
- `benches/`：Criterion microbench 与 macrobench 入口

当前落地的 proof boundary 与 verifier flow 保持论文语义上的主结构：

- commitments：`[A, B, C]`、`[Z]`、`[T_lo, T_mid, T_hi]`、`[W_z]`、`[W_{z omega}]`
- evaluations：`a(zeta)`、`b(zeta)`、`c(zeta)`、`S_sigma1(zeta)`、`S_sigma2(zeta)`、`Z(omega * zeta)`
- statement boundary：只使用 external `public_inputs`，proof 内不再携带 statement 副本
- opening flow：same-point opening at `zeta` + shifted opening for `Z(omega * zeta)`，并保留显式 `u` 聚合
- verifier：显式重放 transcript，显式重建线性化相关承诺项，显式执行 pairing 检查

当前实现还包含最小可接受的零知识对齐：

- `A(X) / B(X) / C(X)` 已加入 witness blinding
- `Z(X)` 已加入与当前协议边界兼容的 blinding
- `T_lo / T_mid / T_hi` 已加入 chunk 级 re-randomization
- proof layout 与 transcript challenge 集合未因 blinding 扩张

## 构建与运行

### 环境要求

- Rust stable toolchain
- 默认曲线 feature：`bn254`
- 可选编译 feature：`bls12_381`

### 常用命令

```bash
cargo test
cargo run --example mimc
cargo bench --no-run
cargo bench
```

### 按入口运行

```bash
cargo test --test step_9_4_verifier_refactor_test
cargo run --example mimc
cargo bench --bench micro_fft
cargo bench --bench micro_kzg
cargo bench --bench micro_pairing
cargo bench --bench macro_plonk
```

### 曲线 feature 切换

默认所有 README 中的复现口径都以 `bn254` 为准。如果只想验证另一条曲线 feature 能否编译，可使用：

```bash
cargo test --no-default-features --features bls12_381
```

注意：
- 当前 benchmark 命名、README 说明与已记录的结果口径默认都以 `BN254` 为准
- 如果切换曲线，不能直接把结果与 README 中的 BN254 基线混合解读

## Benchmark 方法

本仓库的 benchmark 目标是“协议工程分析”，不是“跑出一个更快的数字”。因此所有 benchmark 都要求参数可追踪、输入固定、命令可复现。

### Microbench

`cargo bench` 会包含以下三类 microbench：

- `micro_fft`
  - 曲线：`BN254`
  - domain size：`2^8`、`2^10`、`2^12`、`2^14`
  - 指标：FFT / IFFT
- `micro_kzg`
  - 曲线：`BN254`
  - polynomial degree：`255`、`1023`、`4095`
  - SRS：`max_degree = degree`
  - 指标：单点 opening / verify
- `micro_pairing`
  - 曲线：`BN254`
  - 输入：固定 `G1/G2` 点，避免把点生成时间混入测量
  - 指标：单次显式 pairing

### Macrobench

`macro_plonk` 负责端到端 `prove / verify`：

- 电路：MiMC-Feistel
- rounds：`8`、`16`、`32`
- 曲线：`BN254`
- SRS：按 case 的 padded `domain_size` 动态生成，`max_degree = next_power_of_two(8 * domain_size)`
- benchmark ID：显式包含 `curve / rounds / domain / srs_max_degree`

除了 Criterion 的迭代结果外，`macro_plonk` 还会打印一次性摘要，用于辅助解释结果：

- `proof_size_bytes`
- `setup_ms`
- `prove_ms`
- `verify_ms`
- `setup / prove / verify` 的粗粒度占比

### 结果解读约束

- 只能比较相同曲线、相同 domain size、相同 SRS 上界下的结果
- 不能把 microbench 与 macrobench 的绝对时间直接混为同一结论
- 不能把本仓库 benchmark 结果写成“优于 arkworks”的宣传语
- 如需与 arkworks 或其他实现对比，必须先对齐曲线、domain、SRS 和多项式次数

Criterion 输出默认位于 `target/criterion/`。

## 项目状态

当前项目已经完成从 Phase 0 到 Phase 12.1 的主线落地，核心 prover / verifier 与 benchmark 入口均已可运行。

### 当前已实现模块

- `src/curve.rs`
- `src/domain/`
- `src/cs/`
- `src/mimc/`
- `src/witness/`
- `src/error.rs`
- `src/prelude.rs`
- `src/transcript.rs`
- `src/types/`
- `src/validate.rs`
- `src/permutation/`
- `src/quotient/`
- `src/kzg/`
- `src/prover.rs`
- `src/verifier.rs`
- `examples/mimc.rs`
- `benches/micro_fft.rs`
- `benches/micro_kzg.rs`
- `benches/micro_pairing.rs`
- `benches/macro_plonk.rs`

### 当前主线状态

- Phase 9：paper-aligned prover / verifier refinement 已完成
- Phase 10：zero-knowledge blinding alignment 已完成
- Phase 11：microbench / macrobench 已完成
- Phase 12.1：documentation and reproducibility 已完成

更细的 Step 状态请查看 `memory-bank/progress.md`。

## 参考资料

- `reference/Plonk.pdf`
- arkworks crates: `ark-ff`, `ark-poly`, `ark-poly-commit`, `ark-ec`
- Criterion benchmark framework: <https://github.com/bheisler/criterion.rs>
