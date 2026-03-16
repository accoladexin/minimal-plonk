# Minimal Plonk（Rust + arkworks）

## 项目动机（Motivation）

本项目是在系统学习零知识证明协议（尤其是 Plonk 系列）的过程中构建的。

与直接使用现成的高层框架不同，本项目的目标是：
- 从工程角度完整实现 Plonk 的核心协议流程
- 明确展示 permutation argument（grand product 多项式）的结构
- 在 verifier 中显式体现基于 pairing 的 KZG 验证逻辑
- 通过可复现的 benchmark，分析 Plonk 系统中的性能瓶颈

该项目旨在作为一个**研究型工程实现**，用于加深对 Plonk 协议、其工程权衡以及性能特征的理解。

> 注：本项目在文档中明确区分“已实现模块”与“规划模块”，
> 以避免读者将整体架构设计误解为完整落地实现。

## 工程设计风格说明

本项目刻意避免在早期阶段一次性设计完整的错误体系、
类型别名或通用工具集合。

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
- 标准 Plonk gate（qL, qR, qO, qM, qC）
- Permutation / copy constraints（grand product 多项式）
- 基于 KZG 的多项式承诺与打开（pairing-based）
- Fiat–Shamir 非交互化
- 可复现的性能 benchmark

### 非目标（Non-goals，刻意不做）
- Lookup arguments
- 递归证明、aggregation、folding
- 生产级可信设置（仅使用开发用 SRS）
- 完整电路 DSL 或 gadget 库

## 与 arkworks 的关系（Relation to arkworks）

本项目并非旨在超越或替代 arkworks。

arkworks 提供的底层原语（FFT、多项式、椭圆曲线与 pairing）被视为基准实现（baseline），
本项目的实现与 benchmark 主要用于分析：
- Plonk 协议中各阶段的性能分布
- permutation argument 与 KZG 验证的工程成本
- 不同模块在整体 prover / verifier 中的占比

因此，所有 benchmark 结果仅用于分析与理解，而非性能宣传。

## 高层架构概览

（由 AI 根据 architecture.md 自动补充）

## 构建与运行

```bash
cargo test
cargo run --example mimc
cargo bench
```

（由 AI 补充 curve feature 切换、benchmark 说明）

---

## Benchmark 方法 🤖【AI 写，按你定的标准】

```markdown
## Benchmark 方法

（由 AI 说明 benchmark 的具体实现方式，
但不得修改 benchmark 的评价标准）
```

## 项目状态

项目正在持续开发中。
当前进展请参见 `memory-bank/progress.md`。

### 当前实现状态（与 memory-bank 文档对齐）

#### [Implemented]
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

#### [Planned]
- `benches/`

### Current Roadmap

- Phase 9: paper-aligned prover / verifier refinement
- Phase 10: zero-knowledge blinding alignment
- Phase 11: benchmark
- Phase 12: documentation polish and reproducibility wrap-up

## 参考资料

- Gabizon et al., "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"
