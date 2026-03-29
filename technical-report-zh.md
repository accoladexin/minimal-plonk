# 技术报告：作为可审计研究工程实现的 Minimal Plonk

## 1. 引言

本仓库基于 Rust 和 arkworks 原语实现了一个小而完整的 Plonk 证明系统。项目目标不是构建生产级 prover，也不是追求最大功能覆盖，而是产出一个具备以下特征的实现：

- 数学语义自洽
- 结构上可审计
- 测试与 benchmark 可复现
- 适合用于研究型展示

项目聚焦于 Plonk 的核心证明链路：

- witness 多项式
- 通过 grand-product 多项式实现的 permutation argument
- quotient 构造
- KZG commitment 与 opening
- Fiat-Shamir transcript replay
- 端到端 prover 与 verifier

这个项目最核心的工程动机，是把协议边界显式地保留下来。很多高层系统会把协议的代数结构、transcript 调度以及 verifier 最终的 pairing 检查隐藏在库封装后面；本仓库采用相反的策略：尽量让这些边界在代码中保持可读、可追踪，使其既是可执行系统，也是可审计对象。

## 2. 范围与边界

### 2.1 已覆盖内容

当前实现包含：

- 标准 Plonk gate 约束，使用 selector 列 `qL / qR / qO / qM / qC`
- 将 copy constraints 编译为 sigma permutation
- permutation grand-product 多项式 `Z(X)`
- 在当前 proof boundary 下的 quotient 构造
- KZG commitment、opening 与显式 pairing 验证
- 面向当前 proof layout 的 Fiat-Shamir transcript replay
- paper-aligned 的 prover 与 verifier 流程
- 针对当前最小协议边界的 zero-knowledge blinding 对齐
- 可复现的测试与 Criterion benchmark

### 2.2 明确不做的内容

当前实现明确不包含：

- lookup arguments
- recursion、aggregation 或 folding
- 生产环境可信设置流程
- 完整的 proving / verifying key 框架
- 面向部署的 production hardening、side-channel hardening 或使用性封装
- 通用 circuit DSL 或 gadget 生态

### 2.3 statement 与 proof boundary

当前落地的 statement boundary 为：

- 仅使用外部传入的 `public_inputs`

proof 内部不再保存 statement 的冗余副本。这样可以让 statement 语义更清晰，并避免 prover 携带的数据与 verifier 提供的数据之间产生“谁才是权威来源”的歧义。

当前落地的 proof boundary 包含：

- wire commitments `[A, B, C]`
- grand-product commitment `[Z]`
- quotient chunk commitments `[T_lo, T_mid, T_hi]`
- opening commitments `[W_z]` 与 `[W_{z omega}]`
- evaluations `a(zeta), b(zeta), c(zeta), S_sigma1(zeta), S_sigma2(zeta), Z(omega * zeta)`

这个边界对应仓库中 Phase 9/10 的 paper-aligned 落地结果，而不是更早期 Step 8 的最小 proof 形态。

## 3. 协议到代码的映射

本仓库的主要价值之一，是把协议对象到代码模块的映射显式保留下来。

| 协议对象 | 作用 | 代码位置 |
| -------- | ---- | -------- |
| radix-2 evaluation domain | 子群 `H`、FFT/IFFT、Lagrange、vanishing helpers | `src/domain/` |
| gate constraints | 按行组织的 Plonk 约束 | `src/cs/` |
| witness columns | `A/B/C` 的 evaluations 与 witness 多项式 | `src/witness/` |
| sigma permutation | 基于 copy constraints 的 wire position permutation | `src/permutation/sigma.rs` |
| grand-product polynomial | permutation argument `Z(X)` | `src/permutation/grand_product.rs` |
| quotient polynomial | 聚合后的 Plonk 主约束 | `src/quotient/quotient.rs` |
| polynomial commitments | KZG commit/open/verify | `src/kzg/` |
| transcript | Fiat-Shamir replay 与 challenge 推导 | `src/transcript.rs` |
| 共享协议类型 | proof 对象与 verifier 固定输入 | `src/types/` |
| prover orchestration | round 顺序、commitments、openings、proof 构造 | `src/prover.rs` |
| verifier orchestration | transcript replay、linearization 重建、pairing 检查 | `src/verifier.rs` |

当前 transcript 顺序固定为：

1. protocol separator
2. common preprocessed input
3. external `public_inputs`
4. wire commitments `[A, B, C]`，随后得到 `beta, gamma`
5. grand-product commitment `[Z]`，随后得到 `alpha`
6. quotient chunk commitments `[T_lo, T_mid, T_hi]`，随后得到 `zeta`
7. evaluation payload，随后得到 `v`
8. opening commitments `[W_z], [W_{z omega}]`，随后得到 `u`

这个顺序之所以重要，是因为它固定了 prover 和 verifier 如何得到相同 challenge，也避免了论文语义与工程 helper 之间发生漂移。

## 4. 关键设计决策

这一节总结了仓库中最重要的设计决策。

### 4.1 仅使用外部 public inputs

决策：

- 把 `public_inputs` 保持为 proof 外部输入

备选方案：

- 在 proof 内再保存一份 statement 副本

为什么这样选：

- statement 语义更明确
- 避免“prover 携带值”和“verifier 提供值”之间的权威冲突
- 更符合 verifier 侧外部提供 statement 的使用方式

代价：

- verifier API 必须始终显式接收外部 statement

### 4.2 Phase 9 的 paper-aligned proof boundary

决策：

- 从更早的最小 proof 形态转向 paper-aligned 的 chunked quotient 与显式 opening 边界

备选方案：

- 保留更早的单 quotient commitment 和更简单的 opening 结构

为什么这样选：

- 能更好地贴合标准 Plonk 的语义结构
- 便于读者对照论文理解 prover / verifier 流程
- 更有利于协议审计与 benchmark 解释

代价：

- 实现会比更早的最小版本更冗长、结构也更重

### 4.3 在 verifier 中显式保留 pairing 逻辑

决策：

- 让最终 pairing 等式直接保留在 verifier orchestration 中

备选方案：

- 把最终验证步骤完全隐藏在库调用背后

为什么这样选：

- verifier 透明性是本仓库的核心目标
- 可以让最终的代数检查关系保持可读
- 更有利于协议审查与研究展示

代价：

- 应用代码层面需要保留更多实现细节

### 4.4 将 verifier 固定预处理独立成单独阶段

决策：

- 暴露 `prepare_verifier_input(...)`，并把 verifier 固定数据预处理与 per-proof verification 分开计时

备选方案：

- 继续把所有固定数据预处理都放在 `verify()` 内部

为什么这样选：

- 可以让 full verifier benchmark 与 primitive baseline 的边界保持一致
- 避免夸大 verifier 的协议开销
- 让 benchmark 解释更诚实、更可复现

代价：

- verifier API 会稍微变大一些

### 4.5 只落地最小可接受 ZK，而不是完整 paper-style ZK

决策：

- 引入与当前 proof boundary 兼容的 witness / grand-product / quotient blinding
- 不把协议继续扩展成更大的 production-style hiding framework

备选方案：

- 立刻追求更广义、也更完整的 ZK 框架

为什么这样选：

- 能让 Phase 10 聚焦在当前已经落地的 prover / verifier 边界
- 避免把协议边界改造与额外 ZK 机制混在一起
- 满足仓库“最小研究工程实现”的目标

代价：

- 当前结果必须谨慎表述为最小或实用意义上的 ZK 对齐，而不是完整 hardened 的生产级 ZK 系统

## 5. Zero-Knowledge 对齐

当前实现已经包含以下 prover 侧 masking 行为：

- 对 `A(X), B(X), C(X)` 进行 witness blinding
- 对 `Z(X)` 进行 grand-product blinding
- 对 `T_lo / T_mid / T_hi` 进行 quotient chunk rerandomization

这些 blinded 对象随后被一致地用于：

- transcript 吸收
- evaluation 生成
- linearization 构造
- opening witness 生成
- verifier 侧检查

同样重要的是，Phase 10 并没有为此引入额外 proof 字段，也没有新增 transcript challenge。proof layout 与 transcript 顺序保持稳定，只是 prover 侧对象被替换为 blinded 版本。

不过，仓库并不宣称自己已经完全闭合了“完美零知识”的语义。当前 permutation 实现仍然会在 denominator 为零时 abort。Plonk 论文明确指出，这种 prover abort 会泄露与 witness 相关的信息，因此会把性质从 perfect ZK 降级为 practical/statistical 意义上的 ZK。

这个区分非常重要。对于研究展示而言，明确承认这个边界，比过度宣称“已经完全达到最强 paper-level ZK 语义”更可信。

## 6. Benchmark 方法

本仓库的 benchmark 目标是支持协议分析，而不是做性能宣传。

### 6.1 Microbench

仓库包含：

- FFT / IFFT microbench
- KZG open / verify microbench
- 显式 pairing microbench

这些 benchmark 用来隔离底层原语成本，为完整 proof pipeline 之外的计算提供更细粒度视角。

### 6.2 Full Macrobench

full macrobench 测量当前端到端 prover 与 verifier 路径。verifier 侧被刻意拆成两个阶段：

- `verify_fixed_preprocess`
- `verify_prepared`

这个拆分很重要，因为 verifier 固定数据预处理并不应与 per-proof transcript replay 和最终 pairing 检查混为同一种成本。

### 6.3 Primitive-Aligned Baseline

仓库还提供了一个 primitive-aligned 的 macro baseline。这个 baseline 不是“官方 arkworks Plonk prover / verifier”。它测量的是在相同条件下的 lower-bound 风格路径，条件包括：

- 相同曲线
- 相同 proof boundary
- 相同 domain size
- 相同 SRS bound

这个 baseline 分开测量：

- fixed preprocessing
- 沿当前 proof boundary 的 primitive prover 工作
- primitive opening verification

这样就可以把仓库中的完整协议编排，与更直接的 primitive path 做对比，而不需要错误地声称自己在和另一个官方 arkworks Plonk 实现做端到端比较。

### 6.4 Benchmark case 设计

当前 macrobench 包含两类 case：

- gate-dominant 的 MiMC case，其中 statement / permutation 负载是平凡的
- 一个带有非空 `public_inputs` 与非空 `copy_constraints` 的小型 non-trivial case

这个区分非常重要，因为如果 benchmark 只包含 gate-dominant 且 trivial-permutation 的 case，就会低估 statement binding 与 permutation machinery 的成本和审计意义。

## 7. 结果与观察

从实现和测量过程中，可以得到几条工程层面的观察。

### 7.1 Prover 开销仍然是主要差距来源

full prover path 明显重于 direct primitive path，这是预期中的结果。因为 full prover 并不只是做 commitment 和 opening；它还需要完成 transcript 调度、quotient 构造、linearization 构造以及 proof 组装。

### 7.2 Verifier 边界对齐会改变结论解释

在把 verifier 路径拆成 fixed preprocessing 与 prepared per-proof verification 之前，benchmark 很容易给出一个误导性的印象，好像 full verifier 比 primitive verifier 重很多。完成边界对齐后，在当前机器上，prepared full verifier 与 primitive verification 已经很接近。这个结果本质上首先是 benchmark 方法论的修正，而不仅仅是性能结果。

### 7.3 Benchmark 必须区分 trivial 与 non-trivial case

gate-dominant 的 MiMC benchmark 仍然有价值，但不能把它当成完整协议路径的通用代表。加入显式的 `public_input_copy_nontrivial` case 后，整个 benchmark suite 的解释力更强，也让项目作为研究展示材料更完整。

### 7.4 高质量实现也应包括 issue 管理

仓库现在保留了显式 issue 跟踪，用来记录 benchmark fairness、架构债务以及剩余协议 caveat。这一点很重要，因为一个研究工程实现不应只展示“做了什么”，也应展示“审查了什么”“修正了什么”“还剩什么未关闭的问题”。

## 8. 局限性与剩余风险

本仓库仍有一些明确局限。

### 8.1 不是生产级系统

这不是一个面向部署的 proving system。它不包含 production hardening、实际可信设置流程或更广泛的工程集成。

### 8.2 剩余的 ZK caveat

前面提到的 denominator-abort caveat 仍未从实现上消除。当前只是完成了准确文档化，而没有彻底修复这一点。

### 8.3 剩余结构债务

部分核心协议文件仍然需要进一步拆分，尤其是：

- `src/prover.rs`
- `src/quotient/quotient.rs`

这不是 correctness failure，但对 auditability 与 maintainability 仍然重要。

### 8.4 剩余源码可读性债务

虽然多份文档以及部分核心源码文件已经修复，但 source tree 中仍有部分注释需要继续清理，才能完全满足仓库自身的可读性规则。

### 8.5 Benchmark 覆盖仍然有限

当前 benchmark suite 已经有用且可复现，但覆盖面仍然偏窄：

- 电路家族有限
- 规模点有限
- 结果仍然主要基于单机本地快照

对于研究工程报告，这样的覆盖已经足够；但对于更广泛的性能结论而言，还远远不够。

## 9. 结论

本仓库更适合被理解为一个“可审计、可复现的 Minimal Plonk 研究工程实现”，而不是生产 prover，也不是单纯的教学练习。

它最主要的贡献不是协议设计创新，而是协议映射的显式化：

- paper-aligned 的 proof 与 transcript 边界
- 在 verifier 中保持可读的 pairing 逻辑
- 基于已落地 prover / verifier 路径的最小零知识对齐
- 区分 fixed preprocessing 与 per-proof verification 的 benchmark 方法
- 通过 issue 跟踪与文档化，使实现保持可审查性

因此，这个项目非常适合用作 zero-knowledge systems、applied cryptography engineering，以及 PhD 申请场景中的研究型展示材料，用来证明实现者具备把协议语义转换为纪律化工程实现的能力。
