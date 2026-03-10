//! Step 1.1：`2^k` 乘法子群（Radix-2 domain）构造工具。

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use crate::{curve::Fr, error::Result, types::DomainParams, validate::ensure};

/// 项目中统一使用的 FFT domain 类型。
pub type PlonkDomain = Radix2EvaluationDomain<Fr>;

/// 按 `log_size` 构造大小为 `2^k` 的 domain。
/// checked_shl`（带检查的左移）
pub fn build_domain_from_log_size(log_size: u32) -> Result<PlonkDomain> {
    // 1usize.checked_shl(log_size)
    // 这一行在做： 1 << log_size (即 2 的 log_size 次方)
    let size = 1usize
        .checked_shl(log_size)
        // 关键点：checked_shl 是安全左移
        // 如果 log_size 太大（比如 128），会导致内存溢出（Overflow）
        // 普通的 << 会直接崩溃或绕回，checked_shl 则返回 None
        .ok_or(crate::error::PlonkError::InvalidInput(
            "log_size is too large",
        ))?; // 这里的 ? 意思是：如果是 None，就立刻把错误扔出去；如果是 Some，就把值解开给 size

    build_domain_from_size(size)
}
/// （安全构造）按 `size` 构造 domain；要求 `size` 是 2 的幂。
pub fn build_domain_from_size(size: usize) -> Result<PlonkDomain> {
    // 1. 确保 size 不是 0 (空域没意义)
    ensure(size > 0, "domain size must be positive")?;

    // 2. size.is_power_of_two()
    // 这是 Rust 整数类型的内置方法。
    // 它利用位运算 (size & (size - 1) == 0) 瞬间判断一个数是不是 2, 4, 8, 16...
    // 如果不是 2 的幂，FFT 算法在数学上就跑不通，这里直接拦截。
    ensure(size.is_power_of_two(), "domain size must be a power of two")?;

    // 3. PlonkDomain::new(size)
    // 这是 arkworks 库的构造函数。
    // 它去数学库里找有没有对应的单位根 ω 满足 ω^size = 1。
    PlonkDomain::new(size)
        // 如果 size 太大，超出了有限域能提供的最大范围（Max n），arkworks 会返回 None。
        .ok_or(crate::error::PlonkError::InvalidInput(
            "failed to build radix2 domain from size",
        ))
}
/// 从 domain 提取可序列化的最小参数结构。
/// - **作用**：`Radix2EvaluationDomain` 是一个很重、包含很多计算预设的结构。而 `DomainParams`（我们在 Step 0 定义的）是一个很轻、只存关键数（Size, LogSize, Generator）的结构。
/// - **意义**：这个函数负责将“计算工具”转为“可传输/序列化的数据”。
pub fn domain_params(domain: &PlonkDomain) -> DomainParams {
    DomainParams::new(
        domain.size() as u64,              // // 2^n，即电路中“行”的数量。
        domain.log_size_of_group() as u32, // n，即 size 的对数。
        domain.group_gen(),                // 生成元 单位原根 ω。
    )
}
