//! Step 1.1：`2^k` 乘法子群（Radix-2 domain）构造工具。

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use crate::{curve::Fr, error::Result, types::DomainParams, validate::ensure};

/// 项目中统一使用的 FFT domain 类型。
pub type PlonkDomain = Radix2EvaluationDomain<Fr>;

/// 按 `log_size` 构造大小为 `2^k` 的 domain。
/// checked_shl`（带检查的左移）
pub fn build_domain_from_log_size(log_size: u32) -> Result<PlonkDomain> {
    let size = 1usize
        .checked_shl(log_size)
        .ok_or(crate::error::PlonkError::InvalidInput(
            "log_size is too large",
        ))?;
    build_domain_from_size(size)
}
/// （安全构造）按 `size` 构造 domain；要求 `size` 是 2 的幂。
pub fn build_domain_from_size(size: usize) -> Result<PlonkDomain> {
    ensure(size > 0, "domain size must be positive")?;
    ensure(size.is_power_of_two(), "domain size must be a power of two")?;
    PlonkDomain::new(size).ok_or(crate::error::PlonkError::InvalidInput(
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
