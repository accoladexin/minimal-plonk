//! 共享错误定义（Step 0.3）。
//!
//! 规则：
//! - 这里只放“跨模块复用”的最小错误定义。
//! - 后续只在真实需求触发时再新增错误变体。

use core::fmt;

/// 项目统一错误类型（最小版）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlonkError {
    /// 输入不满足最基本前置条件时使用。
    InvalidInput(&'static str), // 是个元组变体，携带一个静态字符串作为错误信息。
    /// 长度关系不一致时使用（例如 domain_size 与向量长度不匹配）。
    InconsistentLength(&'static str),
}

impl fmt::Display for PlonkError {
    /// 统一错误文本输出，便于日志和测试比对。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid input: {message}"),
            Self::InconsistentLength(message) => write!(f, "inconsistent length: {message}"),
        }
    }
}

impl std::error::Error for PlonkError {}

/// 项目统一 `Result` 别名。
pub type Result<T> = core::result::Result<T, PlonkError>;
