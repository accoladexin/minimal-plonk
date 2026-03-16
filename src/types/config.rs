//! Shared configuration types.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::curve::Fr;

/// Supported transcript hash backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptHash {
    Blake2b,
    Sha256,
}

impl TranscriptHash {
    /// 功能说明：返回稳定的哈希后端编号，便于序列化和调试。
    /// 输入：一个 `TranscriptHash` 枚举值。
    /// 输出：对应的固定 `u8` 编号。
    /// 示例：`TranscriptHash::Blake2b.as_byte()` 会返回 `0`。
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Blake2b => 0,
            Self::Sha256 => 1,
        }
    }
}

impl Default for TranscriptHash {
    /// 功能说明：提供项目当前默认的 transcript 哈希后端。
    /// 输入：无。
    /// 输出：默认的 `TranscriptHash::Blake2b`。
    /// 示例：`TranscriptHash::default()`。
    fn default() -> Self {
        Self::Blake2b
    }
}

/// Basic radix-2 domain parameters shared across modules.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DomainParams {
    pub size: u64,
    pub log_size: u32,
    pub generator: Fr,
}

impl DomainParams {
    /// 功能说明：构造一个最小 domain 参数对象。
    /// 输入：domain 大小、`log2(size)`、以及生成元。
    /// 输出：一个可序列化的 `DomainParams`。
    /// 示例：`DomainParams::new(8, 3, omega)`。
    pub fn new(size: u64, log_size: u32, generator: Fr) -> Self {
        Self {
            size,
            log_size,
            generator,
        }
    }
}

/// Global protocol configuration shared by tests and examples.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkConfig {
    pub max_degree: u64,
    pub num_wire_columns: u32,
    pub transcript_hash_id: u8,
}

impl PlonkConfig {
    /// 功能说明：构造一个最小协议配置对象。
    /// 输入：SRS 最大次数、wire 列数、以及 transcript 哈希后端。
    /// 输出：一个可序列化的 `PlonkConfig`。
    /// 示例：`PlonkConfig::new(16, 3, TranscriptHash::Blake2b)`。
    pub fn new(max_degree: u64, num_wire_columns: u32, transcript_hash: TranscriptHash) -> Self {
        Self {
            max_degree,
            num_wire_columns,
            transcript_hash_id: transcript_hash.as_byte(),
        }
    }
}
