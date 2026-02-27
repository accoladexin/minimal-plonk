//! Step 0.3 验收测试：
//! - 共享错误定义可用
//! - 共享校验入口可用
//! - prelude 导出可直接使用

use minimal_plonk::{
    error::{PlonkError, Result as PlonkResult},
    prelude::*,
};

/// 校验通过时应返回 `Ok(())`。
#[test]
fn ensure_returns_ok_when_condition_is_true() {
    assert!(ensure(true, "must pass").is_ok());
}

/// 校验失败时应返回统一错误类型。
#[test]
fn ensure_returns_shared_error_when_condition_is_false() {
    let result = ensure(false, "bad input");
    assert_eq!(result, Err(PlonkError::InvalidInput("bad input")));
}

/// prelude 应提供常用共享类型导出。
#[test]
fn prelude_re_exports_are_usable() {
    let config = PlonkConfig::new(16, 3, TranscriptHash::Blake2b);
    let _: Fr = Fr::from(7u64);
    assert_eq!(config.transcript_hash_id, TranscriptHash::Blake2b.as_byte());
}

/// 统一 `PlonkResult` 别名应可直接使用。
#[test]
fn plonk_result_alias_is_usable() {
    let value: PlonkResult<u32> = Ok(42);
    assert_eq!(value, Ok(42));
}
