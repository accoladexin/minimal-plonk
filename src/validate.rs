//! 共享校验工具（Step 0.3）。
//!
//! 这里只放通用输入校验，不放具体协议逻辑。

use crate::error::{PlonkError, Result};

/// 统一断言入口：条件不满足时返回 `PlonkError::InvalidInput`。
pub fn ensure(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(PlonkError::InvalidInput(message))
    }
}

