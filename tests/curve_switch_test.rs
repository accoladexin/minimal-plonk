//! Step 0.1 验收测试：曲线 feature 可切换，且不需要改业务代码。

use minimal_plonk::curve::{Curve, Fr};

/// 当启用 `bn254` feature 时，Curve 应该是 ark_bn254::Bn254。
#[cfg(feature = "bn254")]
#[test]
fn curve_is_bn254_when_bn254_feature_enabled() {
    let curve_type = core::any::type_name::<Curve>();
    assert!(curve_type.contains("ark_bn254"), "Curve type: {curve_type}");

    // 简单 sanity：Fr 的加法应正常工作（字段运算）。
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    assert_eq!(a + b, Fr::from(3u64));
}

/// 当启用 `bls12_381` feature 时，Curve 应该是 ark_bls12_381::Bls12_381。
#[cfg(feature = "bls12_381")]
#[test]
fn curve_is_bls12_381_when_bls12_381_feature_enabled() {
    let curve_type = core::any::type_name::<Curve>();
    assert!(
        curve_type.contains("ark_bls12_381"),
        "Curve type: {curve_type}"
    );

    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    assert_eq!(a + b, Fr::from(3u64));
}
