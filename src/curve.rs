//! 曲线抽象层（Step 0.1）
//!
//! 目标：
//! - 默认使用 BN254
//! - 通过 Cargo feature 在不改业务代码的情况下切换到 BLS12-381
//!
//! 说明（给刚学 Rust 的同学）：
//! - arkworks 用 `Pairing` trait 抽象“配对友好曲线”
//! - 我们在这里统一导出 `Curve / Fr / G1 / G2`，让后续模块不关心具体曲线类型

use ark_ec::pairing::Pairing;

// 同时启用两条曲线会造成类型不确定，直接在编译期报错。
#[cfg(all(feature = "bn254", feature = "bls12_381"))]
compile_error!("feature `bn254` and `bls12_381` cannot be enabled at the same time");

/// 当前使用的配对曲线（默认 BN254）。
#[cfg(feature = "bn254")]
pub type Curve = ark_bn254::Bn254;

/// 当前使用的配对曲线（BLS12-381）。
#[cfg(feature = "bls12_381")]
pub type Curve = ark_bls12_381::Bls12_381;

/// 标量域（电路约束、挑战值等都在这个域里）。
pub type Fr = <Curve as Pairing>::ScalarField;

// 关键转换 (`from_projective`)**：

//- **Projective (G1)**：内部计算用的坐标 $(x, y, z)$，计算快但费空间。
//- **Affine (G1Affine)**：存储和传输用的坐标 $(x, y)$，结构紧凑。
// - **作用**：Prover 算完之后，会把结果“压缩”成 Affine 格式放进这个结构体。
/// G1 群（KZG 承诺通常在 G1 上做）。
/// Curve as Pairing 表明Cureve实现了Pairing trait，G1是这个trait中的一个关联类型。
pub type G1 = <Curve as Pairing>::G1;

/// G1 的仿射表示，适合做稳定序列化与承诺存储。
pub type G1Affine = <Curve as Pairing>::G1Affine;

/// G2 群（KZG 验证通常需要用到 G2）。
pub type G2 = <Curve as Pairing>::G2;

/// G2 的仿射表示，适合做公开参数与验证键存储。
pub type G2Affine = <Curve as Pairing>::G2Affine;
