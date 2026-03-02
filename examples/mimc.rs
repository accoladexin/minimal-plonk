//! Step 2.2 最小示例：
//! - 单输入 MiMC-Feistel
//! - reference 输出对齐
//! - 电路约束验证通过

use minimal_plonk::{
    curve::Fr,
    mimc::{build_mimc_feistel_circuit, mimc_feistel, DEFAULT_ROUNDS},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // mimc的输出
    let input = Fr::from(7u64);
    // 直接调用 reference 实现获取预期输出，并构建电路验证约束满足。
    let expected_output = mimc_feistel(input, DEFAULT_ROUNDS)?;
    // 构建电路
    let build = build_mimc_feistel_circuit(input, DEFAULT_ROUNDS)?;

    // 验证电路输出与 reference 输出一致
    if build.output != expected_output {
        return Err("circuit output does not match reference output".into());
    }
    // gate是否正确
    if !build.circuit.are_all_gates_satisfied() {
        return Err("circuit constraints are not satisfied".into());
    }

    println!(
        "MiMC example passed: rounds={}, rows={}, domain_size={:?}",
        build.rounds,
        build.circuit.num_rows(),
        build.circuit.domain_size()
    );
    Ok(())
}
