//! Step 4.1 验收测试：
//! - 正确 wiring 构造出的 sigma 应通过双射校验
//! - 错误 wiring / 坏 sigma 应失败

use minimal_plonk::permutation::{
    Column, CopyConstraint, Pos, SigmaMapping, build_sigma_from_copy_constraints, pos_to_wire_id,
    validate_sigma_bijection,
};

/// 正确 wiring：包含单元素 cycle、多元素 cycle 和 fixed point 的混合场景。
#[test]
fn valid_wiring_builds_bijection_sigma() {
    let domain_size = 4usize;
    let constraints = vec![
        CopyConstraint {
            left: Pos {
                col: Column::A,
                row: 0,
            },
            right: Pos {
                col: Column::B,
                row: 1,
            },
        },
        CopyConstraint {
            left: Pos {
                col: Column::B,
                row: 1,
            },
            right: Pos {
                col: Column::C,
                row: 2,
            },
        },
        CopyConstraint {
            left: Pos {
                col: Column::A,
                row: 3,
            },
            right: Pos {
                col: Column::A,
                row: 3,
            },
        },
    ];

    let sigma = build_sigma_from_copy_constraints(domain_size, &constraints)
        .expect("valid wiring should build sigma");
    assert_eq!(sigma.sigma_ids().len(), 12);
    assert!(validate_sigma_bijection(&sigma).is_ok());

    let a0 = pos_to_wire_id(
        Pos {
            col: Column::A,
            row: 0,
        },
        domain_size,
    )
    .expect("id should exist");
    let b1 = pos_to_wire_id(
        Pos {
            col: Column::B,
            row: 1,
        },
        domain_size,
    )
    .expect("id should exist");
    let c2 = pos_to_wire_id(
        Pos {
            col: Column::C,
            row: 2,
        },
        domain_size,
    )
    .expect("id should exist");

    assert_eq!(sigma.image_at(a0).expect("image should exist"), b1);
    assert_eq!(sigma.image_at(b1).expect("image should exist"), c2);
    assert_eq!(sigma.image_at(c2).expect("image should exist"), a0);

    let a1 = pos_to_wire_id(
        Pos {
            col: Column::A,
            row: 1,
        },
        domain_size,
    )
    .expect("id should exist");
    assert_eq!(sigma.image_at(a1).expect("image should exist"), a1);
}

/// 错误 wiring：越界位置应在构造阶段失败。
#[test]
fn out_of_range_wiring_is_rejected() {
    let constraints = vec![CopyConstraint {
        left: Pos {
            col: Column::A,
            row: 0,
        },
        right: Pos {
            col: Column::C,
            row: 4,
        },
    }];

    let result = build_sigma_from_copy_constraints(4, &constraints);
    assert!(result.is_err());
}

/// 坏 sigma：重复像应失败。
#[test]
fn duplicated_sigma_image_is_rejected() {
    let result = SigmaMapping::from_raw_parts(2, vec![0, 0, 2, 3, 4, 5]);
    assert!(result.is_err());
}

/// 坏 sigma：长度不等于 3n 应失败。
#[test]
fn wrong_sigma_length_is_rejected() {
    let result = SigmaMapping::from_raw_parts(2, vec![0, 1, 2, 3, 4]);
    assert!(result.is_err());
}
