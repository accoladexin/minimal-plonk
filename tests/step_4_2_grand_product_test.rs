//! Step 4.2 验收测试：
//! - 正确 wiring（fixed-point / 非平凡 cycle）通过
//! - 错误 wiring 或破坏 copy 关系失败
//! - 分母为 0 时显式返回错误

use minimal_plonk::{
    curve::Fr,
    domain::{build_domain_from_size, polynomial_to_evaluations},
    permutation::{
        Column, CopyConstraint, Pos, build_sigma_from_copy_constraints,
        compute_grand_product_evaluations, interpolate_grand_product_evaluations,
        verify_grand_product_boundary, verify_grand_product_recurrence,
    },
};

#[test]
fn fixed_point_sigma_produces_all_one_z_and_closing_value() {
    let a_eval = vec![
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let b_eval = vec![
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let c_eval = vec![
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(11u64),
        Fr::from(12u64),
    ];
    let sigma = build_sigma_from_copy_constraints(4, &[]).expect("identity sigma should build");

    let z = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(17u64),
        Fr::from(19u64),
    )
    .expect("grand product should compute");

    assert_eq!(z.grand_product_evaluations.len(), 5);
    for value in &z.grand_product_evaluations {
        assert_eq!(*value, Fr::from(1u64));
    }
    assert!(
        verify_grand_product_recurrence(
            &z.grand_product_evaluations,
            &a_eval,
            &b_eval,
            &c_eval,
            &sigma,
            Fr::from(17u64),
            Fr::from(19u64),
        )
        .expect("recurrence check should run")
    );
    assert!(
        verify_grand_product_boundary(&z.grand_product_evaluations, 4)
            .expect("boundary check should run")
    );
}

#[test]
fn nontrivial_copy_cycle_passes_recurrence_and_boundary() {
    let mut a_eval = vec![
        Fr::from(11u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let mut b_eval = vec![
        Fr::from(5u64),
        Fr::from(11u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let mut c_eval = vec![
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(11u64),
        Fr::from(12u64),
    ];
    a_eval[0] = Fr::from(31u64);
    b_eval[1] = Fr::from(31u64);
    c_eval[2] = Fr::from(31u64);

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
    ];
    let sigma = build_sigma_from_copy_constraints(4, &constraints).expect("sigma should build");

    let z = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(13u64),
        Fr::from(29u64),
    )
    .expect("grand product should compute");

    assert_eq!(z.grand_product_evaluations.len(), 5);
    assert_eq!(z.grand_product_evaluations[4], Fr::from(1u64));
    assert!(
        verify_grand_product_recurrence(
            &z.grand_product_evaluations,
            &a_eval,
            &b_eval,
            &c_eval,
            &sigma,
            Fr::from(13u64),
            Fr::from(29u64),
        )
        .expect("recurrence check should run")
    );
    assert!(
        verify_grand_product_boundary(&z.grand_product_evaluations, 4)
            .expect("boundary check should run")
    );
}

#[test]
fn broken_copy_value_fails_boundary_check() {
    let a_eval = vec![
        Fr::from(31u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let mut b_eval = vec![
        Fr::from(5u64),
        Fr::from(31u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let c_eval = vec![
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(31u64),
        Fr::from(12u64),
    ];

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
    ];
    let sigma = build_sigma_from_copy_constraints(4, &constraints).expect("sigma should build");
    let z_valid = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(13u64),
        Fr::from(29u64),
    )
    .expect("valid z should compute");
    assert_eq!(z_valid.grand_product_evaluations[4], Fr::from(1u64));

    b_eval[1] = Fr::from(32u64);
    let z_broken = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(13u64),
        Fr::from(29u64),
    )
    .expect("broken witness z should compute");
    assert!(
        !verify_grand_product_boundary(&z_broken.grand_product_evaluations, 4)
            .expect("boundary check should run")
    );
}

#[test]
fn wrong_but_still_bijective_sigma_fails_row_recurrence_against_valid_z() {
    let a_eval = vec![
        Fr::from(31u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let b_eval = vec![
        Fr::from(5u64),
        Fr::from(31u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let c_eval = vec![
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(31u64),
        Fr::from(12u64),
    ];

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
    ];
    let sigma = build_sigma_from_copy_constraints(4, &constraints).expect("sigma should build");
    let z = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(13u64),
        Fr::from(29u64),
    )
    .expect("valid z should compute");

    let wrong_constraints = vec![CopyConstraint {
        left: Pos {
            col: Column::A,
            row: 0,
        },
        right: Pos {
            col: Column::C,
            row: 1,
        },
    }];
    let wrong_sigma =
        build_sigma_from_copy_constraints(4, &wrong_constraints).expect("sigma should build");

    assert!(
        !verify_grand_product_recurrence(
            &z.grand_product_evaluations,
            &a_eval,
            &b_eval,
            &c_eval,
            &wrong_sigma,
            Fr::from(13u64),
            Fr::from(29u64),
        )
        .expect("recurrence check should run")
    );
}

#[test]
fn denominator_zero_is_reported_explicitly() {
    let a_eval = vec![
        Fr::from(0u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let b_eval = vec![
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let c_eval = vec![
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(11u64),
        Fr::from(12u64),
    ];
    let sigma = build_sigma_from_copy_constraints(4, &[]).expect("identity sigma should build");

    let result = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(0u64),
        Fr::from(0u64),
    );
    assert!(result.is_err());
}

#[test]
fn interpolation_uses_prefix_n_points_only() {
    let a_eval = vec![
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let b_eval = vec![
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let c_eval = vec![
        Fr::from(9u64),
        Fr::from(10u64),
        Fr::from(11u64),
        Fr::from(12u64),
    ];
    let sigma = build_sigma_from_copy_constraints(4, &[]).expect("identity sigma should build");
    let z = compute_grand_product_evaluations(
        &a_eval,
        &b_eval,
        &c_eval,
        &sigma,
        Fr::from(17u64),
        Fr::from(19u64),
    )
    .expect("z should compute");

    let z_poly = interpolate_grand_product_evaluations(&z.grand_product_evaluations, 4)
        .expect("interpolation should succeed");
    let domain = build_domain_from_size(4).expect("domain should build");
    let round_trip =
        polynomial_to_evaluations(&domain, &z_poly).expect("evaluation should succeed");
    assert_eq!(round_trip, z.grand_product_evaluations[..4].to_vec());
}
