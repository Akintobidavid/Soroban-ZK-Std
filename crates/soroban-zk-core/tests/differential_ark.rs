//! Phase 2 — Differential testing against a trusted reference implementation.
//!
//! Every arithmetic result is computed independently with `arkworks` (ark-bn254
//! 0.6, the de-facto reference BN254 implementation) and asserted to be
//! *bit-for-bit identical* to `soroban-zk-core`. Inputs are pseudo-random
//! (proptest) so the comparison is exercised across the whole field, not just
//! hand-picked samples.
//!
//! On any mismatch proptest prints the PRNG seed and the minimal failing input,
//! so a discrepancy can be reproduced and frozen as a permanent regression test.

use ark_bn254::{Fq as ArkFq, Fr as ArkFr, G1Projective as ArkG1, G2Projective as ArkG2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ethnum::u256;
use proptest::prelude::*;
use soroban_zk_core::{Bn254, G1Affine, G2Projective};

// ----------------------------------------------------------------------------
// Conversion helpers between our `u256` representation and arkworks.
// ----------------------------------------------------------------------------

fn u256_to_ark_fr(x: u256) -> ArkFr {
    ArkFr::from_be_bytes_mod_order(&x.to_be_bytes())
}

fn u256_to_ark_fq(x: u256) -> ArkFq {
    ArkFq::from_be_bytes_mod_order(&x.to_be_bytes())
}

/// Convert an arkworks canonical `Fp` (big-endian, 32 bytes for BN254) to our `u256`.
fn ark_fp_to_u256<B: PrimeField>(x: B) -> u256 {
    let bytes = x.into_bigint().to_bytes_be();
    let arr: [u8; 32] = bytes.try_into().expect("BN254 field elements are 32 bytes");
    u256::from_be_bytes(arr)
}

fn ark_fr_to_u256(x: ArkFr) -> u256 {
    ark_fp_to_u256(x)
}

fn ark_fq_to_u256(x: ArkFq) -> u256 {
    ark_fp_to_u256(x)
}

/// The canonical BN254 G2 generator, matching `soroban_zk_std::vk::G2_GENERATOR`.
fn g2_generator() -> ((u256, u256), (u256, u256)) {
    let x0 = u256::from_be_bytes([
        24, 0, 222, 239, 18, 31, 30, 118, 66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247,
        94, 218, 221, 70, 222, 189, 92, 217, 146, 246, 237,
    ]);
    let x1 = u256::from_be_bytes([
        25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73, 51,
        53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194,
    ]);
    let y0 = u256::from_be_bytes([
        18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227, 209, 231,
        105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170,
    ]);
    let y1 = u256::from_be_bytes([
        9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149, 188, 75, 49, 51,
        112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91,
    ]);
    ((x0, x1), (y0, y1))
}

/// Full Fq² multiplicative inverse of `(a, b)` = `a + b·u`, where `u² = -1`.
/// The norm is `a² + b²`, so `(a + b·u)⁻¹ = (a, -b) / (a² + b²)`.
fn fq2_inverse(z: (u256, u256)) -> (u256, u256) {
    if z == (u256::from(0u8), u256::from(0u8)) {
        return (u256::from(0u8), u256::from(0u8));
    }
    let norm = Bn254::add_fq(Bn254::mul_fq(z.0, z.0), Bn254::mul_fq(z.1, z.1));
    let norm_inv = Bn254::invert_fq(norm);
    (
        Bn254::mul_fq(z.0, norm_inv),
        Bn254::sub_fq(u256::from(0u8), Bn254::mul_fq(z.1, norm_inv)),
    )
}

/// Convert our G2 projective point to affine coords. `z` is a *general* Fq²
/// element (it gains a non-zero imaginary part after the first doubling, since
/// `Z₃ = 2·Y·Z`), so a full Fq² inversion is required.
fn g2_to_affine(p: G2Projective) -> ((u256, u256), (u256, u256)) {
    if p.z == (u256::from(0u8), u256::from(0u8)) {
        return (
            (u256::from(0u8), u256::from(0u8)),
            (u256::from(0u8), u256::from(0u8)),
        );
    }
    let z_inv = fq2_inverse(p.z);
    let z_inv_sq = Bn254::fq2_sq(z_inv);
    let z_inv_cb = Bn254::fq2_mul(z_inv_sq, z_inv);
    (Bn254::fq2_mul(p.x, z_inv_sq), Bn254::fq2_mul(p.y, z_inv_cb))
}

// ----------------------------------------------------------------------------
// Scalar field (Fr / r) differential tests.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn diff_fr_add(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FR_MODULUS;
        let b = u256::from_be_bytes(b_bytes) % Bn254::FR_MODULUS;
        let our = Bn254::add(a, b);
        let ark_r = u256_to_ark_fr(a) + u256_to_ark_fr(b);
        prop_assert_eq!(our, ark_fr_to_u256(ark_r));
    }

    #[test]
    fn diff_fr_sub(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FR_MODULUS;
        let b = u256::from_be_bytes(b_bytes) % Bn254::FR_MODULUS;
        let our = Bn254::sub(a, b);
        let ark_r = u256_to_ark_fr(a) - u256_to_ark_fr(b);
        prop_assert_eq!(our, ark_fr_to_u256(ark_r));
    }

    #[test]
    fn diff_fr_mul(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FR_MODULUS;
        let b = u256::from_be_bytes(b_bytes) % Bn254::FR_MODULUS;
        let our = Bn254::mul(a, b);
        let ark_r = u256_to_ark_fr(a) * u256_to_ark_fr(b);
        prop_assert_eq!(our, ark_fr_to_u256(ark_r));
    }

    #[test]
    fn diff_fr_inv(a_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FR_MODULUS;
        prop_assume!(a != u256::from(0u8));
        let our = Bn254::invert(a);
        let ark_r = u256_to_ark_fr(a).inverse().unwrap();
        prop_assert_eq!(our, ark_fr_to_u256(ark_r));
    }
}

// ----------------------------------------------------------------------------
// Base field (Fq / q) differential tests.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn diff_fq_add(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FQ_MODULUS;
        let b = u256::from_be_bytes(b_bytes) % Bn254::FQ_MODULUS;
        let our = Bn254::add_fq(a, b);
        let ark_r = u256_to_ark_fq(a) + u256_to_ark_fq(b);
        prop_assert_eq!(our, ark_fq_to_u256(ark_r));
    }

    #[test]
    fn diff_fq_sub(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FQ_MODULUS;
        let b = u256::from_be_bytes(b_bytes) % Bn254::FQ_MODULUS;
        let our = Bn254::sub_fq(a, b);
        let ark_r = u256_to_ark_fq(a) - u256_to_ark_fq(b);
        prop_assert_eq!(our, ark_fq_to_u256(ark_r));
    }

    #[test]
    fn diff_fq_mul(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FQ_MODULUS;
        let b = u256::from_be_bytes(b_bytes) % Bn254::FQ_MODULUS;
        let our = Bn254::mul_fq(a, b);
        let ark_r = u256_to_ark_fq(a) * u256_to_ark_fq(b);
        prop_assert_eq!(our, ark_fq_to_u256(ark_r));
    }

    #[test]
    fn diff_fq_inv(a_bytes in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a_bytes) % Bn254::FQ_MODULUS;
        prop_assume!(a != u256::from(0u8));
        let our = Bn254::invert_fq(a);
        let ark_r = u256_to_ark_fq(a).inverse().unwrap();
        prop_assert_eq!(our, ark_fq_to_u256(ark_r));
    }
}

// ----------------------------------------------------------------------------
// Elliptic-curve scalar multiplication differential tests (G1 and G2).
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn diff_g1_scalar_mul(s_bytes in any::<[u8; 32]>()) {
        let s = u256::from_be_bytes(s_bytes) % Bn254::FR_MODULUS;
        let base = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let our = base.scalar_mul(s);
        let ark_res = ArkG1::generator() * u256_to_ark_fr(s);
        let ark_aff = ark_res.into_affine();
        prop_assert_eq!(our.x, ark_fq_to_u256(ark_aff.x));
        prop_assert_eq!(our.y, ark_fq_to_u256(ark_aff.y));
    }

    #[test]
    fn diff_g2_scalar_mul(s_bytes in any::<[u8; 32]>()) {
        let s = u256::from_be_bytes(s_bytes) % Bn254::FR_MODULUS;
        let ((x0, x1), (y0, y1)) = g2_generator();
        let our = Bn254::g2_scalar_mul(
            G2Projective {
                x: (x0, x1),
                y: (y0, y1),
                z: (u256::from(1u8), u256::from(0u8)),
            },
            s,
        );
        let (our_x, our_y) = g2_to_affine(our);

        let ark_res = ArkG2::generator() * u256_to_ark_fr(s);
        let ark_aff = ark_res.into_affine();
        let ark_x = (ark_fq_to_u256(ark_aff.x.c0), ark_fq_to_u256(ark_aff.x.c1));
        let ark_y = (ark_fq_to_u256(ark_aff.y.c0), ark_fq_to_u256(ark_aff.y.c1));

        prop_assert_eq!(our_x, ark_x);
        prop_assert_eq!(our_y, ark_y);
    }
}
