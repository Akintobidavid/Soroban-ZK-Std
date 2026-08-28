//! Phase 1 — Property-based tests for the BN254 *base field* `Fq` (modulus `q`).
//!
//! These mirror the existing `proptest_fr.rs` scalar-field suite but exercise
//! the base-field arithmetic (`add_fq` / `sub_fq` / `mul_fq` / `invert_fq` /
//! `sqrt_fq`) used by G1/G2 coordinate math. The randomness is supplied by
//! `proptest`, which already logs the PRNG seed and the minimal failing input
//! on every failure, satisfying the determinism requirement of the task.

use ethnum::u256;
use proptest::prelude::*;
use soroban_zk_core::Bn254;

/// Map an arbitrary 32-byte seed into a canonical `Fq` element `[0, q)`.
fn fq_from_seed(seed: [u8; 32]) -> u256 {
    u256::from_be_bytes(seed) % Bn254::FQ_MODULUS
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn fq_additive_identity_holds(a_bytes in any::<[u8; 32]>()) {
        let a = fq_from_seed(a_bytes);
        prop_assert_eq!(Bn254::add_fq(a, u256::from(0u8)), a);
    }

    #[test]
    fn fq_additive_inverse_holds(a_bytes in any::<[u8; 32]>()) {
        let a = fq_from_seed(a_bytes);
        let neg_a = Bn254::sub_fq(u256::from(0u8), a);
        prop_assert_eq!(Bn254::add_fq(a, neg_a), u256::from(0u8));
    }

    #[test]
    fn fq_addition_is_commutative(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = fq_from_seed(a_bytes);
        let b = fq_from_seed(b_bytes);
        prop_assert_eq!(Bn254::add_fq(a, b), Bn254::add_fq(b, a));
    }

    #[test]
    fn fq_addition_is_associative(
        a_bytes in any::<[u8; 32]>(),
        b_bytes in any::<[u8; 32]>(),
        c_bytes in any::<[u8; 32]>(),
    ) {
        let a = fq_from_seed(a_bytes);
        let b = fq_from_seed(b_bytes);
        let c = fq_from_seed(c_bytes);
        prop_assert_eq!(
            Bn254::add_fq(Bn254::add_fq(a, b), c),
            Bn254::add_fq(a, Bn254::add_fq(b, c))
        );
    }

    #[test]
    fn fq_multiplicative_identity_holds(a_bytes in any::<[u8; 32]>()) {
        let a = fq_from_seed(a_bytes);
        prop_assert_eq!(Bn254::mul_fq(a, u256::from(1u8)), a);
    }

    #[test]
    fn fq_multiplicative_inverse_holds(a_bytes in any::<[u8; 32]>()) {
        let a = fq_from_seed(a_bytes);
        prop_assume!(a != u256::from(0u8));
        let inv_a = Bn254::invert_fq(a);
        prop_assert_eq!(Bn254::mul_fq(a, inv_a), u256::from(1u8));
    }

    #[test]
    fn fq_multiplication_is_commutative(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = fq_from_seed(a_bytes);
        let b = fq_from_seed(b_bytes);
        prop_assert_eq!(Bn254::mul_fq(a, b), Bn254::mul_fq(b, a));
    }

    #[test]
    fn fq_multiplication_distributes_over_addition(
        a_bytes in any::<[u8; 32]>(),
        b_bytes in any::<[u8; 32]>(),
        c_bytes in any::<[u8; 32]>(),
    ) {
        let a = fq_from_seed(a_bytes);
        let b = fq_from_seed(b_bytes);
        let c = fq_from_seed(c_bytes);
        prop_assert_eq!(
            Bn254::mul_fq(Bn254::add_fq(a, b), c),
            Bn254::add_fq(Bn254::mul_fq(a, c), Bn254::mul_fq(b, c))
        );
    }

    /// A square root must square back to its argument for quadratic residues.
    /// We synthesise a residue as `r = t^2` and check `sqrt_fq(r)^2 == r`.
    #[test]
    fn fq_sqrt_squares_back(t_bytes in any::<[u8; 32]>()) {
        let t = fq_from_seed(t_bytes);
        let r = Bn254::mul_fq(t, t);
        let s = Bn254::sqrt_fq(r);
        prop_assert_eq!(Bn254::mul_fq(s, s), r);
    }
}
