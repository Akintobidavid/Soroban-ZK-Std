//! Phase 3 — Fuzzing the curve-validation components (G1 & G2 point parsing).
//!
//! The contract never trusts externally supplied curve points: every point is
//! run through `is_valid_g1` / `is_valid_g1_subgroup` (G1) and `is_on_curve` /
//! `is_in_correct_subgroup` (G2) before being used. This suite bombards those
//! validators with randomised, malformed, and out-of-bounds 32-byte coordinate
//! inputs to guarantee they *never panic* and that an invalid point is always
//! rejected (subgroup membership implies on-curve validity, and any coordinate
//! outside `Fq` can never be a valid point).
//!
//! `proptest` acts as the fuzzing engine: on the first failure it prints the
//! PRNG seed and the minimal counterexample, satisfying the determinism
//! requirement so the edge case can be frozen as a regression test.

use ethnum::u256;
use proptest::prelude::*;
use soroban_zk_core::Bn254;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn fuzz_g1_validation_no_panic(xb in any::<[u8; 32]>(), yb in any::<[u8; 32]>()) {
        let x = u256::from_be_bytes(xb);
        let y = u256::from_be_bytes(yb);

        // These must never panic regardless of input.
        let valid = Bn254::is_valid_g1(x, y);
        let in_subgroup = Bn254::is_valid_g1_subgroup(x, y);

        // Invariant: subgroup membership strictly implies on-curve validity.
        prop_assert!(!in_subgroup || valid);

        // Any coordinate outside the base field can never be a valid point.
        if x >= Bn254::FQ_MODULUS || y >= Bn254::FQ_MODULUS {
            prop_assert!(!valid, "coordinate outside Fq must be rejected");
        }
    }

    #[test]
    fn fuzz_g1_byte_decoding_no_panic(b in any::<[u8; 32]>()) {
        // Raw Fr/Fq decoding must always return an Option, never panic.
        let _ = Bn254::fr_from_bytes(b);
        let _ = Bn254::fq_from_bytes(b);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fuzz_g2_validation_no_panic(
        x0b in any::<[u8; 32]>(),
        x1b in any::<[u8; 32]>(),
        y0b in any::<[u8; 32]>(),
        y1b in any::<[u8; 32]>(),
    ) {
        let x = (u256::from_be_bytes(x0b), u256::from_be_bytes(x1b));
        let y = (u256::from_be_bytes(y0b), u256::from_be_bytes(y1b));

        // Never panic — full subgroup check runs a 254-bit scalar multiplication.
        let on_curve = Bn254::is_on_curve(x, y);
        let in_subgroup = Bn254::is_in_correct_subgroup(x, y);

        // Invariant: subgroup membership implies on-curve validity.
        prop_assert!(!in_subgroup || on_curve);

        // Any Fq² coefficient outside the base field can never be on-curve.
        if x.0 >= Bn254::FQ_MODULUS
            || x.1 >= Bn254::FQ_MODULUS
            || y.0 >= Bn254::FQ_MODULUS
            || y.1 >= Bn254::FQ_MODULUS
        {
            prop_assert!(!on_curve, "Fq² coefficient outside Fq must be rejected");
        }
    }
}
