//! Phase 1 — Explicit boundary-condition fixtures for field arithmetic.
//!
//! Property tests are great at exploring the *bulk* of the field, but they are
//! probabilistically unlikely to ever hit the exact edges (zero, `q - 1`, `q`,
//! negative wrap-around). These hand-picked fixtures pin down those corners so a
//! regression at the modulus boundary is caught deterministically.

use ethnum::u256;
use soroban_zk_core::Bn254;

const ZERO: u256 = u256::from_words(0u128, 0u128);

// ============================================================================
// Scalar field Fq (r) boundaries  — note: Bn254::add/sub/mul operate over Fr.
// ============================================================================

#[test]
fn fr_zero_is_additive_identity() {
    assert_eq!(Bn254::add(ZERO, ZERO), ZERO);
    assert_eq!(
        Bn254::add(Bn254::FR_MODULUS - u256::from(1u8), ZERO),
        Bn254::FR_MODULUS - u256::from(1u8)
    );
}

#[test]
fn fr_zero_annihilates_multiplication() {
    let a = Bn254::FR_MODULUS - u256::from(7u8);
    assert_eq!(Bn254::mul(ZERO, a), ZERO);
    assert_eq!(Bn254::mul(a, ZERO), ZERO);
}

#[test]
fn fr_q_minus_one_is_largest_valid_element() {
    let qm1 = Bn254::FR_MODULUS - u256::from(1u8);
    // (q-1) + 1 wraps exactly to 0.
    assert_eq!(Bn254::add(qm1, u256::from(1u8)), ZERO);
    // (q-1) + (q-1) = 2q - 2 = q - 2 (mod q).
    assert_eq!(Bn254::add(qm1, qm1), Bn254::FR_MODULUS - u256::from(2u8));
}

#[test]
fn fr_exactly_q_wraps_modulo() {
    // Inputs >= the modulus are not "field elements", but the arithmetic must
    // stay memory-safe (never panic). `add` performs a single modular reduction
    // and assumes canonical inputs, so `q + 1` correctly wraps to `1` while
    // `q + q` itself is an out-of-contract input. The authoritative boundary
    // check lives in `fr_from_bytes`/`SafeFrom`, which reject `q` outright
    // (see `fr_from_bytes_rejects_modulus_and_above`).
    let a = Bn254::FR_MODULUS; // == 0 mod r
    assert_eq!(Bn254::add(a, u256::from(1u8)), u256::from(1u8));
    assert_eq!(Bn254::add(a, ZERO), ZERO);
    // Multiplication of an over-modulus value normalises via `% modulus`.
    assert_eq!(Bn254::mul(a, u256::from(5u8)), ZERO);
}

#[test]
fn fr_negative_wrap_around() {
    // 0 - 1 underflows to q - 1 (the modular additive inverse of 1).
    assert_eq!(
        Bn254::sub(ZERO, u256::from(1u8)),
        Bn254::FR_MODULUS - u256::from(1u8)
    );
    // (0 - a) + a == 0 for any a.
    let a = u256::from(12345u64);
    assert_eq!(Bn254::add(Bn254::sub(ZERO, a), a), ZERO);
}

#[test]
fn fr_inverse_of_zero_is_zero() {
    // The spec defines invert(0) = 0 to avoid a divide-by-zero panic; callers
    // must check before inverting. Bit-for-bit it must stay 0.
    assert_eq!(Bn254::invert(ZERO), ZERO);
}

#[test]
fn fr_inverse_of_q_minus_one_is_itself() {
    // q - 1 is its own inverse because (q-1)^2 = q^2 - 2q + 1 = 1 (mod q).
    let qm1 = Bn254::FR_MODULUS - u256::from(1u8);
    assert_eq!(Bn254::invert(qm1), qm1);
}

// ============================================================================
// Base field Fq (q) boundaries — used by G1/G2 coordinate validation.
// ============================================================================

#[test]
fn fq_zero_is_additive_identity() {
    assert_eq!(Bn254::add_fq(ZERO, ZERO), ZERO);
}

#[test]
fn fq_q_minus_one_wraps() {
    let qm1 = Bn254::FQ_MODULUS - u256::from(1u8);
    assert_eq!(Bn254::add_fq(qm1, u256::from(1u8)), ZERO);
    assert_eq!(Bn254::sub_fq(ZERO, u256::from(1u8)), qm1);
}

#[test]
fn fq_exactly_q_wraps_modulo() {
    let a = Bn254::FQ_MODULUS;
    assert_eq!(Bn254::add_fq(a, u256::from(1u8)), u256::from(1u8));
    assert_eq!(Bn254::mul_fq(a, u256::from(5u8)), ZERO);
}

#[test]
fn fq_negative_wrap_around() {
    assert_eq!(
        Bn254::sub_fq(ZERO, u256::from(1u8)),
        Bn254::FQ_MODULUS - u256::from(1u8)
    );
}

#[test]
fn fq_inverse_of_zero_is_zero() {
    assert_eq!(Bn254::invert_fq(ZERO), ZERO);
}

// ============================================================================
// Byte decoding boundaries — `fr_from_bytes` / `fq_from_bytes` must reject
// anything >= modulus rather than silently wrapping or panicking.
// ============================================================================

#[test]
fn fr_from_bytes_rejects_modulus_and_above() {
    assert_eq!(Bn254::fr_from_bytes(Bn254::FR_MODULUS.to_be_bytes()), None);
    let above = Bn254::FR_MODULUS + u256::from(1u8);
    assert_eq!(Bn254::fr_from_bytes(above.to_be_bytes()), None);
}

#[test]
fn fr_from_bytes_accepts_max_valid_scalar() {
    let max = Bn254::FR_MODULUS - u256::from(1u8);
    assert_eq!(Bn254::fr_from_bytes(max.to_be_bytes()), Some(max));
}

#[test]
fn fq_from_bytes_rejects_modulus_and_above() {
    assert_eq!(Bn254::fq_from_bytes(Bn254::FQ_MODULUS.to_be_bytes()), None);
    let above = Bn254::FQ_MODULUS + u256::from(1u8);
    assert_eq!(Bn254::fq_from_bytes(above.to_be_bytes()), None);
}
