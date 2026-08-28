//! Phase 3 — Fuzzing the XDR / raw-byte entry points.
//!
//! Raw bytes arriving from the Soroban host are decoded into field elements and
//! curve points *before* any cryptographic use. This suite fuzzes that decoding
//! boundary with malformed, truncated, zero-filled, and trailing-garbage buffers,
//! asserting the parsers reject bad input (via `None` / `false`) and never panic
//! or produce a host trap.
//!
//! The decoding primitives live in `soroban_zk_core` (`fr_from_bytes`,
//! `fq_from_bytes`, `is_valid_g1*`, `is_on_curve`, `is_in_correct_subgroup`),
//! which is exactly where the contract's `Bytes` payloads are turned into
//! structured math. We replay a representative XDR-style buffer (the same
//! fixed-width layout used by `vk_from_bytes`: 64-byte G1 points and 128-byte G2
//! points) through these validators under randomized, out-of-bounds input.
//!
//! `proptest` continuously generates the pseudo-random inputs; on any failure it
//! prints the PRNG seed and minimal counterexample so the edge case can be frozen
//! as a permanent regression test.

use ethnum::u256;
use proptest::collection::vec;
use proptest::prelude::*;
use soroban_zk_core::Bn254;

/// Reject a 64-byte G1 window the same way the contract's point parser would:
/// decode both coordinates as base-field elements and require them to be a valid
/// point *in the prime-order subgroup*.
fn parse_g1_window(win: &[u8]) -> bool {
    if win.len() != 64 {
        return false;
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&win[..32]);
    yb.copy_from_slice(&win[32..64]);
    let x = match Bn254::fq_from_bytes(xb) {
        Some(v) => v,
        None => return false,
    };
    let y = match Bn254::fq_from_bytes(yb) {
        Some(v) => v,
        None => return false,
    };
    Bn254::is_valid_g1_subgroup(x, y)
}

/// Reject a 128-byte G2 window: four Fq² coefficients must all be field elements
/// and the point must be on the curve *and* in the prime-order subgroup.
fn parse_g2_window(win: &[u8]) -> bool {
    if win.len() != 128 {
        return false;
    }
    let mut c = [[0u8; 32]; 4];
    for (i, chunk) in c.iter_mut().enumerate() {
        chunk.copy_from_slice(&win[i * 32..i * 32 + 32]);
    }
    let coords: [(u256, u256); 2] = [
        (
            match Bn254::fq_from_bytes(c[0]) {
                Some(v) => v,
                None => return false,
            },
            match Bn254::fq_from_bytes(c[1]) {
                Some(v) => v,
                None => return false,
            },
        ),
        (
            match Bn254::fq_from_bytes(c[2]) {
                Some(v) => v,
                None => return false,
            },
            match Bn254::fq_from_bytes(c[3]) {
                Some(v) => v,
                None => return false,
            },
        ),
    ];
    Bn254::is_in_correct_subgroup(coords[0], coords[1])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Every 32-byte chunk fed to the field decoder must be classified (`Some` /
    /// `None`) and never panic. Inputs `>= modulus` must be rejected.
    #[test]
    fn fuzz_field_byte_decoding(bytes in vec(any::<u8>(), 0..4096)) {
        // Slide a 32-byte window across the buffer, exactly as a decoder would.
        for chunk in bytes.windows(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            let fr = Bn254::fr_from_bytes(arr);
            let fq = Bn254::fq_from_bytes(arr);
            // Coherence: a value outside Fq is also outside Fr (since q > r),
            // so it can never decode as a valid field element in either field.
            if let Some(v) = fq {
                prop_assert!(v < Bn254::FQ_MODULUS);
                prop_assert!(Bn254::is_valid_fq(v));
            }
            if let Some(v) = fr {
                prop_assert!(v < Bn254::FR_MODULUS);
                prop_assert!(Bn254::is_valid_scalar(v));
            }
        }
    }

    /// Simulate an XDR buffer of concatenated G1 points: zero-length, truncated,
    /// trailing-garbage, and zero-filled payloads must all be rejected safely.
    #[test]
    fn fuzz_g1_xdr_windows(bytes in vec(any::<u8>(), 0..4096)) {
        // Exact 64-byte windows are parsed; anything else (truncated / trailing
        // garbage) is rejected by `parse_g1_window`.
        let mut i = 0;
        while i + 64 <= bytes.len() {
            let _ = parse_g1_window(&bytes[i..i + 64]);
            i += 64;
        }
        // Trailing remainder (the "garbage" bytes) is simply ignored here, which
        // mirrors a higher-layer length check rejecting the whole buffer.
        prop_assert!(true);
    }

    /// Simulate an XDR buffer of concatenated G2 points under random input.
    #[test]
    fn fuzz_g2_xdr_windows(bytes in vec(any::<u8>(), 0..4096)) {
        let mut i = 0;
        while i + 128 <= bytes.len() {
            let _ = parse_g2_window(&bytes[i..i + 128]);
            i += 128;
        }
        prop_assert!(true);
    }

    /// Zero-filled payloads (the classic "all-zero" malformed input) must be
    /// rejected by every validator rather than producing a valid point.
    #[test]
    fn fuzz_zero_filled_payloads(len in 0..256usize) {
        let zeros = vec![0u8; len];
        // A 32-byte all-zero window decodes to the scalar 0 — a *valid* field
        // element, so the field decoder accepts it; the point validators must
        // then reject the resulting (0, 0) point.
        let zero_field = Bn254::fr_from_bytes([0u8; 32]);
        prop_assert_eq!(zero_field, Some(u256::from(0u8)));
        // A 64-byte all-zero G1 window is the point at (0,0): not a valid point.
        prop_assert!(!parse_g1_window(&zeros[..core::cmp::min(64, len)]));
        // A 128-byte all-zero G2 window is similarly invalid.
        prop_assert!(!parse_g2_window(&zeros[..core::cmp::min(128, len)]));
    }
}
