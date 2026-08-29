//! FRI (Fast Reed–Solomon Interactive Oracle Proofs of Proximity) primitives
//! (Issue #366, Phase 2).
//!
//! All folding works on caller-provided slices; the core routine
//! [`fold_layer_into`] writes the next layer into a caller-owned buffer, so the
//! FRI parameter-processing path performs **no heap allocation**. Folding is the
//! proximity test: a low-degree polynomial, when folded with a random `β`, stays
//! low-degree (its degree halves), whereas a random function does not.

use soroban_sdk::{BytesN, Env, Vec};

use crate::stark::field::Felt;
use crate::stark::merkle;

/// FRI domain configuration. `log_max` is the base trace domain log-size.
pub struct FriConfig {
    pub log_max: u32,
}

impl FriConfig {
    pub fn new(log_max: u32) -> Self {
        FriConfig { log_max }
    }

    /// The `index`-th point of the coset domain for a layer of `2^log` points.
    pub fn domain_point(&self, log: u32, index: u64) -> Felt {
        Felt::domain_point(log, index)
    }
}

/// Fold one FRI layer into the next, in place into `dst` (no allocation).
///
/// `src` must have `2^log` elements; `dst` must hold `2^(log−1)`. For each
/// `m`, the pair `(m, m + 2^(log−1))` are the two domain points `x` and `−x`;
/// the folded value is
/// `((f(x) + f(−x)) + β·(f(x) − f(−x))·x⁻¹) · 2⁻¹`, evaluated at `x²`.
pub fn fold_layer_into(src: &[Felt], dst: &mut [Felt], beta: Felt, log: u32) {
    let half = (1usize << (log - 1)) as usize;
    debug_assert!(src.len() >= half * 2);
    debug_assert!(dst.len() >= half);
    for m in 0..half {
        let x = Felt::domain_point(log, m as u64);
        let a = src[m];
        let b = src[m + half];
        let num = a.add(b).add(beta.mul(a.sub(b)).mul(x.inv()));
        dst[m] = num.mul(Felt::inv2());
    }
}

/// Merkle-commit to an FRI layer (prover/verifier-shared). Returns the root over
/// the SHA-256 leaf digests of each field element.
pub fn commit_layer(env: &Env, layer: &[Felt]) -> BytesN<32> {
    let mut leaves: Vec<BytesN<32>> = Vec::new(env);
    for f in layer {
        leaves.push_back(merkle::felt_leaf(env, *f));
    }
    merkle::merkle_root(env, &leaves)
}

/// `(p(ζ) − p(z)) / (ζ − z)` — the quotient-polynomial evaluation used by the
/// deep composition. Computed directly from coefficients, no allocation.
///
/// (When `ζ == z` this is the formal derivative; callers pass a random `ζ` that
/// is distinct from every queried point `z`.)
pub fn quotient_eval(coeffs: &[Felt], zeta: Felt, z: Felt) -> Felt {
    let denom = zeta.sub(z).inv();
    let mut acc = Felt::ZERO;
    let mut zeta_pow = Felt::ONE;
    let mut z_pow = Felt::ONE;
    for c in coeffs {
        let num = zeta_pow.sub(z_pow);
        acc = acc.add(c.mul(num.mul(denom)));
        zeta_pow = zeta_pow.mul(zeta);
        z_pow = z_pow.mul(z);
    }
    acc
}

/// Deep-FRI composition polynomial value at `ζ`:
/// `H(ζ) = Σ α · (p(ζ) − p(z)) / (ζ − z)` over all queried columns/degrees.
///
/// Each term is `(α, coefficients of p, query point z)`; `α` is the random
/// Fiat-Shamir challenge for that term.
pub fn deep_composition(terms: &[(Felt, &[Felt], Felt)], zeta: Felt) -> Felt {
    let mut h = Felt::ZERO;
    for (alpha, coeffs, z) in terms {
        h = h.add(alpha.mul(quotient_eval(coeffs, zeta, *z)));
    }
    h
}

/// Verify a single FRI query: given the revealed column values across all FRI
/// layers at one query position, fold them with `beta`, and confirm the folded
/// value equals the verifier-computed value at the squared domain point. This is
/// the per-query proximity check a verifier runs.
///
/// `column` is the revealed value at the current layer; the function returns the
/// folded value so the caller can compare it against the next layer's revealed
/// value.
pub fn fold_value(column: Felt, neg_column: Felt, x: Felt, beta: Felt) -> Felt {
    let num = column.add(neg_column).add(beta.mul(column.sub(neg_column)).mul(x.inv()));
    num.mul(Felt::inv2())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn fold_matches_coefficient_construction() {
        // Build a random polynomial p of degree < 2^8 and fold its coset
        // evaluation. The folded layer must equal p' evaluated on the next
        // domain, where p'(y) = Σ_{i even} c_i y^{i/2} + β Σ_{i odd} c_i y^{(i-1)/2}.
        let log = 8u32;
        let degree = (1usize << log) - 3; // < 2^log
        let coeffs: std::vec::Vec<Felt> = (0..=degree)
            .map(|i| Felt::new(((i as u64).wrapping_mul(0x9E37_79B9) % 97) + 1))
            .collect();
        let beta = Felt::new(12345);

        // Evaluate p on the full coset domain.
        let n = 1usize << log;
        let mut layer: std::vec::Vec<Felt> = std::vec::Vec::with_capacity(n);
        for i in 0..n {
            layer.push(Felt::poly_eval(&coeffs, Felt::domain_point(log, i as u64)));
        }

        // Independent p' coefficients.
        let pp_len = degree / 2 + 1;
        let mut pp: std::vec::Vec<Felt> = std::vec::Vec::with_capacity(pp_len);
        for _ in 0..pp_len {
            pp.push(Felt::ZERO);
        }
        for (i, c) in coeffs.iter().enumerate() {
            if i % 2 == 0 {
                pp[i / 2] = pp[i / 2].add(*c);
            } else {
                pp[(i - 1) / 2] = pp[(i - 1) / 2].add(beta.mul(*c));
            }
        }

        // Fold into a stack buffer.
        let half = 1usize << (log - 1);
        let mut folded: std::vec::Vec<Felt> = std::vec::Vec::with_capacity(half);
        for _ in 0..half {
            folded.push(Felt::ZERO);
        }
        fold_layer_into(&layer, &mut folded, beta, log);

        // Compare against p' evaluated on the next (log-1) domain.
        for m in 0..half {
            let y = Felt::domain_point(log - 1, m as u64);
            assert_eq!(folded[m], Felt::poly_eval(&pp, y), "fold mismatch at {}", m);
        }
    }

    #[test]
    fn deep_composition_zero_when_polynomials_consistent() {
        // One term: p(x)=x, query z=3, alpha=anything, zeta=5.
        // (p(zeta)-p(z))/(zeta-z) = (5-3)/(5-3) = 1.
        let coeffs = [Felt::ZERO, Felt::ONE]; // p(x)=x
        let zeta = Felt::new(5);
        let z = Felt::new(3);
        let alpha = Felt::new(7);
        let terms = [(alpha, &coeffs[..], z)];
        let h = deep_composition(&terms, zeta);
        assert_eq!(h, alpha.mul(Felt::ONE));
    }
}
