//! Goldilocks field arithmetic (Issue #366, STARK primitives).
//!
//! The STARK FRI protocol needs a field with a *large* power-of-two subgroup
//! (high 2-adicity) for its Reed–Solomon domain. `Bn254`'s scalar field only
//! has 2-adicity ≈ 7, so we add the STARK-friendly **Goldilocks** field
//! `p = 2^64 − 2^32 + 1` (2-adicity 32). Elements fit in a single `u64` and all
//! arithmetic reduces through `u128`, so it is extremely cheap in the Soroban
//! WASM runtime and needs no heap allocation.

use core::ops::{Add, Mul, Neg, Sub};

/// Goldilocks prime modulus `p = 2^64 − 2^32 + 1`.
pub const MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// `2^(FRI_MAX_LOG)`-th primitive root of unity (generator `7` raised to
/// `(p−1)/2^32`). `ROOT_OF_UNITY^(2^32) == 1` and `ROOT_OF_UNITY^(2^31) == −1`.
pub const ROOT_OF_UNITY: u64 = 0x1856_29dc_da58_878c;

/// Coset offset used so the FRI evaluation domain never contains `0`.
pub const COSSET_OFFSET: u64 = 2;

/// Maximum FRI domain log-size. The domain has `2^FRI_MAX_LOG` points.
pub const FRI_MAX_LOG: u32 = 32;

/// `2⁻¹ mod p`, used in the FRI folding identity.
pub const INV2: u64 = 0x7FFF_FFFF_8000_0001; // (MODULUS + 1) / 2

/// A Goldilocks field element in `[0, p)`.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Felt {
    pub value: u64,
}

impl Felt {
    pub const ZERO: Felt = Felt { value: 0 };
    pub const ONE: Felt = Felt { value: 1 };

    /// Wrap a `u64`, reducing modulo `p`.
    #[inline]
    pub fn new(v: u64) -> Felt {
        Felt {
            value: v % MODULUS,
        }
    }

    #[inline]
    pub fn from_u64(v: u64) -> Felt {
        Felt::new(v)
    }

    /// Reduce a `u128` intermediate to a field element.
    #[inline(always)]
    fn reduce(x: u128) -> Felt {
        Felt {
            value: (x % MODULUS as u128) as u64,
        }
    }

    #[inline]
    pub fn add(self, o: Felt) -> Felt {
        Felt::reduce(self.value as u128 + o.value as u128)
    }

    #[inline]
    pub fn sub(self, o: Felt) -> Felt {
        Felt::reduce(self.value as u128 + MODULUS as u128 - o.value as u128)
    }

    #[inline]
    pub fn mul(self, o: Felt) -> Felt {
        Felt::reduce(self.value as u128 * o.value as u128)
    }

    #[inline]
    pub fn neg(self) -> Felt {
        if self.value == 0 {
            Felt::ZERO
        } else {
            Felt {
                value: MODULUS - self.value,
            }
        }
    }

    /// Multiplicative inverse via Fermat's little theorem (`a^(p−2)`).
    #[inline]
    pub fn inv(self) -> Felt {
        self.pow(MODULUS - 2)
    }

    /// Exponentiation by a `u64` exponent (square-and-multiply).
    #[inline]
    pub fn pow(self, mut e: u64) -> Felt {
        let mut r: u128 = 1;
        let mut b: u128 = self.value as u128;
        let m: u128 = MODULUS as u128;
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % m;
            }
            b = b * b % m;
            e >>= 1;
        }
        Felt {
            value: r as u64,
        }
    }

    /// `2⁻¹` as a field element.
    #[inline]
    pub fn inv2() -> Felt {
        Felt { value: INV2 }
    }

    /// Returns the FRI domain root of unity of order `2^log`:
    /// `ROOT_OF_UNITY^(2^(FRI_MAX_LOG − log))`.
    #[inline]
    pub fn layer_root(log: u32) -> Felt {
        Felt::new(ROOT_OF_UNITY).pow(1u64 << (FRI_MAX_LOG - log))
    }

    /// Coset offset raised to `2^(FRI_MAX_LOG − log)` for the given layer.
    #[inline]
    pub fn layer_offset(log: u32) -> Felt {
        Felt::new(COSSET_OFFSET).pow(1u64 << (FRI_MAX_LOG - log))
    }

    /// The `index`-th point of the coset evaluation domain for a layer of
    /// `2^log` points: `offset_log · root_log^index`.
    #[inline]
    pub fn domain_point(log: u32, index: u64) -> Felt {
        Felt::layer_offset(log).mul(Felt::layer_root(log).pow(index))
    }

    /// Evaluate a polynomial (coefficients low-to-high) at `x` via Horner.
    #[inline]
    pub fn poly_eval(coeffs: &[Felt], x: Felt) -> Felt {
        let mut acc = Felt::ZERO;
        for c in coeffs.iter().rev() {
            acc = acc.mul(x).add(*c);
        }
        acc
    }

    /// Canonical 8-byte big-endian encoding (used as Merkle leaf input).
    #[inline]
    pub fn to_bytes(self) -> [u8; 8] {
        self.value.to_be_bytes()
    }

    /// Decode an 8-byte big-endian encoding, reducing into the field.
    #[inline]
    pub fn from_bytes(b: &[u8; 8]) -> Felt {
        Felt::new(u64::from_be_bytes(*b))
    }

    /// Raw `u64` value.
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.value
    }
}

impl Add for Felt {
    type Output = Felt;
    #[inline]
    fn add(self, o: Felt) -> Felt {
        self.add(o)
    }
}
impl Sub for Felt {
    type Output = Felt;
    #[inline]
    fn sub(self, o: Felt) -> Felt {
        self.sub(o)
    }
}
impl Mul for Felt {
    type Output = Felt;
    #[inline]
    fn mul(self, o: Felt) -> Felt {
        self.mul(o)
    }
}
impl Neg for Felt {
    type Output = Felt;
    #[inline]
    fn neg(self) -> Felt {
        self.neg()
    }
}

impl From<u64> for Felt {
    #[inline]
    fn from(v: u64) -> Felt {
        Felt::new(v)
    }
}

impl core::fmt::Debug for Felt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Felt({:#x})", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_identities() {
        let a = Felt::new(0x1234_5678);
        let b = Felt::new(0x9abc_def0);
        assert_eq!((a + b).sub(b), a);
        assert_eq!((a * b).mul(b.inv()), a);
        assert_eq!(a.add(Felt::ZERO), a);
        assert_eq!(a.sub(a), Felt::ZERO);
        assert_eq!(a.neg().neg(), a);
        // inv is its own inverse
        assert_eq!(a.inv().inv(), a);
    }

    #[test]
    fn root_of_unity_properties() {
        let w = Felt::new(ROOT_OF_UNITY);
        assert_eq!(w.pow(1u64 << 32), Felt::ONE);
        assert_eq!(w.pow(1u64 << 31), Felt::new(MODULUS - 1)); // -1
        // domain points are paired as x and -x
        let half = 1u64 << 7;
        for m in 0..4u64 {
            let x = Felt::domain_point(8, m);
            let nx = Felt::domain_point(8, m + half);
            assert_eq!(x.add(nx), Felt::ZERO);
        }
    }

    #[test]
    fn poly_eval_matches_manual() {
        // p(x) = 3 + 5x + 7x^2
        let coeffs = [Felt::new(3), Felt::new(5), Felt::new(7)];
        let x = Felt::new(11);
        let expected = Felt::new(3)
            .add(Felt::new(5).mul(x))
            .add(Felt::new(7).mul(x.mul(x)));
        assert_eq!(Felt::poly_eval(&coeffs, x), expected);
    }
}
