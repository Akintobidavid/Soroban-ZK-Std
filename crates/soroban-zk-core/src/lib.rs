#![no_std]
use ethnum::u256;

pub mod elgamal {
    use super::*;

    /// An ElGamal Ciphertext consisting of two points (c1, c2).
    /// Used for shielded/private balance encryption.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct ElGamalCiphertext {
        pub c1: G1Affine, // Matches contract expectation
        pub c2: G1Affine, // Matches contract expectation
    }

    impl ElGamalCiphertext {
        /// The BN254 G1 generator point (x=1, y=2).
        ///
        /// Uses `from_words` because `u256::from` is not a `const fn`.
        pub const G: G1Affine = G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        };

        /// EC-ElGamal encryption over BN254 G1.
        ///
        /// Maps a scalar `amount` to a curve point via `amount·G` and encrypts
        /// it under `pub_key` using the ephemeral scalar `ephemeral`.
        ///
        /// # Output
        /// - `c1 = ephemeral·G`        — the ephemeral public key
        /// - `c2 = amount·G + ephemeral·pub_key` — the encrypted amount point
        ///
        /// # Errors
        /// Returns [`ZkError::InvalidFieldElement`] if `amount` ≥ the BN254
        /// scalar field modulus, since such values would wrap around in
        /// `scalar_mul` and produce unexpected plaintexts.
        ///
        /// The caller MUST provide a fresh, uniformly random `ephemeral` for
        /// each encryption; reuse leaks the relationship between plaintexts.
        pub fn encrypt(
            amount: u256,
            pub_key: &G1Affine,
            ephemeral: u256,
        ) -> Result<Self, ZkError> {
            // Validate amount is in the scalar field
            if amount >= Bn254::BASE_MODULUS {
                return Err(ZkError::InvalidFieldElement);
            }

            // c1 = ephemeral * G
            let c1 = Self::G.scalar_mul(ephemeral);

            // c2 = amount * G + ephemeral * pub_key
            let amount_point = Self::G.scalar_mul(amount);
            let shared_secret = pub_key.scalar_mul(ephemeral);
            let c2 = amount_point.add(&shared_secret);

            Ok(Self { c1, c2 })
        }

        /// Decrypts the ciphertext, recovering the amount point `amount·G`.
        ///
        /// `private_key` must be the scalar whose corresponding public key was
        /// used during encryption (i.e., `pub_key = private_key·G`).
        ///
        /// # How it works
        /// ```text
        /// amount_point = c2 - private_key·c1
        ///              = (amount·G + ephemeral·pub_key) - sk·(ephemeral·G)
        ///              = amount·G + ephemeral·(sk·G) - sk·(ephemeral·G)
        ///              = amount·G
        /// ```
        pub fn decrypt_amount_point(&self, private_key: u256) -> Result<G1Affine, ZkError> {
            // shared = private_key * c1 = private_key * ephemeral * G
            let shared_secret = self.c1.scalar_mul(private_key);

            // Negate shared_secret: -(x, y) = (x, -y mod Fq)
            let neg_shared_secret = G1Affine {
                x: shared_secret.x,
                y: Bn254::sub_fq(u256::from(0u8), shared_secret.y),
            };

            // c2 + (-shared_secret) = c2 - shared_secret = amount·G
            Ok(self.c2.add(&neg_shared_secret))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Derive a public key from a private key: pk = sk·G
        fn derive_pub_key(sk: u256) -> G1Affine {
            ElGamalCiphertext::G.scalar_mul(sk)
        }

        #[test]
        fn round_trip_encrypt_decrypt_small_amount() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");

            let decrypted_point = ct
                .decrypt_amount_point(sk)
                .expect("decrypt should succeed");

            // decrypted_point should equal amount·G
            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(decrypted_point, expected);
        }

        #[test]
        fn round_trip_zero_amount() {
            let amount = u256::from(0u8);
            let sk = u256::from(5u8);
            let ephemeral = u256::from(3u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");

            let decrypted_point = ct
                .decrypt_amount_point(sk)
                .expect("decrypt should succeed");

            // 0·G = point at infinity = (0, 0) in affine
            assert_eq!(decrypted_point.x, u256::from(0u8));
            assert_eq!(decrypted_point.y, u256::from(0u8));
        }

        #[test]
        fn round_trip_large_amount() {
            // Use a large amount that's still within Fr modulus
            let amount = u256::from_words(0x1234567890abcdef_u128, 0xdeadbeefcafebabe_u128);
            let sk = u256::from(12345u64);
            let ephemeral = u256::from(98765u64);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");
            let decrypted_point = ct
                .decrypt_amount_point(sk)
                .expect("decrypt should succeed");

            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(decrypted_point, expected);
        }

        #[test]
        fn different_amounts_produce_different_c2() {
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct1 = ElGamalCiphertext::encrypt(u256::from(1u8), &pk, ephemeral)
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(u256::from(2u8), &pk, ephemeral)
                .expect("encrypt should succeed");

            // Same ephemeral → same c1
            assert_eq!(ct1.c1, ct2.c1);
            // Different amounts → different c2
            assert_ne!(ct1.c2, ct2.c2);
        }

        #[test]
        fn different_ephemerals_produce_different_ciphertexts() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);

            let ct1 = ElGamalCiphertext::encrypt(amount, &pk, u256::from(3u8))
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(amount, &pk, u256::from(5u8))
                .expect("encrypt should succeed");

            // Different ephemeral → different c1 AND c2
            assert_ne!(ct1.c1, ct2.c1);
            assert_ne!(ct1.c2, ct2.c2);
        }

        #[test]
        fn different_keys_produce_different_ciphertexts() {
            let amount = u256::from(42u8);
            let ephemeral = u256::from(13u8);
            let pk1 = derive_pub_key(u256::from(7u8));
            let pk2 = derive_pub_key(u256::from(11u8));

            let ct1 = ElGamalCiphertext::encrypt(amount, &pk1, ephemeral)
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(amount, &pk2, ephemeral)
                .expect("encrypt should succeed");

            // Same ephemeral → same c1
            assert_eq!(ct1.c1, ct2.c1);
            // Different pub keys → different c2
            assert_ne!(ct1.c2, ct2.c2);
        }

        #[test]
        fn decrypt_with_wrong_key_produces_wrong_point() {
            let amount = u256::from(42u8);
            let sk_correct = u256::from(7u8);
            let sk_wrong = u256::from(11u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk_correct);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");

            let decrypted_wrong = ct
                .decrypt_amount_point(sk_wrong)
                .expect("decrypt should succeed");

            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_ne!(decrypted_wrong, expected);
        }

        #[test]
        fn encrypt_is_deterministic() {
            let amount = u256::from(99u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(31u8);
            let pk = derive_pub_key(sk);

            let ct1 = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");

            assert_eq!(ct1, ct2);
        }

        #[test]
        fn encrypt_with_max_scalar_amount() {
            // Fr modulus - 1 is the largest valid scalar
            let amount = Bn254::BASE_MODULUS - u256::from(1u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, ephemeral)
                .expect("encrypt should succeed");

            let decrypted_point = ct
                .decrypt_amount_point(sk)
                .expect("decrypt should succeed");

            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(decrypted_point, expected);
        }

        #[test]
        fn encrypt_rejects_amount_above_modulus() {
            let amount = Bn254::BASE_MODULUS; // exactly the modulus — invalid
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        fn encrypt_rejects_amount_well_above_modulus() {
            let amount = Bn254::BASE_MODULUS + u256::from(1000u16);
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        fn encrypt_with_ephemeral_zero_produces_unrandomized_ciphertext() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, u256::from(0u8))
                .expect("encrypt should succeed");

            // c1 = 0·G = identity
            assert_eq!(ct.c1.x, u256::from(0u8));
            assert_eq!(ct.c1.y, u256::from(0u8));
            // c2 = amount·G + 0·pk = amount·G
            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(ct.c2, expected);

            // Decryption still works
            let decrypted = ct
                .decrypt_amount_point(sk)
                .expect("decrypt should succeed");
            assert_eq!(decrypted, expected);
        }

        #[test]
        fn homomorphic_addition_two_ciphertexts() {
            // ElGamal is additively homomorphic:
            //   Dec(sk, ct(a) + ct(b)) == (a+b)·G
            let a = u256::from(30u8);
            let b = u256::from(12u8);
            let sk = u256::from(7u8);
            let ephemeral_a = u256::from(5u8);
            let ephemeral_b = u256::from(11u8);
            let pk = derive_pub_key(sk);

            let ct_a = ElGamalCiphertext::encrypt(a, &pk, ephemeral_a)
                .expect("encrypt a");
            let ct_b = ElGamalCiphertext::encrypt(b, &pk, ephemeral_b)
                .expect("encrypt b");

            // Homomorphic addition: sum c1 and c2 components independently
            let sum_ct = ElGamalCiphertext {
                c1: ct_a.c1.add(&ct_b.c1),
                c2: ct_a.c2.add(&ct_b.c2),
            };

            let decrypted_sum = sum_ct
                .decrypt_amount_point(sk)
                .expect("decrypt sum");

            let expected = ElGamalCiphertext::G.scalar_mul(a + b);
            assert_eq!(decrypted_sum, expected);
        }

        #[test]
        fn homomorphic_addition_with_single_ciphertext_and_plaintext() {
            // Encrypt a, then add b·G to c2 (and keep c1 as-is)
            let a = u256::from(100u8);
            let b = u256::from(50u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(a, &pk, ephemeral)
                .expect("encrypt a");

            // Mixed addition: add b·G to c2 only
            // Dec(sk, (c1, c2 + b·G)) = a·G + b·G = (a+b)·G
            let ct_plus_b = ElGamalCiphertext {
                c1: ct.c1,
                c2: ct.c2.add(&ElGamalCiphertext::G.scalar_mul(b)),
            };

            let decrypted = ct_plus_b
                .decrypt_amount_point(sk)
                .expect("decrypt");

            let expected = ElGamalCiphertext::G.scalar_mul(a + b);
            assert_eq!(decrypted, expected);
        }
    }
}

pub use elgamal::ElGamalCiphertext;
pub mod polynomial;
pub use polynomial::{DensePolynomial, SparsePolynomial};

/// Errors returned by zero-knowledge conversion and validation operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// The supplied value is ≥ the BN254 scalar field modulus and is not a valid field element.
    InvalidFieldElement,
    /// Mismatched input lengths or empty slices in multi-input operations.
    InvalidInput,
    /// Serialized proof or point bytes could not be decoded into a valid structure.
    DeserializationError,
}

/// A BN254 scalar field element guaranteed to be in the range `[0, r)`.
/// Construct exclusively via [`SafeFrom`] to enforce field bounds without panicking.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fr(u256);

impl Fr {
    /// Returns the inner `u256` representation of the field element.
    #[inline(always)]
    pub fn inner(&self) -> u256 {
        self.0
    }
}

/// A BN254 G1 point in affine coordinates (x, y).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G1Affine {
    pub x: u256,
    pub y: u256,
}

impl G1Affine {
    /// Bridges the contract's method call to the Bn254 implementation.
    pub fn scalar_mul(&self, scalar: u256) -> G1Affine {
        Bn254::g1_scalar_mul(G1Projective::from(*self), scalar).to_affine()
    }

    /// Adds two affine points using the existing projective addition path.
    pub fn add(&self, other: &G1Affine) -> G1Affine {
        G1Projective::from(*self)
            .add(&G1Projective::from(*other))
            .to_affine()
    }
}

impl From<G1Affine> for G1Projective {
    fn from(affine: G1Affine) -> Self {
        Self {
            x: affine.x,
            y: affine.y,
            z: u256::from(1u8),
        }
    }
}

impl G1Projective {
    // ... your existing identity, ct_select, double, add methods ...

    /// Converts the projective point back to affine coordinates.
    pub fn to_affine(&self) -> G1Affine {
        // Handle the point at infinity
        if self.z == u256::from(0u8) {
            return G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            };
        }

        // Z^-1
        let z_inv = Bn254::invert_fq(self.z);
        // Z^-2
        let z_inv_sq = Bn254::mul_fq(z_inv, z_inv);
        // Z^-3
        let z_inv_cb = Bn254::mul_fq(z_inv_sq, z_inv);

        G1Affine {
            x: Bn254::mul_fq(self.x, z_inv_sq),
            y: Bn254::mul_fq(self.y, z_inv_cb),
        }
    }
}

/// Constant-time, fallible conversion into a cryptographic type.
pub trait SafeFrom<T>: Sized {
    fn safe_from(val: T) -> Result<Self, ZkError>;
}

impl SafeFrom<u256> for Fr {
    #[inline(always)]
    fn safe_from(val: u256) -> Result<Self, ZkError> {
        let (_, in_field) = val.overflowing_sub(Bn254::BASE_MODULUS);
        if in_field {
            Ok(Fr(val))
        } else {
            Err(ZkError::InvalidFieldElement)
        }
    }
}

/// The BN254 elliptic curve group parameters and arithmetic operations.
pub struct Bn254;

/// Affine point representation (x, y) on the BN254 curve
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: u256,
    pub y: u256,
}

/// Jacobian point representation (X, Y, Z) on the BN254 curve
/// Affine coordinates (x, y) are related by: x = X/Z², y = Y/Z³
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JacobianPoint {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

impl Bn254 {
    /// BN254 scalar field modulus r (order of G1/G2).
    pub const BASE_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FR_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FQ_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x97816a916871ca8d3c208c16d87cfd47_u128,
    );
    pub const G1_B: u256 = u256::from_words(0u128, 3u128);
    pub const LEGENDRE_EXP_FR: ethnum::u256 = ethnum::u256::from_words(
        0x183227397098d014dc2822db40c0ac2e_u128,
        0x9419f4243cdcb848a1f0fac9f8000000_u128,
    );
    pub const LEGENDRE_EXP_FQ: ethnum::u256 = ethnum::u256::from_words(
        0x183227397098d014dc2822db40c0ac2e_u128,
        0xcbc0b548b438e5469e10460b6c3e7ea3_u128,
    );

    pub fn fr_to_bytes(a: u256) -> [u8; 32] {
        a.to_be_bytes()
    }
    pub fn fr_from_bytes(bytes: [u8; 32]) -> Option<u256> {
        let val = u256::from_be_bytes(bytes);
        if val < Self::BASE_MODULUS {
            Some(val)
        } else {
            None
        }
    }
    pub fn fq_to_bytes(a: u256) -> [u8; 32] {
        a.to_be_bytes()
    }
    pub fn fq_from_bytes(bytes: [u8; 32]) -> Option<u256> {
        let val = u256::from_be_bytes(bytes);
        if val < Self::FQ_MODULUS {
            Some(val)
        } else {
            None
        }
    }

    #[inline(always)]
    fn add_mod(a: u256, b: u256, modulus: u256) -> u256 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= modulus {
            sum.wrapping_sub(modulus)
        } else {
            sum
        }
    }

    pub fn sub(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        if underflow {
            res.wrapping_add(Self::BASE_MODULUS)
        } else {
            res
        }
    }

    #[inline(always)]
    fn mul_mod(a: u256, b: u256, modulus: u256) -> u256 {
        let mut result = u256::from(0u8);
        let mut a = a % modulus;
        let mut b = b % modulus;
        while b > 0 {
            if b & u256::from(1u8) != u256::from(0u8) {
                result = Self::add_mod(result, a, modulus);
            }
            a = Self::add_mod(a, a, modulus);
            b >>= 1;
        }
        result
    }

    #[inline(always)]
    fn pow_mod(mut base: u256, mut exp: u256, modulus: u256) -> u256 {
        let mut res = u256::from(1u8);
        while exp > 0 {
            if exp & u256::from(1u8) != u256::from(0u8) {
                res = Self::mul_mod(res, base, modulus);
            }
            base = Self::mul_mod(base, base, modulus);
            exp >>= 1;
        }
        res
    }

    pub fn is_valid_scalar(val: u256) -> bool {
        val < Self::FR_MODULUS
    }

    /// Validates a BN254 base field element in Fq.
    ///
    /// This ensures the element is within the field modulus and prevents
    /// malformed G2 coordinate components from being passed into the native
    /// host pairing call.
    pub fn is_valid_fq(val: u256) -> bool {
        val < Self::FQ_MODULUS
    }

    pub fn add(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FR_MODULUS)
    }
    pub fn mul(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FR_MODULUS)
    }
    pub fn pow(base: u256, exp: u256) -> u256 {
        Self::pow_mod(base, exp, Self::FR_MODULUS)
    }
    pub fn invert(a: u256) -> u256 {
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::FR_MODULUS - u256::from(2u8);
        Self::pow(a, exponent)
    }

    pub fn mul_fq(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn add_fq(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn sub_fq(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        if underflow {
            res.wrapping_add(Self::FQ_MODULUS)
        } else {
            res
        }
    }
    pub fn invert_fq(a: u256) -> u256 {
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::FQ_MODULUS - u256::from(2u8);
        Self::pow_mod(a, exponent, Self::FQ_MODULUS)
    }

    pub fn is_valid_g1(x: u256, y: u256) -> bool {
        if x == 0 && y == 0 {
            return false;
        }
        if x >= Self::FQ_MODULUS || y >= Self::FQ_MODULUS {
            return false;
        }

        let y_sq = Self::mul_mod(y, y, Self::FQ_MODULUS);
        let x_sq = Self::mul_mod(x, x, Self::FQ_MODULUS);
        let x_cb = Self::mul_mod(x_sq, x, Self::FQ_MODULUS);
        let rhs = Self::add_mod(x_cb, Self::G1_B, Self::FQ_MODULUS);

        y_sq == rhs
    }

    pub fn is_valid_g1_subgroup(x: u256, y: u256) -> bool {
        if !Self::is_valid_g1(x, y) {
            return false;
        }

        let point = G1Projective::from(G1Affine { x, y });
        let result = Self::g1_scalar_mul(point, Self::BASE_MODULUS);
        result.z == u256::from(0u8)
    }

    pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
        if scalar == 0 {
            return G1Projective::identity();
        }
        if scalar == 1 {
            return point;
        }

        let mut result = G1Projective::identity();

        for i in (0..254).rev() {
            result = result.double();
            let added = result.add(&point);

            // Use ethnum explicitly for bit extraction
            let shifted: ethnum::u256 = scalar >> i;
            let mask: ethnum::u256 = ethnum::u256::from(1u8);
            let bit: u128 = (shifted & mask).as_u128();

            result = G1Projective::ct_select(bit, added, result);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct G1Projective {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

impl G1Projective {
    pub fn identity() -> Self {
        Self {
            x: u256::from(1u8),
            y: u256::from(1u8),
            z: u256::from(0u8),
        }
    }

    pub fn is_identity(&self) -> bool {
        self.z == u256::from(0u8)
    }

    pub fn ct_select(choice: u128, a: Self, b: Self) -> Self {
        let mask = u256::from(0u128).wrapping_sub(u256::from(choice));
        let not_mask = !mask;

        Self {
            x: (mask & a.x) | (not_mask & b.x),
            y: (mask & a.y) | (not_mask & b.y),
            z: (mask & a.z) | (not_mask & b.z),
        }
    }

    /// Doubles the projective point (2 * P) using Jacobian formulas.
    pub fn double(&self) -> Self {
        // If the point is at infinity, doubling it returns infinity
        if self.z == u256::from(0u8) {
            return *self;
        }

        let xx = Bn254::mul_fq(self.x, self.x);
        let yy = Bn254::mul_fq(self.y, self.y);
        let yyyy = Bn254::mul_fq(yy, yy);

        // S = 4 * X * Y^2
        let xy2 = Bn254::mul_fq(self.x, yy);
        let s = Bn254::mul_fq(xy2, u256::from(4u8));

        // M = 3 * X^2 (since a = 0 for BN254 curve y^2 = x^3 + 3)
        let m = Bn254::mul_fq(xx, u256::from(3u8));

        // T = M^2 - 2*S
        let m2 = Bn254::mul_fq(m, m);
        let s2 = Bn254::add_fq(s, s);
        let t = Bn254::sub_fq(m2, s2);

        let x3 = t;

        // Y3 = M * (S - X3) - 8 * Y^4
        let s_minus_t = Bn254::sub_fq(s, t);
        let m_times_sm_t = Bn254::mul_fq(m, s_minus_t);
        let yyyy8 = Bn254::mul_fq(yyyy, u256::from(8u8));
        let y3 = Bn254::sub_fq(m_times_sm_t, yyyy8);

        // Z3 = 2 * Y * Z
        let yz = Bn254::mul_fq(self.y, self.z);
        let z3 = Bn254::add_fq(yz, yz);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Adds two projective points (P1 + P2) using Jacobian formulas.
    pub fn add(&self, other: &Self) -> Self {
        // Handle identity/infinity cases
        if self.z == u256::from(0u8) {
            return *other;
        }
        if other.z == u256::from(0u8) {
            return *self;
        }

        let z1z1 = Bn254::mul_fq(self.z, self.z);
        let z2z2 = Bn254::mul_fq(other.z, other.z);

        let u1 = Bn254::mul_fq(self.x, z2z2);
        let u2 = Bn254::mul_fq(other.x, z1z1);

        let z1_cubed = Bn254::mul_fq(self.z, z1z1);
        let z2_cubed = Bn254::mul_fq(other.z, z2z2);

        let s1 = Bn254::mul_fq(self.y, z2_cubed);
        let s2 = Bn254::mul_fq(other.y, z1_cubed);

        if u1 == u2 {
            if s1 == s2 {
                return self.double(); // Points are the same
            } else {
                return Self::identity(); // Points are inverses
            }
        }

        let h = Bn254::sub_fq(u2, u1);
        let r = Bn254::sub_fq(s2, s1);

        let h2 = Bn254::mul_fq(h, h);
        let h3 = Bn254::mul_fq(h2, h);

        let u1_h2 = Bn254::mul_fq(u1, h2);

        // X3 = R^2 - H^3 - 2*U1*H^2
        let r2 = Bn254::mul_fq(r, r);
        let u1_h2_times_2 = Bn254::add_fq(u1_h2, u1_h2);
        let x3_part1 = Bn254::sub_fq(r2, h3);
        let x3 = Bn254::sub_fq(x3_part1, u1_h2_times_2);

        // Y3 = R*(U1*H^2 - X3) - S1*H^3
        let u1_h2_minus_x3 = Bn254::sub_fq(u1_h2, x3);
        let r_times_u1_h2_minus_x3 = Bn254::mul_fq(r, u1_h2_minus_x3);
        let s1_h3 = Bn254::mul_fq(s1, h3);
        let y3 = Bn254::sub_fq(r_times_u1_h2_minus_x3, s1_h3);

        // Z3 = H * Z1 * Z2
        let z1z2 = Bn254::mul_fq(self.z, other.z);
        let z3 = Bn254::mul_fq(h, z1z2);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// KZG commitment generation.
///
/// Computes `C = sum(a_i * srs[i])` where `a_i` are the polynomial
/// coefficients and `srs[i]` are the structured reference string G1 points.
///
/// Returns the group identity if the polynomial is zero.
/// Returns [`ZkError::InvalidInput`] if the polynomial length exceeds the
/// SRS length.
///
/// All computation is stack-allocated with zero heap usage.
pub fn kzg_commit<const N: usize>(
    poly: &DensePolynomial<N>,
    srs: &[G1Affine],
) -> Result<G1Affine, ZkError> {
    if poly.len > srs.len() {
        return Err(ZkError::InvalidInput);
    }

    let mut acc = G1Projective::identity();

    for (coeff, srs_point) in poly.coeffs().iter().zip(srs.iter()) {
        let term = Bn254::g1_scalar_mul(G1Projective::from(*srs_point), *coeff);
        acc = acc.add(&term);
    }

    Ok(acc.to_affine())
}
