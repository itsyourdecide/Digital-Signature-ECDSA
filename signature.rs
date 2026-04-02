use crate::secp256k1::{U256, Point};
use crate::sha256::Sha256;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub r: U256,
    pub s: U256,
}

impl Signature {
    // secp256k1 low-S threshold: floor(N / 2)
    const HALF_N: U256 = U256([
        0xDFE9_2F46_681B_20A0,
        0x5D57_6E73_57A4_501D,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ]);

    /// Generate a random scalar in the range [1, N-1]
    fn random_scalar() -> U256 {
        loop {
            let mut buf = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .expect("Failed to open /dev/urandom")
                .read_exact(&mut buf)
                .expect("Failed to read random bytes");

            let scalar = U256::from_bytes(&buf);
            if !scalar.is_zero() && !scalar.is_greater_or_equal(&U256::N) {
                return scalar;
            }
        }
    }

    pub fn generate_privkey() -> U256 {
        Self::random_scalar()
    }

    /// Load and validate private key from hex string.
    /// Returns Some(privkey) if valid, None if invalid (zero or >= N).
    pub fn load_privkey_from_hex(hex: &str) -> Option<U256> {
        let privkey = U256::from_hex(hex);
        if privkey.is_valid_privkey() {
            Some(privkey)
        } else {
            None
        }
    }

    /// ECDSA signing
    pub fn sign(d: &U256, z: &U256) -> Self {
        loop {
            let k = Self::random_scalar();

            // R = k * G
            let r_point = Point::G.mul_scalar(&k);
            let r = U256::add_mod(&r_point.x, &U256([0; 4]), &U256::N);
            if r.is_zero() {
                continue;
            }

            // k^-1 mod N
            let k_inv = U256::invert(&k, &U256::N);

            // s = k^-1 * (z + r * d) mod N
            let r_mul_d = U256::mul_mod(&r, d, &U256::N);
            let z_plus_rd = U256::add_mod(z, &r_mul_d, &U256::N);
            let mut s = U256::mul_mod(&k_inv, &z_plus_rd, &U256::N);

            // Enforce canonical low-S form: if s > N/2 then s = N - s.
            if s.is_greater_or_equal(&Self::HALF_N) && s != Self::HALF_N {
                s = U256::sup_row(&U256::N, &s);
            }

            if s.is_zero() {
                continue;
            }

            return Signature { r, s };
        }
    }

    /// ECDSA verification
    pub fn verify(sig: &Signature, z: &U256, pubkey: &Point) -> bool {
        let s_inv = U256::invert(&sig.s, &U256::N);

        // u1 = z * s^-1 mod N
        let u1 = U256::mul_mod(z, &s_inv, &U256::N);
        // u2 = r * s^-1 mod N
        let u2 = U256::mul_mod(&sig.r, &s_inv, &U256::N);

        // R' = u1*G + u2*Q
        let p1 = Point::G.mul_scalar(&u1);
        let p2 = pubkey.mul_scalar(&u2);
        let r_point = p1.add(&p2);

        if r_point.is_infinity() {
            return false;
        }

        let v = U256::add_mod(&r_point.x, &U256([0; 4]), &U256::N);
        v == sig.r
    }

    pub fn hash_message(msg: &[u8]) -> U256 {
        let hash = Sha256::new().finalize(msg);
        U256::from_bytes(&hash)
    }
}