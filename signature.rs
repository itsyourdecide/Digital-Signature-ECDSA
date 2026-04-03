use crate::secp256k1::{U256, Point};
use crate::sha256::Sha256;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub r: U256, // Signature component r
    pub s: U256, // Signature component s
    pub v: u8, // Recovery ID (0 or 1)
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
        let mut attempt = 0usize;
        loop {
            let k = Self::generate_k_rfc6979(d, z, attempt);
            attempt += 1;

            // R = k * G
            let r_point = Point::G.mul_scalar(&k);
            let r = U256::add_mod(&r_point.x, &U256([0; 4]), &U256::N);
            if r.is_zero() { continue; }

            let mut is_y_odd = r_point.y.0[0] & 1 == 1;

            // k^-1 mod N
            let k_inv = U256::invert(&k, &U256::N);

            // s = k^-1 * (z + r * d) mod N
            let r_mul_d = U256::mul_mod(&r, d, &U256::N);
            let z_plus_rd = U256::add_mod(z, &r_mul_d, &U256::N);
            let mut s = U256::mul_mod(&k_inv, &z_plus_rd, &U256::N);

            // EIP-2: Canonical low-S
            if s.is_greater_or_equal(&Self::HALF_N) && s != Self::HALF_N {
                s = U256::sup_row(&U256::N, &s);
                is_y_odd = !is_y_odd; 
            }

            if s.is_zero() { continue; }

            let v = if is_y_odd { 1 } else { 0 };

            return Signature { r, s, v };
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

    fn u256_to_bytes_be(x: &U256) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            let limb_be = x.0[3 - i].to_be_bytes();
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb_be);
        }
        out
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let hash = Sha256::new().finalize(key);
            k[..32].copy_from_slice(&hash);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut o_key_pad = [0x5c_u8; 64];
        let mut i_key_pad = [0x36_u8; 64];
        for i in 0..64 {
            o_key_pad[i] ^= k[i];
            i_key_pad[i] ^= k[i];
        }

        let mut inner_data = i_key_pad.to_vec();
        inner_data.extend_from_slice(data);
        let inner_hash = Sha256::new().finalize(&inner_data);

        let mut outer_data = o_key_pad.to_vec();
        outer_data.extend_from_slice(&inner_hash);
        Sha256::new().finalize(&outer_data)
    }

    /// RFC 6979 deterministic nonce generation.
    /// attempt=0 returns first valid k, attempt=1 returns second valid k, etc.
    fn generate_k_rfc6979(d: &U256, z: &U256, attempt: usize) -> U256 {
        let mut v = [0x01_u8; 32];
        let mut k_mac = [0x00_u8; 32];

        // int2octets(d), int2octets(z) in big-endian form
        let d_bytes = Self::u256_to_bytes_be(d);
        let z_bytes = Self::u256_to_bytes_be(z);

        // 1. K = HMAC_SHA256(K, V || 0x00 || int2octets(d) || int2octets(z))
        let mut data1 = v.to_vec();
        data1.push(0x00);
        data1.extend_from_slice(&d_bytes);
        data1.extend_from_slice(&z_bytes);
        k_mac = Self::hmac_sha256(&k_mac, &data1);

        // 2. V = HMAC_SHA256(K, V)
        v = Self::hmac_sha256(&k_mac, &v);

        // 3. K = HMAC_SHA256(K, V || 0x01 || int2octets(d) || int2octets(z))
        let mut data2 = v.to_vec();
        data2.push(0x01);
        data2.extend_from_slice(&d_bytes);
        data2.extend_from_slice(&z_bytes);
        k_mac = Self::hmac_sha256(&k_mac, &data2);

        // 4. V = HMAC_SHA256(K, V)
        v = Self::hmac_sha256(&k_mac, &v);

        let mut valid_idx = 0usize;
        loop {
            // 5. V = HMAC_SHA256(K, V)
            v = Self::hmac_sha256(&k_mac, &v);

            let k_candidate = U256::from_bytes(&v);

            if !k_candidate.is_zero() && !k_candidate.is_greater_or_equal(&U256::N) {
                if valid_idx == attempt {
                    return k_candidate;
                }
                valid_idx += 1;
            }

            // If k is not suitable (probability ~2^-128), update K and V
            let mut data3 = v.to_vec();
            data3.push(0x00);
            k_mac = Self::hmac_sha256(&k_mac, &data3);
            v = Self::hmac_sha256(&k_mac, &v);
        }
    }
}