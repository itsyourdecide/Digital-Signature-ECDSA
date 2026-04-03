use sha256_core::secp256k1::{Point, U256};
use sha256_core::signature::Signature;

const HALF_N: U256 = U256([
    0xDFE9_2F46_681B_20A0,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
]);

fn sample_privkey() -> U256 {
    Signature::load_privkey_from_hex(
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
    )
    .expect("sample private key must be valid")
}

#[test]
fn known_public_key_matches_reference_vector() {
    let privkey = sample_privkey();
    let pubkey = Point::G.mul_scalar(&privkey);

    assert_eq!(
        pubkey.x.to_hex(),
        "50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    );
    assert_eq!(
        pubkey.y.to_hex(),
        "2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
    );
}

#[test]
fn sign_and_verify_round_trip() {
    let privkey = sample_privkey();
    let pubkey = Point::G.mul_scalar(&privkey);
    let z = Signature::hash_message(b"hello signature");

    let sig = Signature::sign(&privkey, &z);

    assert!(Signature::verify(&sig, &z, &pubkey));
}

#[test]
fn signing_is_deterministic_for_same_key_and_message() {
    let privkey = sample_privkey();
    let z = Signature::hash_message(b"same message");

    let sig_a = Signature::sign(&privkey, &z);
    let sig_b = Signature::sign(&privkey, &z);

    assert_eq!(sig_a, sig_b);
}

#[test]
fn signature_is_normalized_to_low_s() {
    let privkey = sample_privkey();
    let z = Signature::hash_message(b"low s check");
    let sig = Signature::sign(&privkey, &z);

    assert!(sig.s == HALF_N || !sig.s.is_greater_or_equal(&HALF_N));
}

#[test]
fn verification_fails_for_modified_message() {
    let privkey = sample_privkey();
    let pubkey = Point::G.mul_scalar(&privkey);
    let z = Signature::hash_message(b"original message");
    let tampered_z = Signature::hash_message(b"tampered message");
    let sig = Signature::sign(&privkey, &z);

    assert!(!Signature::verify(&sig, &tampered_z, &pubkey));
}

#[test]
fn verification_fails_for_modified_signature() {
    let privkey = sample_privkey();
    let pubkey = Point::G.mul_scalar(&privkey);
    let z = Signature::hash_message(b"signature tamper");
    let mut sig = Signature::sign(&privkey, &z);

    sig.r = U256::add_mod(&sig.r, &U256::ONE, &U256::N);

    assert!(!Signature::verify(&sig, &z, &pubkey));
}

#[test]
fn verification_fails_with_wrong_public_key() {
    let privkey = sample_privkey();
    let wrong_privkey = Signature::generate_privkey();
    let wrong_pubkey = Point::G.mul_scalar(&wrong_privkey);
    let z = Signature::hash_message(b"wrong pubkey");
    let sig = Signature::sign(&privkey, &z);

    assert!(!Signature::verify(&sig, &z, &wrong_pubkey));
}

#[test]
fn verification_rejects_zero_signature_components() {
    let privkey = sample_privkey();
    let pubkey = Point::G.mul_scalar(&privkey);
    let z = Signature::hash_message(b"zero components");

    let sig_r_zero = Signature {
        r: U256([0; 4]),
        s: U256::ONE,
        v: 0,
    };
    let sig_s_zero = Signature {
        r: U256::ONE,
        s: U256([0; 4]),
        v: 0,
    };

    assert!(!Signature::verify(&sig_r_zero, &z, &pubkey));
    assert!(!Signature::verify(&sig_s_zero, &z, &pubkey));
}

#[test]
fn verification_rejects_signature_components_out_of_range() {
    let privkey = sample_privkey();
    let pubkey = Point::G.mul_scalar(&privkey);
    let z = Signature::hash_message(b"out of range");

    let sig_r_big = Signature {
        r: U256::N,
        s: U256::ONE,
        v: 0,
    };
    let sig_s_big = Signature {
        r: U256::ONE,
        s: U256::N,
        v: 0,
    };

    assert!(!Signature::verify(&sig_r_big, &z, &pubkey));
    assert!(!Signature::verify(&sig_s_big, &z, &pubkey));
}

#[test]
fn private_key_loader_rejects_zero_and_accepts_valid_key() {
    assert!(Signature::load_privkey_from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    .is_none());

    assert!(Signature::load_privkey_from_hex(
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    )
    .is_some());

    assert!(Signature::load_privkey_from_hex(&U256::N.to_hex()).is_none());
}

#[test]
fn hash_message_matches_known_sha256_vector() {
    let z = Signature::hash_message(b"Hello!");

    assert_eq!(
        z.to_hex(),
        "334d016f755cd6dc58c53a86e183882f8ec14f52fb05345887c8a5edd42c87b7"
    );
}
