mod secp256k1;
mod sha256;
mod signature;

use secp256k1::Point;
use signature::Signature;

fn main() {
    println!("=== Load & Validate Private Key from Hex ===");
    let hex_key = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    match Signature::load_privkey_from_hex(hex_key) {
        Some(loaded_key) => {
            println!("Loaded Private Key: {}", loaded_key.to_hex());
            
            println!("\n=== Public Key from Loaded Key ===");
            let pub_key = Point::G.mul_scalar(&loaded_key);
            println!("Public Key X: {}", pub_key.x.to_hex());
            println!("Public Key Y: {}", pub_key.y.to_hex());
        }
        None => println!("Invalid private key!"),
    }

    println!("\n=== Generate Random Private Key ===");
    let priv_key = Signature::generate_privkey();
    println!("Generated Private Key: {}", priv_key.to_hex());

    println!("\n=== Public Key ===");
    let pub_key = Point::G.mul_scalar(&priv_key);
    println!("Public Key X: {}", pub_key.x.to_hex());
    println!("Public Key Y: {}", pub_key.y.to_hex());

    println!("\n=== ECDSA Signature ===");
    let message = b"Hello!";
    let z = Signature::hash_message(message);
    println!("Message: Hello!");
    println!("Hash (z): {}", z.to_hex());

    let sig = Signature::sign(&priv_key, &z);
    println!("Signature r: {}", sig.r.to_hex());
    println!("Signature s: {}", sig.s.to_hex());

    println!("\n=== Verification ===");
    let valid = Signature::verify(&sig, &z, &pub_key);
    println!("Valid: {}", valid);
}