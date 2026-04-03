use sha256_core::secp256k1::Point;
use sha256_core::signature::Signature;

#[cfg(target_family = "unix")]
fn get_os_entropy() -> [u8; 32] {
    use std::fs::File;
    use std::io::Read;

    let mut buf = [0u8; 32];
    let mut file = File::open("/dev/urandom").expect("OS entropy failed: /dev/urandom not found");
    file.read_exact(&mut buf).expect("Failed to read from /dev/urandom");
    buf
}

#[cfg(target_os = "windows")]
fn get_os_entropy() -> [u8; 32] {
    
    #[link(name = "advapi32")]
    extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(RandomBuffer: *mut u8, RandomBufferLength: u32) -> u8;
    }

    let mut buf = [0u8; 32];
    unsafe {
        let res = RtlGenRandom(buf.as_mut_ptr(), buf.len() as u32);
        assert!(res != 0, "Windows OS entropy (RtlGenRandom) failed");
    }
    buf
}

fn main() {
    let entropy = get_os_entropy();


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
    let privkey = Signature::generate_privkey_from_entropy(&entropy)
        .expect("OS entropy produced invalid private key candidate");
    println!("Generated Private Key: {}", privkey.to_hex());

    println!("\n=== Public Key ===");
    let pub_key = Point::G.mul_scalar(&privkey);
    println!("Public Key X: {}", pub_key.x.to_hex());
    println!("Public Key Y: {}", pub_key.y.to_hex());

    println!("\n=== ECDSA Signature ===");
    let message = b"Hello!";
    let z = Signature::hash_message(message);
    println!("Message: Hello!");
    println!("Hash (z): {}", z.to_hex());

    let sig = Signature::sign(&privkey, &z);
    println!("Signature r: {}", sig.r.to_hex());
    println!("Signature s: {}", sig.s.to_hex());

    println!("\n=== Verification ===");
    let valid = Signature::verify(&sig, &z, &pub_key);
    println!("Valid: {}", valid);
}