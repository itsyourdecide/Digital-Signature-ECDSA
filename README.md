# SHA256 + secp256k1 + ECDSA Signatures (Rust Implementation)

## What exactly is this?

This is a complete, from-scratch implementation of Bitcoin-grade cryptography in Rust. It includes SHA-256 hashing, the secp256k1 elliptic curve algebra, and ECDSA signatures with proper canonical normalization (low-S), deterministic nonces (RFC 6979), and EVM-compatible public key recovery. 

This is an evolution of my previous secp256k1 and SHA-256 repos, but completely overhauled and mathematically corrected. No external crypto crates—just pure math and code.

---

## The Dev Log: How Everything Was Broken (And How I Fixed It)

### The Beginning: A Cryptographic Nightmare

#### **1. The Wrong Group Order (N)**
In the early days of my `secp256k1.rs`, the constant `N` (the order of the curve) had a slight typo. The third limb was `0xFFFFFFFFFFFFFFFF` instead of `0xFFFFFFFFFFFFFFFE`. 
Sounds like a minor typo, right? Well, it meant that all modular arithmetic modulo $N$ was off by $2^{128}$! 
**Result:** Signatures never verified because the modular inversion was fundamentally broken.

#### **2. The "Two Fields" Problem**
When I initially wrote the `U256` struct, I assumed that key generation and all curve operations happened in the same finite field modulo `P`. To my disappointment, that’s not how elliptic curve cryptography works. Coordinates live in the base field (modulo `P`), but signatures and scalars live in the scalar field (modulo `N`).
I had to **unify the architecture**: making every function flexible enough to accept an arbitrary modulus (`P` for points, `N` for signatures).

---

### Phase 1: Core Refactoring & Unification (`secp256k1.rs`)

**What I actually fixed:**

1. **Added `is_zero()`** — A fast way to check for zero, which is critical during signature generation.
2. **Added `from_bytes()`** — Converts a 32-byte array straight into a `U256` struct. Absolutely necessary for hashing messages.
3. **Unified Modular Arithmetic:**
   - `add_mod(a, b, modulus)` — Now accepts a modulus and reduces correctly.
   - `mul_mod(a, b, modulus)` — Smart routing: if the modulus is `P`, it uses fast reduction; for arbitrary moduli (like `N`), it falls back to the reliable "Russian peasant" (binary) multiplication.
   - `pow_mod(base, exp, modulus)` — Binary exponentiation with an arbitrary modulus.
   - `invert(a, modulus)` — Modular inversion using Fermat's Little Theorem.
4. **Upgraded Point Math:**
   - `Point::add()` and `Point::double()` now strictly enforce the `&U256::P` modulus. Point arithmetic is now permanently safe.

---

### Phase 2: The Signature Engine (`signature.rs`)

**The new mechanics:**

1. **Private Key Generation:**
   - `generate_privkey()` — Pulls raw entropy directly from the OS (`/dev/urandom`) and generates a random scalar in the strict range `[1, N-1]`.
2. **Key Loading & Validation:**
   - `load_privkey_from_hex(hex)` — Safely imports a private key from a hex string. It checks if the key is valid (not zero, strictly `< N`) and returns an `Option`.
3. **ECDSA Signing (RFC 6979 & EVM Ready):**
   - `sign(d, z)` — Signs the message hash `z` using the private key `d`.
   - **Deterministic Nonce:** The ephemeral key $k$ is no longer left to the mercy of hardware entropy. It is generated deterministically using **RFC 6979** (HMAC-SHA256 DRBG), making lattice attacks mathematically impossible.
   - **Recovery ID:** The function now outputs `(r, s, v)`, where `v` is the parity of the $Y$ coordinate, allowing public key recovery (`ecrecover`).
   - **Critical feature:** I implemented canonical Low-S normalization (EIP-2 standard).
     - If `s > N/2`, it forcibly flips it: `s = N - s` (and correspondingly mathematically reflects the `v` parity).
     - This prevents **Signature Malleability** — a vulnerability that causes modern blockchains to immediately reject your transactions.
4. **ECDSA Verification:**
   - `verify(sig, z, pubkey)` — Mathematically proves the signature belongs to the public key owner. Recalculates the point $R'$ using $u_1 = z \cdot s^{-1} \pmod n$ and $u_2 = r \cdot s^{-1} \pmod n$.
5. **Message Hashing:**
   - `hash_message(msg)` — Hashes raw bytes via SHA-256 and casts the result to `U256`.

---

### Phase 3: The Main Workflow (`main.rs`)

It used to be a hardcoded test. Now it’s a fully functional pipeline:

1. **Loads a key from hex:** Demonstrates validation. If someone tries a bad key, it cleanly returns `None`.
2. **Derives the Public Key:** Calculates $Q = d \cdot G$.
3. **Generates a brand new random key** to prove the entropy engine works.
4. **Signs a message:** `Signature::sign(&privkey, &z)`
5. **Verifies the payload:** Returns `Valid: true` if the math checks out.

---

## Constants Cheat Sheet

| Constant | Purpose |
|----------|---------|
| `P` | The prime base field (used for $x, y$ point coordinates). |
| `N` | The order of the cyclic group (used for scalars, keys, and signatures). |
| `ONE` | Just `U256(1)`. |
| `P_MINUS_2` | Precomputed $P - 2$ for modular inversion (Fermat). |
| `G` | The Generator Point — the origin of the secp256k1 universe. |
| `HALF_N` | $N/2$ — The strict threshold for Low-S normalization. |

---

## Why does this architecture matter?

### **1. Signature Malleability (EIP-2)**
If you sign a message and get a valid `(r, s)`, the mathematical mirror `(r, N - s)` is *also* a valid signature! This means an attacker in the mempool could mutate your transaction without knowing your private key.
**The Fix:** We strictly require `s <= N/2`. If the engine generates an `s` that is too high, we invert it on the spot.

### **2. The Two Fields Trap (P vs N)**
- Points on the curve live in field **P**.
- Scalars (private keys, nonces, signature parts) live in group **N**.
- If you mix them up, your crypto engine produces garbage.
**The Fix:** Every single modular function explicitly demands a `modulus` parameter to prevent cross-contamination.

### **3. The Entropy Trap (RFC 6979)**
If your random number generator glitches and you reuse the ephemeral key $k$ for two different messages, your private key can be derived with simple algebra. Even a 1-bit statistical bias in $k$ allows attackers to extract your key using Lattice Attacks (Hidden Number Problem).
**The Fix:** I removed reliance on `/dev/urandom` during signing. The engine now uses the **RFC 6979** standard, acting as a Deterministic Random Bit Generator (DRBG) via HMAC-SHA256. $k$ is now a perfectly uniform derivative of your private key and the message hash.

### **4. EVM Compatibility (Recovery ID 'v')**
Ethereum and other EVM chains do not include your public key in the transaction payload to save gas. Instead, smart contracts use `ecrecover` to deduce your public key mathematically from the signature itself.
**The Fix:** The signature engine calculates the `v` parameter, tracking the parity (even/odd) of the $Y$ coordinate of the $R$ point. If the Low-S rule flips the $s$ value, the engine reflects the point across the X-axis by inverting `v`. These signatures are now native to Ethereum.

---

## Project Structure

```text
src/
├── secp256k1.rs    ← Core Math: U256, Elliptic Curve Points, Modular Arithmetic
├── sha256.rs       ← Hashing Engine
├── signature.rs    ← Cryptography: Keygen, ECDSA Sign/Verify, RFC 6979
└── main.rs         ← The orchestrator and demo workflow
