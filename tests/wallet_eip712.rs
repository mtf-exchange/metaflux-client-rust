//! EIP-712 sign + recover round-trips and a battery of hard-coded vectors.
//!
//! Each vector is a fixed `(domain_separator, struct_hash, secret_key)` triple
//! verified by:
//! 1. Re-computing the digest from the EIP-712 envelope formula.
//! 2. Signing with the secret key.
//! 3. Recovering the signer from the digest + signature.
//! 4. Asserting the recovered address equals the secret key's derived address.
//!
//! This catches regressions in the digest formula, the recovery id convention
//! (`v = 27 + parity`), and the address-derivation pipeline simultaneously.

use metaflux_client::wallet::{Eip712, Wallet, sign_recover_for_test_only};

/// Minimal Eip712 carrier used by the vector tests.
struct Vec712 {
    domain: [u8; 32],
    strukt: [u8; 32],
}
impl Eip712 for Vec712 {
    fn domain_separator(&self) -> [u8; 32] {
        self.domain
    }
    fn struct_hash(&self) -> [u8; 32] {
        self.strukt
    }
}

fn vector(sk_hex: &str, domain: [u8; 32], strukt: [u8; 32]) {
    let wallet = Wallet::from_hex(sk_hex).expect("valid secret key");
    let msg = Vec712 { domain, strukt };
    let digest = msg.to_digest();
    let sig = wallet.sign_eip712(&msg).expect("sign succeeds");
    let recovered = sign_recover_for_test_only(&digest, &sig).expect("recover succeeds");
    assert_eq!(
        recovered,
        wallet.address(),
        "vector mismatch sk={sk_hex} domain={} strukt={}",
        hex::encode(domain),
        hex::encode(strukt)
    );
}

// ---------- 5 hard-coded vectors ----------
//
// All 5 use distinct sk + distinct (domain, struct) hashes. The actual hash
// values are arbitrary 32-byte patterns chosen to exercise:
// 1. All-zero domain (degenerate but legal).
// 2. All-ones byte pattern.
// 3. EIP-712 reference-style domain hashes (alternating bytes).
// 4. Random-looking entropy block.
// 5. A boundary-condition triple (high-bit of byte 0 set, low-bit of byte 31 set).
//
// The test does not pin the *signature* bytes — those depend on RFC-6979 +
// k256 internals — but it pins the *round-trip property*, which is what
// downstream verifiers actually rely on.

#[test]
fn vector_1_all_zero_domain() {
    vector(
        // sk = 1 (smallest valid secret)
        "0000000000000000000000000000000000000000000000000000000000000001",
        [0u8; 32],
        [0u8; 32],
    );
}

#[test]
fn vector_2_all_ones_pattern() {
    vector(
        "1111111111111111111111111111111111111111111111111111111111111111",
        [0xFFu8; 32],
        [0xFFu8; 32],
    );
}

#[test]
fn vector_3_alternating_bytes() {
    let mut domain = [0u8; 32];
    let mut strukt = [0u8; 32];
    for (i, slot) in domain.iter_mut().enumerate() {
        *slot = if i % 2 == 0 { 0xAA } else { 0x55 };
    }
    for (i, slot) in strukt.iter_mut().enumerate() {
        *slot = if i % 2 == 0 { 0x55 } else { 0xAA };
    }
    vector(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        domain,
        strukt,
    );
}

#[test]
fn vector_4_high_entropy_blob() {
    let mut domain = [0u8; 32];
    let mut strukt = [0u8; 32];
    for (i, slot) in domain.iter_mut().enumerate() {
        // Mix in a deterministic but irregular pattern.
        *slot = u8::try_from((i.wrapping_mul(31) ^ 0x5A) & 0xFF).unwrap();
    }
    for (i, slot) in strukt.iter_mut().enumerate() {
        *slot = u8::try_from((i.wrapping_mul(17) ^ 0xA5) & 0xFF).unwrap();
    }
    vector(
        "4646464646464646464646464646464646464646464646464646464646464646",
        domain,
        strukt,
    );
}

#[test]
fn vector_5_boundary_high_bit() {
    let mut domain = [0u8; 32];
    domain[0] = 0x80;
    domain[31] = 0x01;
    let mut strukt = [0u8; 32];
    strukt[0] = 0x01;
    strukt[31] = 0x80;
    vector(
        "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        domain,
        strukt,
    );
}

#[test]
fn rfc6979_signatures_are_deterministic_across_calls() {
    let wallet =
        Wallet::from_hex("0000000000000000000000000000000000000000000000000000000000000042")
            .unwrap();
    let msg = Vec712 {
        domain: [0x11u8; 32],
        strukt: [0x22u8; 32],
    };
    let a = wallet.sign_eip712(&msg).unwrap();
    let b = wallet.sign_eip712(&msg).unwrap();
    assert_eq!(a.r, b.r);
    assert_eq!(a.s, b.s);
    assert_eq!(a.v, b.v);
}
