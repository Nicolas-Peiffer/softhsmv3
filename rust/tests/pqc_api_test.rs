use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::KemCore;
use rand::rngs::OsRng;

#[test]
fn test_ml_kem() {
    let (dk, ek) = ml_kem::MlKem768::generate(&mut OsRng);
    let (ct, ss1) = ek.encapsulate(&mut OsRng).unwrap();
    let ss2 = dk.decapsulate(&ct).unwrap();
    assert_eq!(ss1, ss2);
}

// ── SLH-DSA context string + deterministic mode tests ────────────────────────
// Use slh_keygen_internal with fixed seeds to avoid rand_core version mismatch
// between test harness (rand 0.8 → rand_core 0.6) and slh-dsa (rand_core 0.10).

fn make_test_sk() -> slh_dsa::SigningKey<slh_dsa::Sha2_128s> {
    slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::slh_keygen_internal(
        &[0x01u8; 16], // SK.seed
        &[0x02u8; 16], // SK.prf
        &[0x03u8; 16], // PK.seed
    )
}

#[test]
fn test_slh_dsa_sign_verify_with_context() {
    use signature::Keypair;
    let sk = make_test_sk();
    let vk = sk.verifying_key();

    let ctx_a: &[u8] = b"context-A";
    let ctx_b: &[u8] = b"context-B";
    let msg = b"hello FIPS 205";

    let sig = sk
        .try_sign_with_context(msg, ctx_a, None)
        .expect("sign with context must succeed");

    vk.try_verify_with_context(msg, ctx_a, &sig)
        .expect("verify with same context must succeed");

    assert!(
        vk.try_verify_with_context(msg, ctx_b, &sig).is_err(),
        "verify with wrong context must fail"
    );
}

#[test]
fn test_slh_dsa_deterministic_produces_same_signature() {
    // Signing the same message twice with deterministic mode (opt_rand = PK.seed)
    // must produce identical signatures (FIPS 205 §10).
    let sk = make_test_sk();
    let sk_vec = sk.to_vec();

    // SK layout: SK.seed(n) || SK.prf(n) || PK.seed(n) || PK.root(n); n = len/4
    let n = sk_vec.len() / 4;
    let pk_seed = sk_vec[2 * n..3 * n].to_vec();

    let msg = b"deterministic signing test";
    let sig1 = sk
        .try_sign_with_context(msg, &[], Some(&pk_seed))
        .expect("deterministic sign 1 must succeed");
    let sig2 = sk
        .try_sign_with_context(msg, &[], Some(&pk_seed))
        .expect("deterministic sign 2 must succeed");

    assert_eq!(
        sig1.to_vec(),
        sig2.to_vec(),
        "deterministic signatures must be identical"
    );
}

#[test]
fn test_slh_dsa_context_cross_verify_fails_on_mismatch() {
    use signature::Keypair;
    let sk = make_test_sk();
    let vk = sk.verifying_key();
    let msg = b"cross-context mismatch test";

    let sig = sk
        .try_sign_with_context(msg, b"sign-ctx", None)
        .expect("sign must succeed");

    assert!(
        vk.try_verify_with_context(msg, b"verify-ctx", &sig).is_err(),
        "cross-context verification must fail"
    );
}
