use super::*;
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

use ark_std::collections::HashMap;

#[test]
pub fn test_dkg_tss() {
    let t = 2;
    let n = 3;
    let g1 = G1::generator();
    let g2 = G2::generator();
    let r1 = 89430;
    let r2 = 110458345;
    let h1 = G1::generator().mul(Fr::from(r1));
    let h2 = G2::generator().mul(Fr::from(r2));

    let mut rng = ChaCha20Rng::seed_from_u64(23u64);
    let mut keys: Vec<(Fr, PublicKey)> = Vec::new();
    for i in 1..n {
        let poly = keygen(2, rng.clone());
        let sk = calculate_secret(poly);
        let pk = calculate_pubkey(h1, h2, sk);
        keys.push((sk, pk));
    }

    // calculate shared pubkey
    let mut ssk: Fr = keys[0].0.clone();
    let mut spk: PublicKey = keys[0].1.clone();
    let big_s: num_bigint::BigUint = ssk.into();
    for i in 1..n-1 {
        ssk = combine_secrets(ssk, keys[i].0.clone());
        spk = combine_pubkeys(spk, keys[i].1.clone());
    }
    let message_digest = sha256(b"hello world");
    let m = slice_to_array_32(&message_digest).unwrap();
    let ct = encrypt(m, h1, spk.g2, &mut rng.clone());
    let recovered = decrypt(ct.v, ct.u.mul(ssk), h2);
    assert_eq!(message_digest, recovered);
}

#[test]
pub fn test_dkg_tss_with_serialization() {
    let t = 2;
    let n = 3;
    let g1 = G1::generator();
    let g2 = G2::generator();
    let r1 = 89430;
    let r2 = 110458345;
    let seed = 23u64;

    let mut keys: Vec<(Vec<u8>, SerializablePublicKey)> = Vec::new();
    for i in 1..n {
        // keygen: Q: how can we verify this was serialized properly when randomly generated?
        let be_poly = s_keygen(seed, t);
        // calculate secret
        let secret = s_calculate_secret(be_poly.clone());        
        let pubkey = s_calculate_pubkey(r1, r2, secret.clone());
        keys.push((secret.clone(), pubkey.clone()));
    }
    // // compute shared pubkey and secretkey
    let mut spk = keys[0].1.clone();
    let mut ssk = keys[0].0.clone();
    for i in 1..n-1 {
        spk = s_combine_pubkeys(spk, keys[i].1.clone());
        ssk = s_combine_secrets(ssk, keys[i].0.clone())
    }
    let message_digest = sha256(b"Hello, world!");
    let ct = s_encrypt(23u64, r1, message_digest.clone(), spk);
    let recovered_message = threshold_decrypt(r2, ct, ssk);
    assert_eq!(message_digest, recovered_message);
}
