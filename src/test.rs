use super::*;
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

#[test]
pub fn society_can_encrypt_and_decrypt() {
    let t = 2;
    let n = 3;
    let message = b"Hello, world!";
    let mut rng = ChaCha20Rng::seed_from_u64(23u64);
    // create n actors with threshold of t
    let actors: Vec<Actor> = (1..n).map(|_| {
        Actor::new(t, rng.clone())
    }).collect::<Vec<_>>();
    // create a new society (each member already has a secret poly)
    let society = Society::new(actors, n, t);
    society.dkg();
    // TODO disputes + verification
    let r1 = Fr::rand(&mut rng.clone());
    let r2 = Fr::rand(&mut rng.clone());
    let h1 = G1::generator().mul(r1); 
    let h2 = G2::generator().mul(r2);
    let mpk = society.derive_pubkey(h1, h2);
    // now we want to reconstruct the secret key and decrypt the message
    let sks = society.derive_secret_keys();
    let mut msk = sks[0].clone();
    for i in 1..sks.len() - 1 {
        msk = msk + sks[i].clone();
    }
    let message_digest = sha256(message);
    let m = slice_to_array_32(&message_digest).unwrap();
    let ciphertext = encrypt(m, h1, mpk, &mut rng);
    let recovered_message_digest = decrypt(&ciphertext, ciphertext.u.mul(msk), h2);

    assert_eq!(recovered_message_digest, m);
}