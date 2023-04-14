use super::*;
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

use ark_std::collections::HashMap;

#[test]
pub fn society_can_encrypt_and_decrypt() {
    let t = 2;
    let n = 3;
    let g1 = G1::generator();
    let g2 = G2::generator();

    let rr1 = 89430;
    let rr2 = 110458345;

    let message = b"Hello, world!";
    let mut rng = ChaCha20Rng::seed_from_u64(23u64);
    // create n actors with threshold of t
    let actors: Vec<Actor> = (1..n).map(|i| {
        Actor::new(i, g1, g2, t, rng.clone())
    }).collect::<Vec<_>>();
    // create a new society (each member already has a secret poly)
    let society = Society::new(actors, n as u8, t);
    // society.dkg();
    // TODO disputes + verification
    let r1 = Fr::from(89430);
    let r2 = Fr::from(110458345);
    let h1 = G1::generator().mul(r1); 
    let h2 = G2::generator().mul(r2);
    let mpk = society.derive_pubkey(h1, h2);
    panic!("{:?}", mpk);
    // now we want to reconstruct the secret key and decrypt the message
    let sks = society.derive_secret_keys();
    let mut msk = sks[0].clone();
    for i in 1..sks.len() - 1 {
        msk = msk + sks[i].clone();
    }
    let message_digest = sha256(message);
    let m = slice_to_array_32(&message_digest).unwrap();
    let ciphertext = encrypt(m, h1, mpk, &mut rng);
    let recovered_message_digest = decrypt(ciphertext.v, ciphertext.u.mul(msk), h2);

    assert_eq!(recovered_message_digest, m);
}

#[test]
pub fn single_actor_can_calculate_and_verify_shares() {
    let t = 2;
    let n = 3;
    let g1 = G1::generator();
    let g2 = G2::generator();
    let mut rng = ChaCha20Rng::seed_from_u64(23u64);

    let actor = Actor::new(0, g1, g2, t, rng);
    let shares = actor.calculate_shares(5);
    shares.iter().for_each(|(s, c)| {
        assert_eq!(g2.mul(s), *c);
    });
}

#[test]
pub fn small_dkg_simulation() {
    let t = 2;
    let n = 3;
    let g1 = G1::generator();
    let g2 = G2::generator();
    let mut rng = ChaCha20Rng::seed_from_u64(23u64);
    // create n actors with threshold of t
    let actors: Vec<Actor> = (1..n).map(|i| {
        Actor::new(i, g1, g2, t, rng.clone())
    }).collect::<Vec<_>>();

    // then each actor generates shares and commitments
    // we'll assume that each actor has its own map, but for now, 
    // we use a hashmap(slot => (slot_of_sender, secret_share, commitment))
    // at the end it should look something like....
    // [0 -> {(1, s10, c10), (2, s20, c20)}. 1 -> {(0, s01, c01), (2, s21, c21)}, ...]
    let mut share_map = HashMap::<u64, Vec<(u64, Fr, G2)>>::new();
    for actor in actors.clone() {
        let shares = actor.calculate_shares(n as u8);
        // distribute a share to each of the other actors
        for i in 1..n {
            if i != actor.slot {
                let entry = (actor.slot, shares[i as usize].0, shares[i as usize].1);
                println!("sharing: {:?}", entry);
                // if the map is empty, insert a new vec with one entr
                share_map.entry(i)
                    .or_insert_with(Vec::new)
                    .push((actor.slot, shares[i as usize].0, shares[i as usize].1))
            }
        }
    }

    // now each actor verifies the shares it recieved
    for actor in actors {
        let shared_shares = share_map.get(&actor.slot).unwrap();
        for (slot, share, commitment) in shared_shares.iter() {
            // now verify each share
            assert_eq!(actor.g2.mul(share), *commitment);
        }
    }
}
