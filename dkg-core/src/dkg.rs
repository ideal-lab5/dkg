//!
//! # DKG Core
//! 
//! The main library that builds the primtives and algorithms needed
//! to perform (blind) dkg. This module supports both std and no-std compilation.
//! 
//!
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::Pairing,
};
use ark_ff::UniformRand;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    ops::Mul,
    rand::Rng,
    Zero,
};
use ark_crypto_primitives::{
    Error as CryptoPrimitivesError,
    signature::{
        schnorr,
        schnorr::{Parameters, Signature},
        SignatureScheme,
    },
};
use blake2::Blake2s256 as Blake2s;
use sha2::Digest;

use ark_bls12_381::{
    Bls12_381, Fr,
    G1Projective as G1, G2Affine, 
    G2Projective as G2
};
use crate::types::*;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

/// generate a new random polynomial over the field Fr
pub fn keygen<R: Rng + Sized>(
    t: usize,
    mut rng: R
) -> DensePolynomial<Fr> {
    DensePolynomial::<Fr>::rand(t as usize, &mut rng)
}

/// calculate the polynomial evaluated at 0
pub fn calculate_secret(f: DensePolynomial<Fr>) -> Fr {
    f.clone().evaluate(&<Fr>::from(0u64))
}

/// calculate the public key in G1 and G2
/// 
/// * `h1`: A generator of G1
/// * `h2`: A generator of G2
/// * `sk`: A secret key in the field Fr
/// 
pub fn calculate_pubkey(h1: G1, h2: G2, sk: Fr) -> PublicKey {
    PublicKey {
        g1: h1.mul(sk),
        g2: h2.mul(sk),
    }
}

/// to verify a share we g^(share) and check if it equals the commitment
pub fn verify_share(
    g2: G2, 
    share: Fr, 
    commitment: G2
) -> bool {
    let verify = g2.mul(share);
    verify.eq(&commitment)
}

/// calculate shares and commitments {(f(i), g2^f(i))} for i in [n]
///
/// * `n`: The number of shares to calculate
/// * `g2`: A generator of G2 (progective)
/// * `poly`: A polynomial over Fr
/// 
pub fn calculate_shares_and_commitments(
    t: u8, 
    n: u8, 
    g2: G2, 
    poly: DensePolynomial<Fr>,
) -> Vec<(Fr, G2)> {
    // first calculate all commitments
    let c: G2 = poly.coeffs.iter()
            .map(|coeff| g2.mul(coeff))
            .fold(G2::zero(), |a, b| a + b);
    (1..n+1).map(|k| {
        // don't calculate '0'th share because that's the secret
        let secret_share = poly.clone().evaluate(&<Fr>::from(k)); 
        // calculate commitment for the share
        let commitment = g2.mul(secret_share);
        (secret_share, commitment) 
    }).collect::<Vec<_>>()
}

/// combine two public keys
pub fn combine_pubkeys(pk1: PublicKey, pk2: PublicKey) -> PublicKey {
    PublicKey {
        g1: pk1.g1 + pk2.g1,
        g2: pk1.g2 + pk2.g2,
    }
}

/// combine two secrets
pub fn combine_secrets(sk1: Fr, sk2: Fr) -> Fr {
    sk1 + sk2
}

/// TODO: these should really be in their own file...
/// signature with BLS12-381 secret 
pub fn sign<R: Rng + Sized>(
    message: &[u8],
    sk: schnorr::SecretKey<G1>,
    parameters: Parameters<G1, Blake2s>,
    mut rng: R,
) -> Result<Signature<G1>, CryptoPrimitivesError> {
    // let s: schnorr::SecretKey<G1> = schnorr::SecretKey(sk);
    // let parameters = schnorr::Schnorr::<G1, Blake2s>::setup::<_>(&mut rng).unwrap();
    schnorr::Schnorr::<G1, Blake2s>::sign(
        &parameters, 
        &sk, 
        &message, 
        &mut rng,
    )
}

/// verify signature over BLS12-381
pub fn verify<R: Rng + Sized>(
    message: &[u8],
    pk: schnorr::PublicKey<G1>,
    signature: Signature<G1>,
    parameters: Parameters<G1, Blake2s>,
    mut rng: R,
) -> Result<bool, CryptoPrimitivesError>  {
    schnorr::Schnorr::<G1, Blake2s>::verify(
        &parameters,
        &pk,
        &message,
        &signature,
    )
}

/// encrypts the message to a given public key
pub fn encrypt<R: Rng + Sized>(
    m: &[u8;32], 
    g1: G1, 
    pubkey: G2, 
    rng: &mut R
) -> Ciphertext {
    // rand val
    let r = Fr::rand(rng);
    // calculate 'ephemeral' generator (like pubkey)
    let u = g1.mul(r);
    // verification key
    let vkr = Bls12_381::pairing(g1, pubkey.mul(r));
    let mut v = Vec::new();
    vkr.serialize_compressed(&mut v).unwrap();
    // hash it
    v = sha256(&v);
    // encode the message
    for i in 0..32 {
        v[i] ^= m[i];
    }
    // hash the encoded message using random generator
    let h = hash_h(u, &v);
    // verification key
    let w = h.mul(r);
    Ciphertext { u, v, w }
}

/// decrypts a message using the provided key
pub fn decrypt(
    ct: Vec<u8>, 
    sk: G1, 
    g2:  G2
) -> Vec<u8> {
    let r = Bls12_381::pairing(sk, g2);
    let mut ret = Vec::new();
    r.serialize_compressed(&mut ret).unwrap();
    ret = sha256(&ret);
    // decode the message
    for (i, ri) in ret.iter_mut().enumerate().take(32) {
        *ri ^= ct[i];
    }
    ret
}

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

fn hash_h(g: G1, x: &[u8]) -> G2 {
    let mut serialized = Vec::new();
    g.serialize_compressed(&mut serialized).unwrap();
    serialized.extend_from_slice(x);
    hash_to_g2(&serialized).into()
}

fn hash_to_g2(b: &[u8]) -> G2Affine {
    let mut nonce = 0u32;
    loop {
        let c = [b"cryptex-domain-g2", b, b"cryptex-sep", &nonce.to_be_bytes()].concat();
        match G2Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
                return v.mul_by_cofactor_to_group().into_affine();
            }
            None => nonce += 1,
        }
    }
}


// TODO
    // /// verify that the pairings inside the ciphertexts add up
    // pub fn verify_ciphertext(&self, c: &TPKECipherText) -> bool {
    //     let h = hash_h(c.u, &c.v);
    //     let p1 = Bls12_381::pairing(self.g1, c.w);
    //     let p2 = Bls12_381::pairing(c.u, h);
    //     p1 == p2
    // }

    // /// verify that the shares given as parameter are valid
    // pub fn verify_share(&self, i: usize, ui: G1, c: &TPKECipherText) -> bool {
    //     if i > self.l.try_into().unwrap() {
    //         return false;
    //     }
    //     let yi = self.vks[i];
    //     let p1 = Bls12_381::pairing(ui, self.g2);
    //     let p2 = Bls12_381::pairing(c.u, yi);
    //     p1 == p2
    // }

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::{
        ChaCha20Rng,
        rand_core::SeedableRng,
    };
    use ark_ec::Group;

    pub fn slice_to_array_32(slice: &[u8]) -> Option<&[u8; 32]> {
        if slice.len() == 32 {
            let ptr = slice.as_ptr() as *const [u8; 32];
            unsafe {Some(&*ptr)}
        } else {
            None
        }
    }

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
        // in this simplified version:
        // this maps: (idx ~ participant) -> (shares + commitments)
        // so later on to simulate 'distribution + verification', a node 'k' would get all 
        // items shares[i][k] for all i
        let mut shares: Vec<Vec<(Fr, G2)>> = Vec::new();
        for i in 0..n-1 {
            let poly = keygen(2, rng.clone());
            let sk = calculate_secret(poly.clone());
            let pk = calculate_pubkey(h1, h2, sk);
            keys.push((sk, pk));
            let shares_and_commitments = 
                calculate_shares_and_commitments(
                    t, n, g2, poly.clone(),
                );
            shares.push(shares_and_commitments);
        }

        // now simulate verification of shares
        for i in 0..n-1 {
            for k in 0..n-1 {
                let share = shares[i as usize]
                    [k as usize].0;
                let commitment = shares[i as usize][k as usize].1;
                let verify = verify_share(g2, share, commitment);
                assert_eq!(true, verify);
            }
        }

        // calculate shared pubkey
        let mut ssk: Fr = keys[0].0.clone();
        let mut spk: PublicKey = keys[0].1.clone();
        let big_s: num_bigint::BigUint = ssk.into();
        for i in 1..n-1 {
            ssk = combine_secrets(ssk, keys[i as usize].0.clone());
            spk = combine_pubkeys(spk, keys[i as usize].1.clone());
        }
        let message_digest = sha256(b"hello world");
        let m = slice_to_array_32(&message_digest).unwrap();
        let ct = encrypt(m, h1, spk.g2, &mut rng.clone());
        let recovered = decrypt(ct.v, ct.u.mul(ssk), h2);
        assert_eq!(message_digest, recovered);
    }

    #[test]
    pub fn can_sign_and_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(23u64);
        let message = b"test".as_slice();

        let parameters = schnorr::Schnorr::<G1, Blake2s>::setup::<_>(&mut rng).unwrap();
        let poly = keygen(2, rng.clone());
        let sk = calculate_secret(poly.clone());
        let pk = parameters.generator.mul(sk);

        let ssk = schnorr::SecretKey::<G1>(sk);

        let signature = sign(&message, ssk, parameters.clone(), &mut rng).unwrap();
        let verify = verify(&message, pk.into(), signature, parameters.clone(), &mut rng).unwrap();
        assert_eq!(true, verify);
    }
}