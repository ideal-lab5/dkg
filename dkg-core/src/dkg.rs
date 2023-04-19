//!
//! # DKG Core
//! 
//! The main library that builds the primtives and algorithms needed
//! to perform (blind) dkg. This module supports both std and no-std compilation.
//! 
//!

#[cfg(test)]
mod test;

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
};
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
pub fn keygen<R: Rng + Sized>(t: usize, mut rng: R) -> DensePolynomial<Fr> {
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

/// calculate shares and commitments {(f(i), g2^f(i))} for i in [n]
///
/// * `n`: The number of shares to calculate
/// * `g2`: A generator of G2 (progective)
/// * `poly`: A polynomial over Fr
/// 
pub fn calculate_shares(n: u8, g2: G2, poly: DensePolynomial<Fr>) -> Vec<(Fr, G2)> {
    (1..n+1).map(|k| {
        // don't calculate '0'th share because that's the secret
        let secret_share = poly.clone().evaluate(&<Fr>::from(k)); 
        // calculate commitment 
        let c = g2.mul(secret_share);
        (secret_share, c) 
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

/// decrypts a message using the provided key shares
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
