//! 
//! Serializable wrappers for DKG functions
//!
use crate::dkg;
use ark_ec::Group;
use ark_bls12_381::{
    Fr,
    G1Projective as G1,
    G2Projective as G2
};
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use rand_chacha::{
    ChaCha20Rng, rand_core::SeedableRng,
};
use serde::{
    Serialize, Deserialize, 
    ser::{
        Serializer, 
        SerializeStruct,
    },
    de::{ Deserializer }
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{
    ops::Mul,
};
use wasm_bindgen::JsValue;
use crate::types::*;


/// a serializable wrapper to represent polynomial coefficiants in the field Fr
/// when serialized, this struct represents coefficients as big endian byte arrays 
#[derive(Clone, Debug)]
pub struct BEPoly {
    pub coeffs: Vec<Fr>,
}

impl BEPoly {
    pub fn new(dense_poly: DensePolynomial<Fr>) -> BEPoly {
        BEPoly {
            coeffs: dense_poly.coeffs().to_vec(),
        }
    }
}

impl Serialize for BEPoly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("BEPoly", 1)?;
        // each coefficient as big endian
        let be_coeffs = self.coeffs.clone().into_iter().map(|c| {
            let big_c: num_bigint::BigUint = Fr::into(c);
            big_c.to_bytes_be()
        }).collect::<Vec<_>>();
        state.serialize_field("coeffs", &be_coeffs)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BEPoly {
    fn deserialize<D>(deserializer: D) -> Result<BEPoly, D::Error>
        where D: Deserializer<'de>
    {
        let input: Vec<Vec<u8>> = Deserialize::deserialize(deserializer)?;
        let coeffs: Vec<Fr> = input.into_iter().map(|i| {
            let big_c = num_bigint::BigUint::from_bytes_be(&i);
            Fr::from(big_c)
        }).collect::<Vec<_>>();
        Ok(BEPoly {
            coeffs: coeffs,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct Share {
    pub share: Vec<u8>,
    pub commitment: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializablePublicKey {
    /// the public key in G1
    pub g1: Vec<u8>,
    /// the public key in G2
    pub g2: Vec<u8>,
}

/// Represents the ciphertext
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializableCiphertext {
    /// the recovery key
    pub u: Vec<u8>,
    /// the ciphered message
    pub v: Vec<u8>,
    /// the verification key
    pub w: Vec<u8>,
}

pub fn s_keygen(seed: u64, threshold: u8) -> BEPoly {
    let rng = ChaCha20Rng::seed_from_u64(seed);
    let poly = dkg::keygen(threshold as usize, rng);
    BEPoly::new(poly)
}

pub fn s_calculate_secret(be_poly: BEPoly) -> Vec<u8> {
    let f = DensePolynomial::<Fr>::from_coefficients_vec(be_poly.coeffs);
    let secret: Fr = dkg::calculate_secret(f);
    let big_secret: num_bigint::BigUint = secret.into();
    big_secret.to_bytes_be()
}

pub fn s_calculate_shares(
    t: u8, 
    n: u8, 
    coeffs: Vec<Fr>,
) -> Vec<Share> {
    let h2 = G2::generator();
    let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    let shares: Vec<(Fr, G2)> = dkg::calculate_shares_and_commitments(t, n, h2, f);
    let serializable_shares: Vec<Share> = shares.iter().map(|(s, c)| {
        let big_s: num_bigint::BigUint = Fr::into(*s);
        let bytes_be_s = big_s.to_bytes_be();
        // TODO: get proper vec size, that one is way too big
        let mut commitments_bytes = Vec::with_capacity(1000);
        c.serialize_compressed(&mut commitments_bytes).unwrap();
        Share {
            share: bytes_be_s, 
            commitment: commitments_bytes,
        }
    }).collect::<Vec<_>>();
    serializable_shares
}

/// calculate the public key in G1 and G2 for a given secret
/// the secret should be encoded as big endian
pub fn s_calculate_pubkey(
    r1: u64, 
    r2: u64, 
    secret_be: Vec<u8>,
) -> SerializablePublicKey {
    // try recover secret
    let big_secret: num_bigint::BigUint = num_bigint::BigUint::from_bytes_be(&secret_be);
    let sk = Fr::from(big_secret);
    let h1 = G1::generator().mul(Fr::from(r1)); 
    let h2 = G2::generator().mul(Fr::from(r2));
    let pubkey = dkg::calculate_pubkey(h1, h2, sk);
    // could make bytes the size of both key
    // then when deserializing, just make sure I use the right number of bytes for each key
    let mut bytes_1 = Vec::with_capacity(1000);
    pubkey.g1.serialize_compressed(&mut bytes_1).unwrap();

    let mut bytes_2 = Vec::with_capacity(1000);
    pubkey.g2.serialize_compressed(&mut bytes_2).unwrap();
    
    SerializablePublicKey {
        g1: bytes_1,
        g2: bytes_2,
    }
}

/// will give the master pubkey in G2 only
pub fn s_combine_pubkeys(
    pk1: SerializablePublicKey,
    pk2: SerializablePublicKey
) -> SerializablePublicKey {
    let pubkey1 = PublicKey {
        g1: G1::deserialize_compressed(&pk1.g1[..]).unwrap(),
        g2: G2::deserialize_compressed(&pk1.g2[..]).unwrap(),
    };

    let pubkey2 = PublicKey {
        g1: G1::deserialize_compressed(&pk2.g1[..]).unwrap(),
        g2: G2::deserialize_compressed(&pk2.g2[..]).unwrap(),
    };

    let sum = dkg::combine_pubkeys(pubkey1, pubkey2);

    let mut g1_bytes = Vec::with_capacity(1000);
    sum.g1.serialize_compressed(&mut g1_bytes).unwrap();

    let mut g2_bytes = Vec::with_capacity(1000);
    sum.g2.serialize_compressed(&mut g2_bytes).unwrap();
    SerializablePublicKey {
        g1: g1_bytes,
        g2: g2_bytes,
    }
}

pub fn s_verify_share(
    r2: u64,
    share_be: Vec<u8>, 
    raw_commitment: Vec<u8>,
) -> bool {
    // recover the generator
    // let g2 = G2::deserialize_compressed(&generator[..]).unwrap();
    let g2 = G2::generator().mul(Fr::from(r2 as u64));
    // recover the share
    let big_share = num_bigint::BigUint::from_bytes_be(&share_be);
    let share = Fr::from(big_share);
    // recover the commitment
    let commitment = G2::deserialize_compressed(&raw_commitment[..]).unwrap();
    dkg::verify_share(g2, share, commitment)
}

pub fn s_combine_secrets(
    s1: Vec<u8>, s2: Vec<u8>
) -> Vec<u8> {
    // each secret is encoded as big endian
    let big_s1 = num_bigint::BigUint::from_bytes_be(&s1);
    let big_s2 = num_bigint::BigUint::from_bytes_be(&s2);
    // // convert both to field elements
    let x1 = Fr::from(big_s1);
    let x2 = Fr::from(big_s2);
    let x = dkg::combine_secrets(x1, x2);
    let big_x: num_bigint::BigUint = x.into();
    big_x.to_bytes_be()
}

pub fn s_encrypt(seed: u64, r1: u64, msg: Vec<u8>, pk: SerializablePublicKey) -> SerializableCiphertext {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let h1 = G1::generator().mul(Fr::from(r1));
    // let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk).unwrap();
    let gpk = G2::deserialize_compressed(&pk.g2[..]).unwrap();
    let m = slice_to_array_32(&msg).unwrap();
    let out = dkg::encrypt(m, h1, gpk, &mut rng);
    let mut u_bytes = Vec::with_capacity(1000);
    let mut v_bytes = Vec::with_capacity(1000);
    out.u.serialize_compressed(&mut u_bytes).unwrap();
    out.v.serialize_compressed(&mut v_bytes).unwrap();
    SerializableCiphertext{
        u: u_bytes,
        v: out.v,
        w: v_bytes,
    }
}

/// sk is encoded as big endian
pub fn threshold_decrypt(r2: u64, ciphertext: SerializableCiphertext, sk: Vec<u8>) -> Vec<u8> {
    let h2 = G2::generator().mul(Fr::from(r2));
    let big_sk = num_bigint::BigUint::from_bytes_be(&sk);
    let x = Fr::from(big_sk);
    // convert c.u to group element
    let u = G1::deserialize_compressed(&ciphertext.u[..]).unwrap();
    let decryption_key = u.mul(x);
    let recovered_message = dkg::decrypt(ciphertext.v, decryption_key, h2);
    recovered_message.to_vec()
}

/// Convert a slice of u8 to an array of u8 of size 32
/// 
/// * `slice`: The slize to convert
/// 
pub fn slice_to_array_32(slice: &[u8]) -> Option<&[u8; 32]> {
    if slice.len() == 32 {
        let ptr = slice.as_ptr() as *const [u8; 32];
        unsafe {Some(&*ptr)}
    } else {
        None
    }
}

// use rand_chacha::{
// 	ChaCha20Rng,
// 	rand_core::SeedableRng,
// };
// #[cfg(test)]
// pub mod test {
//     use super::*;
//     use sha2::Digest;

//     fn sha256(b: &[u8]) -> Vec<u8> {
//         let mut hasher = sha2::Sha256::new();
//         hasher.update(b);
//         hasher.finalize().to_vec()
//     }

//     #[test]
//     pub fn test_dkg_tss_with_serialization() {
//         let t = 2;
//         let n = 3;
//         let g1 = G1::generator();
//         let g2 = G2::generator();
//         let r1 = 89430;
//         let r2 = 110458345;
//         let seed = 23u64;

//         let mut keys: Vec<(Vec<u8>, SerializablePublicKey)> = Vec::new();
//         for i in 1..n {
//             // keygen: Q: how can we verify this was serialized properly when randomly generated?
//             let be_poly = s_keygen(seed, t);
//             // calculate secret
//             let secret = s_calculate_secret(be_poly.clone());        
//             let pubkey = s_calculate_pubkey(r1, r2, secret.clone());
//             keys.push((secret.clone(), pubkey.clone()));
//         }
//         // // compute shared pubkey and secretkey
//         let mut spk = keys[0].1.clone();
//         let mut ssk = keys[0].0.clone();
//         for i in 1..n-1 {
//             spk = s_combine_pubkeys(spk, keys[i].1.clone());
//             ssk = s_combine_secrets(ssk, keys[i].0.clone())
//         }
//         let message_digest = sha256(b"Hello, world!");
//         let ct = s_encrypt(23u64, r1, message_digest.clone(), spk);
//         let recovered_message = threshold_decrypt(r2, ct, ssk);
//         assert_eq!(message_digest, recovered_message);
//     }
// }