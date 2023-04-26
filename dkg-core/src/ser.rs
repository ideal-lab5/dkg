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
    ChaCha20Rng, 
    rand_core::SeedableRng,
};
use serde::{
    Serialize, Deserialize, 
    ser::{
        Serializer, 
        SerializeStruct,
    },
    de::{ Deserializer }
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

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{
    ops::Mul,
    rand::RngCore,
};

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

#[derive(Serialize, Deserialize, Clone)]
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

/// a serializable version of 
/// ark_crypto_primitives::schnorr::Signature
#[derive(Serialize, Deserialize, Debug)]
pub struct SerializableSignature {
    pub prover_response:  Vec<u8>,
    pub verifier_challenge: Vec<u8>,
}

/// a serializable version of 
/// ark_crypto_primitives::schnorr::Parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableParameters {
    pub generator: Vec<u8>,
    pub salt: [u8;32],
}

pub fn keygen(seed: u64, threshold: u8) -> BEPoly {
    let rng = ChaCha20Rng::seed_from_u64(seed);
    let poly = dkg::keygen(threshold as usize, rng);
    BEPoly::new(poly)
}

pub fn calculate_secret(be_poly: BEPoly) -> Vec<u8> {
    let f = DensePolynomial::<Fr>::from_coefficients_vec(be_poly.coeffs);
    let secret: Fr = dkg::calculate_secret(f);
    let big_secret: num_bigint::BigUint = secret.into();
    big_secret.to_bytes_be()
}

pub fn calculate_shares_and_commitments(
    t: u8, 
    n: u8, 
    r2: u64,
    poly: BEPoly,
) -> Vec<Share> {
    let h2 = G2::generator().mul(Fr::from(r2));
    let f = DensePolynomial::<Fr>::from_coefficients_vec(poly.coeffs);
    let shares: Vec<(Fr, G2)> = dkg::calculate_shares_and_commitments(t, n, h2, f);
    let serializable_shares: Vec<Share> = shares.iter().map(|(s, c)| {
        let big_s: num_bigint::BigUint = Fr::into(*s);
        let mut commitments_bytes = Vec::new();
        c.serialize_compressed(&mut commitments_bytes).unwrap();
        Share {
            share: big_s.to_bytes_be(), 
            commitment: commitments_bytes,
        }
    }).collect::<Vec<_>>();
    serializable_shares
}

/// calculate the public key in G1 and G2 for a given secret
/// the secret should be encoded as big endian
pub fn calculate_pubkey(
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
pub fn combine_pubkeys(
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

    let mut g1_bytes = Vec::new();
    sum.g1.serialize_compressed(&mut g1_bytes).unwrap();

    let mut g2_bytes = Vec::new();
    sum.g2.serialize_compressed(&mut g2_bytes).unwrap();
    SerializablePublicKey {
        g1: g1_bytes,
        g2: g2_bytes,
    }
}

pub fn verify_share(
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

pub fn combine_secrets(
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

// needed??
pub fn signature_setup(
    seed: u64,
    r1: u64,
) -> SerializableParameters {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let g1 = G1::generator().mul(Fr::from(r1));
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let mut s_generator = Vec::new();
    g1.serialize_compressed(&mut s_generator).unwrap();
    SerializableParameters {
        generator: s_generator,
        salt: salt,
    }
}

pub fn sign(
    seed: u64,
    message: Vec<u8>,
    secret_key: Vec<u8>,
    parameters: SerializableParameters,
) -> SerializableSignature {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let big_sk = num_bigint::BigUint::from_bytes_be(&secret_key);
    let sk = Fr::from(big_sk);
    let x = schnorr::SecretKey::<G1>(sk);
    let generator = G1::deserialize_compressed(&parameters.generator[..]).unwrap();
    // since _hash is a private field... we'll create it this way for now
    // will probably need to modify the implementation later
    let mut params = schnorr::Schnorr::<G1, Blake2s>::setup::<_>(&mut rng).unwrap();
    params.generator = generator.into();
    params.salt = parameters.salt;
    let sig = dkg::sign(&message, x, params, &mut rng).unwrap();

    let big_pr: num_bigint::BigUint = sig.prover_response.into();
    let big_vc: num_bigint::BigUint = sig.verifier_challenge.into();

    SerializableSignature {
        prover_response: big_pr.to_bytes_be(),
        verifier_challenge: big_vc.to_bytes_be(),
    }
}

pub fn verify(
    seed: u64,
    message: Vec<u8>,
    public_key: SerializablePublicKey,
    signature: SerializableSignature,
    parameters: SerializableParameters,
) -> bool {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    // deserialize publickey (g1)
    let pk = G1::deserialize_compressed(&public_key.g1[..]).unwrap();
    // deserialize signature
    let big_pr = num_bigint::BigUint::from_bytes_be(&signature.prover_response);
    let big_vc = num_bigint::BigUint::from_bytes_be(&signature.verifier_challenge);
    let sig: Signature<G1> = Signature {
        prover_response: Fr::from(big_pr),
        verifier_challenge: Fr::from(big_vc),
    };
    // deserialize parameters
    let generator = G1::deserialize_compressed(&parameters.generator[..]).unwrap();
    // since _hash is a private field... we'll create it this way for now
    // will probably need to modify the implementation later
    let mut params = schnorr::Schnorr::<G1, Blake2s>::setup::<_>(&mut rng).unwrap();
    params.generator = generator.into();
    params.salt = parameters.salt;
    // TODO: handle errors
    dkg::verify(&message, pk.into(), sig, params, &mut rng).unwrap()
}

pub fn encrypt(
    seed: u64, 
    r1: u64, 
    msg: Vec<u8>, 
    pk: SerializablePublicKey
) -> SerializableCiphertext {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let h1 = G1::generator().mul(Fr::from(r1));
    // let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk).unwrap();
    let gpk = G2::deserialize_compressed(&pk.g2[..]).unwrap();
    let m = slice_to_array_32(&msg).unwrap();
    let out = dkg::encrypt(m, h1, gpk, &mut rng);
    let mut u_bytes = Vec::new();
    let mut v_bytes = Vec::new();
    out.u.serialize_compressed(&mut u_bytes).unwrap();
    out.v.serialize_compressed(&mut v_bytes).unwrap();
    SerializableCiphertext{
        u: u_bytes,
        v: out.v,
        w: v_bytes,
    }
}

/// sk is encoded as big endian
pub fn threshold_decrypt(
    r2: u64, 
    ciphertext: SerializableCiphertext, 
    sk: Vec<u8>,
) -> Vec<u8> {
    let h2 = G2::generator().mul(Fr::from(r2));
    let big_sk = num_bigint::BigUint::from_bytes_be(&sk);
    let x = Fr::from(big_sk);
    // convert c.u to group element
    let u = G1::deserialize_compressed(&ciphertext.u[..]).unwrap();
    let decryption_key = u.mul(x);
    let recovered_message = dkg::decrypt(ciphertext.v, decryption_key, h2);
    recovered_message.to_vec()
}

pub fn verify_ciphertext(
    g1: Vec<u8>, // g1
    u: Vec<u8>, // g1
    v: Vec<u8>, 
    w: Vec<u8>, // g2
) -> bool {
    let g1G1 = G1::deserialize_compressed(&g1[..]).unwrap();
    let uG1 = G1::deserialize_compressed(&u[..]).unwrap();
    let wG2 = G2::deserialize_compressed(&w[..]).unwrap();
    dkg::verify_ciphertext(g1G1, uG1, v, wG2)
}

// hash from G1 to G2
pub fn hash_h(
    r1: u64, 
    x: &[u8],
) -> Vec<u8> {
    let g1 = G1::generator().mul(Fr::from(r1));
    let g2 = dkg::hash_h(g1, x);
    let mut out_bytes = Vec::new();
    g2.serialize_compressed(&mut out_bytes).unwrap();
    out_bytes
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

#[cfg(test)]
pub mod test {
    use super::*;
    use sha2::Digest;

    fn sha256(b: &[u8]) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b);
        hasher.finalize().to_vec()
    }

    // #[test]
    // pub fn test_dkg_tss_with_serialization() {
    //     let t = 2;
    //     let n = 3;
    //     let g1 = G1::generator();
    //     let g2 = G2::generator();
    //     let r1 = 89430;
    //     let r2 = 110458345;
    //     let seed = 23u64;

    //     let mut keys: Vec<(Vec<u8>, SerializablePublicKey)> = Vec::new();
    //     // (share, commitment)
    //     let mut shares: Vec<Vec<Share>> = Vec::new();
    //     for i in 1..n {
    //         // keygen: Q: how can we verify this was serialized properly when randomly generated?
    //         let be_poly = keygen(seed, t);
    //         // calculate secret
    //         let secret = calculate_secret(be_poly.clone());        
    //         let pubkey = calculate_pubkey(r1, r2, secret.clone());
    //         let shares_and_commitments: Vec<Share> = calculate_shares_and_commitments(
    //             t, n, r1, be_poly,
    //         );
    //         shares.push(shares_and_commitments);
    //         keys.push((secret.clone(), pubkey.clone()));
    //     }

    //     // now simulate verification of shares
    //     for i in 0..n-1 {
    //         for k in 0..n-1 {
    //             let share = shares[i as usize]
    //                 [k as usize].clone().share;
    //             let commitment = shares[i as usize][k as usize].clone().commitment;
    //             let verify = verify_share(r2, share, commitment);
    //             assert_eq!(true, verify);
    //         }
    //     }

    //     // compute shared pubkey and secretkey
    //     let mut spk = keys[0].1.clone();
    //     let mut ssk = keys[0].0.clone();
    //     for i in 1..n-1 {
    //         spk = combine_pubkeys(spk, keys[i as usize].1.clone());
    //         ssk = combine_secrets(ssk, keys[i as usize].0.clone())
    //     }
    //     let message_digest = sha256(b"Hello, world!");
    //     let ct = encrypt(23u64, r1, message_digest.clone(), spk);
    //     let recovered_message = threshold_decrypt(r2, ct, ssk);
    //     assert_eq!(message_digest, recovered_message);
    // }

    #[test]
    pub fn can_sign_and_verify_with_serialization() {
        let message = b"test".as_slice();
        let seed = 23u64;
        let r1 = 123;
        let r2 = 123123;
        let parameters = signature_setup(seed, r1);
        let poly = keygen(seed, 2);
        let sk = calculate_secret(poly.clone());
        let pk = calculate_pubkey(r1, r2, sk.clone());

        let signature = sign(
            seed, message.to_vec(), sk.clone(), parameters.clone());
        let verify = verify(
            seed, message.to_vec(), pk, signature, parameters.clone());
        assert_eq!(true, verify);
    }
}
