use ark_ec::{
    AffineRepr, Group, CurveGroup,
    pairing::Pairing,
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::Mul,
    rand::Rng,
};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};
use sha2::Digest;

use ark_bls12_381::{
    Bls12_381, Fr,
    G1Projective as G1, G2Affine, 
    G2Projective as G2
};

use serde::{Serialize, Deserialize};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[cfg(test)]
mod test;

#[derive(Serialize, Deserialize)]
pub struct Share {
    pub share: Vec<u8>,
    pub commitment: Vec<u8>,
}

// #[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SerializablePublicKey {
    /// the public key in G1
    pub p1: Vec<u8>,
    /// the public key in G2
    pub p2: Vec<u8>,
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

#[derive(Debug, Clone)]
enum Error {
    MessageLengthInvalid,
}

#[wasm_bindgen]
pub fn keygen(seed: u64, threshold: u8) -> Vec<u8> {
    let rng = ChaCha20Rng::seed_from_u64(seed);
    let h1 = G1::generator(); 
    let h2 = G2::generator();
    let actor = Actor::new(0, h1, h2, threshold, rng);
    // should return coefficients to polynomial
    let modulus: num_bigint::BigUint = Fr::MODULUS.into();
    // we assume only positive values
    let coeffs: Vec<Vec<u8>> = actor.poly.coeffs().iter().map(|c| {
        // something weird is going on with type annotations here..
        // c^modulus = c since the field is finite and prime order
        let a = c.pow(modulus.to_u64_digits());
        let big_c: num_bigint::BigUint = a.into();
        // be vs le?
        big_c.to_bytes_be()
    }).collect::<Vec<_>>();
    bincode::serialize(&coeffs).unwrap()
}

#[wasm_bindgen]
pub fn calculate_secret(coeffs_blob: Vec<u8>) -> Vec<u8> {
    let deserialized_coeffs: Vec<Vec<u8>> = bincode::deserialize(&coeffs_blob).unwrap();
    // convert BigUint -> Fr
    let coeffs: Vec<Fr> = deserialized_coeffs.iter().map(|c| {
        let big_c: num_bigint::BigUint = num_bigint::BigUint::from_bytes_be(c);
        Fr::from(big_c)
    }).collect::<Vec<_>>();
    let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    let secret: Fr = f.clone().evaluate(&<Fr>::from(0u64));
    let big_secret: num_bigint::BigUint = secret.into();
    bincode::serialize(&big_secret.to_bytes_be()).unwrap()
}

#[wasm_bindgen]
pub fn calculate_shares(n: u8, coeffs_blob: Vec<u8>) -> JsValue {
    let h2 = G2::generator();
    // TODO: this could be its own function (recover_poly(coeffs_blob))
    let deserialized_coeffs: Vec<Vec<u8>> = bincode::deserialize(&coeffs_blob).unwrap();
    let coeffs: Vec<Fr> = deserialized_coeffs.iter().map(|c| {
        let big_c: num_bigint::BigUint = num_bigint::BigUint::from_bytes_be(c);
        Fr::from(big_c)
    }).collect::<Vec<_>>();
    let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    let shares: Vec<(Fr, G2)> = do_calculate_shares(n, h2, f);
    let modulus: num_bigint::BigUint = Fr::MODULUS.into();
    let serializable_shares: Vec<Share> = shares.iter().map(|(s, c)| {
        // something weird is going on with type annotations here..
        // c^modulus = c since the field is finite and prime order
        let x = s.pow(modulus.to_u64_digits());
        // conver shares to biguint and then to_bytes_be
        let big_s: num_bigint::BigUint = x.into();
        let bytes_be_s = big_s.to_bytes_be();
        // can serialize c, TODO: get proper vec size, that one is way too big
        let mut commitments_bytes = Vec::with_capacity(1000);
        c.serialize_compressed(&mut commitments_bytes).unwrap();
        Share {
            share: bytes_be_s, 
            commitment: commitments_bytes,
        }
    }).collect::<Vec<_>>();

    // bincode::serialize(&serializable_shares).unwrap()
    serde_wasm_bindgen::to_value(&serializable_shares).unwrap()
}

/// calculate the public key in G1 and G2 for a given secret
#[wasm_bindgen]
pub fn calculate_pubkey(seed: u64, r1: u64, r2: u64, secret: Vec<u8>) -> JsValue {
    // try recover secret
    let big_secret_bytes_be = bincode::deserialize(&secret).unwrap();
    let big_secret: num_bigint::BigUint = num_bigint::BigUint::from_bytes_be(big_secret_bytes_be);
    let secret = Fr::from(big_secret);
    let rng = ChaCha20Rng::seed_from_u64(seed);
    let h1 = G1::generator().mul(Fr::from(r1)); 
    let h2 = G2::generator().mul(Fr::from(r2));
    let pk1 = h1.mul(secret);
    let pk2 = h2.mul(secret);
    // could make bytes the size of both key
    // then when deserializing, just make sure I use the right number of bytes for each key
    let mut bytes_1 = Vec::with_capacity(1000);
    pk1.serialize_compressed(&mut bytes_1).unwrap();

    let mut bytes_2 = Vec::with_capacity(1000);
    pk2.serialize_compressed(&mut bytes_2).unwrap();
    
    let pubkey = SerializablePublicKey {
        p1: bytes_1,
        p2: bytes_2,
    };
    serde_wasm_bindgen::to_value(&pubkey).unwrap()
}

/// will give the master pubkey in G2 only
#[wasm_bindgen]
pub fn combine_pubkeys(pk1: JsValue, pk2: JsValue) -> JsValue {
    // deserialize both keys
    // TODO: handle error if deserialization fails
    let w_pk1: SerializablePublicKey = serde_wasm_bindgen::from_value(pk1).unwrap();
    let w_pk2: SerializablePublicKey = serde_wasm_bindgen::from_value(pk2).unwrap();
    // pubkeys in G2
    let g2_pk1 = G2::deserialize_compressed(&w_pk1.p2[..]).unwrap();
    let g2_pk2 = G2::deserialize_compressed(&w_pk2.p2[..]).unwrap();
    let sum = g2_pk1 + g2_pk2;
    let mut bytes = Vec::with_capacity(1000);
    sum.serialize_compressed(&mut bytes).unwrap();
    serde_wasm_bindgen::to_value(&SerializablePublicKey {
        p1: w_pk1.p1,
        // this isn't really a good design here
        // i'm just doing this so we can combine keys
        // but this field might be ignored for now
        p2: bytes,
    }).unwrap()
}

#[wasm_bindgen]
pub fn combine_secrets(s1: Vec<u8>, s2: Vec<u8>) -> Vec<u8> {
    // each secret is encoded as big endian
    let big_s1 = num_bigint::BigUint::from_bytes_be(&s1);
    let big_s2 = num_bigint::BigUint::from_bytes_be(&s2);
    // // convert both to field elements
    let x1 = Fr::from(big_s1);
    let x2 = Fr::from(big_s2);
    let x = x1 + x2;
    let big_x: num_bigint::BigUint = x.into();
    big_x.to_bytes_be()
}

#[wasm_bindgen]
pub fn threshold_encrypt(seed: u64, r1: u8, msg: Vec<u8>, pk: JsValue) -> Result<JsValue, JsError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let h1 = G1::generator().mul(Fr::from(r1));
    let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk).unwrap();
    let gpk = G2::deserialize_compressed(&wpk.p2[..]).unwrap();
    let m = slice_to_array_32(&msg).unwrap();
    let out = encrypt(m, h1, gpk, &mut rng);
    let mut u_bytes = Vec::with_capacity(1000);
    let mut v_bytes = Vec::with_capacity(1000);
    out.u.serialize_compressed(&mut u_bytes).unwrap();
    out.v.serialize_compressed(&mut v_bytes).unwrap();
    Ok(serde_wasm_bindgen::to_value(&SerializableCiphertext{
        u: u_bytes,
        v: out.v,
        w: v_bytes,
    }).unwrap())
}

/// sk is encoded as big endian
#[wasm_bindgen]
pub fn threshold_decrypt(r2: u8, ciphertext_blob: JsValue, sk: Vec<u8>) -> Vec<u8> {
    let ciphertext: SerializableCiphertext = serde_wasm_bindgen::from_value(ciphertext_blob).unwrap();
    let h2 = G2::generator().mul(Fr::from(r2));
    let big_sk = num_bigint::BigUint::from_bytes_be(&sk);
    let x = Fr::from(big_sk);
    // convert c.u to group element
    let u = G1::deserialize_compressed(&ciphertext.u[..]).unwrap();
    let decryption_key = u.mul(x);
    let recovered_message = decrypt(ciphertext.v, decryption_key, h2);
    recovered_message.to_vec()
}

pub fn do_calculate_shares(n: u8, g2: G2, poly: DensePolynomial<Fr>) -> Vec<(Fr, G2)> {
    (1..n+1).map(|k| {
        // don't calculate '0'th share because that's the secret
        let secret_share = poly.clone().evaluate(&<Fr>::from(k)); 
        // calculate commitment 
        let c = g2.mul(secret_share);
        (secret_share, c) 
    }).collect::<Vec<_>>()
}

/// Represents a public key in both G1 and G2
// #[derive(Serialize)]
pub struct PublicKey {
    pub pub_g1: G1,
    pub pub_g2: G2,
}

/// Represents the ciphertext
pub struct Ciphertext {
    /// the recovery key
    pub u: G1,
    /// the ciphered message
    pub v: Vec<u8>,
    /// the verification key
    pub w: G2,
}

/// a society coordinates the:
/// formation of society
/// derivation of pubkey (for encryption)
/// derivation of secret key (for decryption)
pub struct Society {
    pub participants: Vec<Actor>,
    pub shares: u8,
    pub threshold: u8,
}

/// A society is a collection of participants that can generate shares amongst themselves,
/// derive a pubkey, and reencrypt a secret
impl Society {
    fn new(participants: Vec<Actor>, shares: u8, threshold: u8) -> Self {
        Self {
            participants, shares, threshold,
        }
    }

    /// the main distributed key generation algorithm
    /// each member of the society generates shares and distributes them
    /// 
    /// * `rng`: the random number generator
    /// 
    fn dkg(&self) {
        for p in self.participants.iter() {
            p.calculate_shares(self.shares);
        }
    }

    /// combine pubkeys to get a group public key
    /// 
    /// `generator`: The generator to be used to calculate a public key
    ///
    fn derive_pubkey(&self, h1: G1, h2: G2) -> G2  {
        // get a pubkey from each actor (in G2)
        let pubkeys = self.participants.iter().map(|p| {
            p.derive_pubkey(h1, h2)
        }).collect::<Vec<_>>();
        // using second returned val since we want the pubkey in G2
        let mut mpk = pubkeys[0].pub_g2;
        // instead of adding, should we be calculating the elliptic curve pairings? 
        for i in 1..pubkeys.len() - 1 {
            mpk = mpk + pubkeys[i].pub_g2
        }
        mpk
    }

    fn derive_secret_keys(&self) -> Vec<Fr> {
        self.participants.iter().map(|p| {
            p.secret()
        }).collect::<Vec<_>>()
    }
}

#[derive(Clone)]
pub struct Actor {
    pub slot: u64,
    // TODO: should this be over Fq or Fr?
    pub poly: DensePolynomial<Fr>,
    /// the generator for G1
    pub g1: G1,
    /// the generator for G2
    pub g2: G2,
}

impl Actor {
    /// create a new actor with a threshold value and a random polynomial with degree = threshold
    /// over the given scalar field
    /// 
    /// * `t`: the thresold value to set. This will be the 'threshold' in the TSS scheme
    /// * `r`: The random number generator used to generate the polynomial
    /// 
    pub fn new<R: Rng + Sized>(slot: u64, g1: G1, g2: G2, t: u8, mut rng: R) -> Actor {
        // generate secret and coefficients
        let rand_poly = DensePolynomial::<Fr>::rand(t as usize, &mut rng);
        Self {
            slot: slot,
            poly: rand_poly,
            g1: g1,
            g2: g2,
        }
    }

    /// Calculate secret shares for the secret polynomial
    /// The shares can then be encrypted + distributed
    /// 
    /// * n: The number of shares to calculate: {f(1), ..., f(n)}
    /// 
    pub fn calculate_shares(&self, n: u8) -> Vec<(Fr, G2)> {
        (1..n+1).map(|k| {
            // don't calculate '0'th share because that's the secret
            let secret_share = self.poly.clone().evaluate(&<Fr>::from(k));
            // calculate commitment 
            let c = self.g2.mul(secret_share);
            (secret_share, c) 
        }).collect::<Vec<_>>()
    }

    /// derive the public key based on the derived secret f(0)
    /// over both G1 and G2
    /// 
    /// `h1`: A generator for G1
    /// `h2`: A generator for G2
    /// 
    pub fn derive_pubkey(&self, h1: G1, h2: G2) -> PublicKey {
        let sk = self.secret();
        PublicKey { 
            pub_g1: h1.mul(sk), 
            pub_g2: h2.mul(sk) 
        }
    }

    /// calculate the actor's secret key
    /// it is the secret polynomial evaluated at 0
    pub fn secret(&self) -> Fr {
        self.poly.clone().evaluate(&<Fr>::from(0u64))
    }

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

/// encrypts the message to a given public key
pub fn encrypt<R: Rng + Sized>(m: &[u8;32], g1: G1, pubkey: G2, rng: &mut R) -> Ciphertext {
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
pub fn decrypt(ct: Vec<u8>, sk: G1, g2:  G2) -> Vec<u8> {
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
