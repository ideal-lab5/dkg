use ark_ec::{
    AffineRepr, Group, CurveGroup,
    pairing::Pairing,
};
use ark_ff::{Field, PrimeField, UniformRand, FftField, Fp256, MontBackend, BigInteger, FpConfig};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use ark_std::{
    Zero, One, ops::{Add, Div, Mul, Sub},
    rand::Rng,
    marker::PhantomData,
};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};
use ark_crypto_primitives::encryption::{
    AsymmetricEncryptionScheme, 
    elgamal::{
        ElGamal, 
        Randomness,
        SecretKey,
    }
};
use std::cmp::Ordering;
use sha2::Digest;

use ark_bls12_381::{
    Bls12_381, Fr, G1Affine, 
    G1Projective as G1, G2Affine, 
    G2Projective as G2
};

pub struct PublicKey {
    pub pub_g1: G1,
    pub pub_g2: G2,
}

pub struct Ciphertext {
    pub u: G1,
    pub v: Vec<u8>, // the 'ciphertext'
    pub w: G2,

}

/// A distributed key gen experiment over BLS12-381
fn main() {
    let t = 2;
    let n = 3;
    let mut rng = ChaCha20Rng::seed_from_u64(23u64);
    // create n actors with threshold of t
    let actors: Vec<Actor> = (1..n).map(|i| {
        Actor::new(i, t, rng.clone())
    }).collect::<Vec<_>>();
    // create a new society (each member already has a secret poly)
    let society = Society::new(actors, n, t);
    society.dkg(rng.clone());
    // TODO disputes + verification
    let r1 = Fr::rand(&mut rng.clone());
    let r2 = Fr::rand(&mut rng.clone());
    let h1 = G1::generator().mul(r1); 
    let h2 = G2::generator().mul(r2);
    let mpk = society.derive_pubkey(h1, h2, &mut rng.clone());
    // // now we want to reconstruct the secret key and decrypt the message
    let sks = society.derive_secret_keys();
    let mut msk = sks[0].clone();
    for i in (1..sks.len()-1) {
        msk = msk + sks[i].clone();
    }
    let message_digest = sha256(b"Hello, world");
    let m = slice_to_array_32(&message_digest).unwrap();
    println!("message bytes: {:?}", m);
    // let g1 = G1::generator();
    let ciphertext = encrypt(m, h1, mpk, &mut rng);
    let recovery_shares: Vec<G1> = sks.iter().map(|sk| ciphertext.u.mul(sk)).collect::<Vec<_>>();
    let recovered_message = decrypt(&ciphertext, ciphertext.u.mul(msk), h2);
    println!("Recovered Message: {:?}", recovered_message);
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
    fn dkg(&self, rng: ChaCha20Rng) {
        for p in self.participants.iter() {
            p.calculate_shares(self.shares);
        }
    }

    /// combine pubkeys to get a group public key
    /// 
    /// `generator`: The generator to be used to calculate a public key
    ///
    fn derive_pubkey<R: Rng + Sized>(&self, h1: G1, h2: G2, r: &mut R) -> G2  {
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
/// a participant in the protocol
/// for now we assume that each participant can only 
/// participate in a single society
pub struct Actor {
    pub slot: u8,
    // TODO: should this be over Fq or Fr?
    pub poly: DensePolynomial<Fr>,

}

/// implementation of an actor
/// a member of the society who can participate in the DKG
impl Actor {
    /// create a new actor with a threshold value and a random polynomial with degree = threshold
    /// over the given scalar field
    /// 
    /// * `t`: the thresold value to set. This will be the 'threshold' in the TSS scheme
    /// * `r`: The random number generator used to generate the polynomial
    /// 
    pub fn new<R: Rng + Sized>(slot: u8, t: u8, mut rng: R) -> Actor {
        // generate secret and coefficients
        // let a = vec![<G::ScalarField>::rand(&mut rng); t.try_into().unwrap()];
        let rand_poly = DensePolynomial::<Fr>::rand(t as usize, &mut rng);
        Self {
            slot: slot, poly: rand_poly
        }
    }

    /// Calculate secret shares for the actor's polynomial
    /// The shares can then be distributed as per a VSS scheme
    /// 
    /// * n: The number of shares to calculate: {f(1), ..., f(n)}
    /// 
    pub fn calculate_shares(&self, n: u8) -> Vec<Fr> {
        (1..n).map(|k| {
            self.poly.clone().evaluate(&<Fr>::from(k))
        }).collect::<Vec<_>>()
    }

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

// fn hash_to_g1(b: &[u8]) -> G1Affine {
//     let mut nonce = 0u32;
//     loop {
//         let c = [b"cryptex-domain-g1", b, b"cryptex-sep", &nonce.to_be_bytes()].concat();
//         match G1Affine::from_random_bytes(&sha256(&c)) {
//             Some(v) => {
//                 // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
//                 return v.mul_by_cofactor_to_group().into_affine();
//             }
//             None => nonce += 1,
//         }
//     }
// }

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

// / decrypts a message using the provided key shares
pub fn decrypt(ct: &Ciphertext, sk: G1, g2:  G2) -> Vec<u8> {
    let r = Bls12_381::pairing(sk, g2);
    let mut ret = Vec::new();
    r.serialize_compressed(&mut ret).unwrap();
    ret = sha256(&ret);
    // decode the message
    for (i, ri) in ret.iter_mut().enumerate().take(32) {
        *ri ^= ct.v[i];
    }
    ret
}
