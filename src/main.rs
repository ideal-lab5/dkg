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
    Zero, One, ops::{Add, Mul},
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
use sha2::Digest;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};

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
    let mpk = society.derive_pubkey(rng.clone());
    // // now we want to reconstruct the secret key and decrypt the message
    let sks = society.derive_secret_keys();
    // then the mpk and msk are on the same curve
    // encrypt
    let g1 = G1::generator();
    let g2 = G2::generator();
    let m = sha256(b"this is my secret");
    if m.len() != 32 {
        panic!("Should be 32 bits");
    }
    println!("The original message is: {:?}", m);
    let r = Fr::rand(&mut rng);
    let u = g1.mul(r);
    let vkr = Bls12_381::pairing(g1, mpk.mul(r));
    let mut v = Vec::new();
    vkr.serialize_compressed(&mut v).unwrap();
    v = sha256(&v);
    for i in 0..32 {
        v[i] ^= m[i];
    }
    let h = hash_h(u, &v);
    let w = h.mul(r);
    // the ciphertext
    let ct = (u, v.clone(), w);
    
    let shares = sks.iter().map(|sk| {
        u.mul(sk)
    }).collect::<Vec<_>>();
    // decryption
    let r = Bls12_381::pairing(shares.iter().fold(G1::zero(), |acc, x| acc.add(x)), g2);
    let mut ret = Vec::new();
    r.serialize_compressed(&mut ret).unwrap();
    ret = sha256(&ret);
    for (i, ri) in ret.iter_mut().enumerate().take(32) {
        *ri ^= v[i];
    }
    println!("ret {:?}", ret);
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
    /// each member of the society generates shares
    /// 
    /// * rng: the random number generator
    /// 
    fn dkg(&self, rng: ChaCha20Rng) {
        for p in self.participants.iter() {
            p.calculate_shares(self.shares);
        }
    }

    /// Given a group generator 'g', the public key is the product of the group generator raised to all secret keys
    /// that is, mpk = product(g^{s}) for all secrets s
    /// 
    /// `generator`: The generator to be used to calculate a public key
    ///
    fn derive_pubkey<R: Rng + Sized>(&self, mut r: R) -> G2  {
        // get a pubkey from each actor (in G2)
        let pubkeys = self.participants.iter().map(|p| {
            p.derive_pubkey()
        }).collect::<Vec<_>>();
        let mut mpk = pubkeys[0];
        // instead of adding, should we be calculating the elliptic curve pairings? 
        for i in 1..pubkeys.len() - 1 {
            mpk = mpk + pubkeys[i]
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

    // the pubkey exists in G2
    // NOTE: will need to encode other coefficients in G2 later on
    //       in order to verify them
    pub fn derive_pubkey(&self) -> G2 {
        let g2 = G2::generator();
        let sk = self.secret();
        g2.mul(sk)
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


// /// encrypts the message to a given public key
// pub fn encrypt(&self, m: &[u8]) {
//     if m.len() != 32 {
//         return Err(TPKEError::InvalidLength);
//     }
//     let mut rng = rand::thread_rng();
//     let r = Fr::rand(&mut rng);
//     let u = self.g1.mul(r);
//     let vkr = Bls12_381::pairing(self.g1, self.vk.mul(r));
//     let mut v = Vec::new();
//     vkr.serialize_compressed(&mut v).unwrap();
//     v = sha256(&v);
//     for i in 0..32 {
//         v[i] ^= m[i];
//     }
//     let h = hash_h(u, &v);
//     let w = h.mul(r);
//     // let p1 = Bls12_381::pairing(self.g1, w);
//     // let p2 = Bls12_381::pairing(u, h);
//     // assert_eq!(p1, p2);
//     // Ok(TPKECipherText { u: u, v: v, w: w })
// }

// /// decrypts a message using the provided key shares
// pub fn combine_shares(
//     &self,
//     c: &TPKECipherText,
//     shares: &HashMap<usize, G1>,
// ) -> Result<Vec<u8>, TPKEError> {
//     if !self.verify_ciphertext(c) {
//         return Err(TPKEError::InvalidCiphertext);
//     }
//     let indices: Vec<u64> = shares.keys().map(|i| (*i).try_into().unwrap()).collect();
//     for (j, share) in shares.iter() {
//         if !self.verify_share(*j, *share, c) {
//             return Err(TPKEError::InvalidShare);
//         }
//     }
//     let r = Bls12_381::pairing(
//         shares
//             .iter()
//             .map(|(k, v)| {
//                 v.mul(
//                     self.lagrange(&indices, (*k).try_into().unwrap())
//                         .unwrap(),
//                 )
//             })
//             .fold(G1::zero(), |acc, x| acc.add(x)),
//         self.g2,
//     );
//     let mut ret = Vec::new();
//     r.serialize_compressed(&mut ret).unwrap();
//     ret = sha256(&ret);
//     for (i, ri) in ret.iter_mut().enumerate().take(32) {
//         *ri ^= c.v[i];
//     }
//     Ok(ret)
// }
