use ark_ec::Group;
use ark_ff::{MontBackend, Fp};
use ark_test_curves::{
    ed_on_bls12_381::{
        Projective as G, Fr as ScalarField, FrConfig as FieldConfig,
    },
    Field,
};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_std::rand::Rng;
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};
// use x25519_dalek::{PublicKey, EphemeralSecret};
use crypto_box::{
    aead::{Aead, AeadCore},
    SalsaBox, PublicKey, SecretKey
};

/// In the first go through, we make some assumptions that make things really simple
/// First, we assume that each 'actor' or participant can only have one secret share at a time (i.e. can only participate in one society)
/// And we also assume that all society communication/network broadcasts are atomic
fn main() {
    let t = 2;
    let n = 3;
    let rng = ChaCha20Rng::seed_from_u64(29u64);
    // create n actors
    let actors = (1..n).map(|i| Actor{ slot: i, share: None } ).collect();
    // create a new society
    let society = Society::new(actors, n, t);
    // generate keys
    let shares = society.dkg(rng.clone());
    // ASSUME OR SIMULATE: sharing phase. This is all on one machine.
    // SKIP: DISPUTES (verify, unverify, zk snarks); For now we assume all values are valid.
    // the secret shares are the first element of each of the abov 
    let secret_shares = shares.iter().map(|x| x[0]).collect::<Vec<_>>();
    // derive a public key
    let mpk = society.derive(secret_shares.clone());
    let big_mpk: num_bigint::BigUint = mpk.to_owned().into();
    let pubkey_bytes = big_mpk.to_bytes_le();
    // convert to [u8;32]
    let ptr = pubkey_bytes.as_ptr() as *const [u8; 32];
    // let's encrypt something!
    let pubkey = PublicKey::from(*unsafe { &*ptr });
    println!("Original pubkey: {:?}", pubkey);
    // let pubkey = PublicKey::from(pubkey_bytes.as_slice());
    let alice_secret_key = SecretKey::generate(&mut rng.clone());
    let alice_public_key = alice_secret_key.public_key();
    let alice_box = SalsaBox::new(&pubkey, &alice_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut rng.clone());
    let plaintext = b"Hello, world!";
    let ciphertext = alice_box.encrypt(&nonce, &plaintext[..]).map_err(|e| {
        println!("Failed to encrypt the message: {:?}", e);
    }).unwrap();
    // now let's say alice forgets her key somehow, well, she can still recover the encrypted text by 
    // getting shares from the society
    let (alice_shares, _) = secret_shares.split_at(t as usize);
    // now use those shares to reconstruct the polynomial, evaluate it at f(0)
    let reconstructed_poly = DensePolynomial::<ScalarField>::from_coefficients_slice(alice_shares);
    let secret = reconstructed_poly.evaluate(&ScalarField::from(0));
    let big_secret: num_bigint::BigUint = secret.to_owned().into();
    let secret_bytes = big_secret.to_bytes_le();
    let ptr_sk = secret_bytes.as_ptr() as *const [u8; 32];
    let reconstructed_secret_key = SecretKey::from(* unsafe { &*ptr_sk });
    let rpk = reconstructed_secret_key.public_key();
    println!("rsk: {:?}", secret_bytes);
    println!("rpk: {:?}", rpk);
    // decrypt it
    let recovery_box = SalsaBox::new(&alice_public_key, &reconstructed_secret_key);
    match recovery_box.decrypt(&nonce, &ciphertext[..]) {
        Ok(message) => {
            println!("The message is: {:?}", message);
        },
        Err(e) => {
            println!("Decryption failed: {:?}", e);
        }
    }
    // println!("And did it work? {:?}", recovered_text);
}

pub struct Society {
    // will be made blind eventually
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
    fn dkg(&self, rng: ChaCha20Rng) -> Vec<Vec<ScalarField>> {
        let mut shares = Vec::new();
        for p in self.participants.iter() {
            // each participant generates shares
            let (_, participant_shares) = 
                p.generate_shares(self.shares, self.threshold, rng.clone());
            shares.push(participant_shares);
        }
        shares
    }

    /// Given a group generator 'g', the public key is the product of the group generator raised to all secret keys
    /// that is, mpk = product(g^{s}) for all secrets s
    /// 
    /// `generator`: The generator to be used to calculate a public key
    ///
    fn derive(&self, shares: Vec<Fp<MontBackend<FieldConfig, 4>, 4>>) -> ScalarField  {
        // let modulus = <ScalarField as PrimeField>::MODULUS;
        let gen = G::generator();
        // ScalarField::from(gen.to_owned().into());
        let g = ScalarField::from(2u32);
        // should be 'actor' based instead of iterating over the shares, we should iterate over actors
        // then each actor can derive a pubkey independently. 
        let public_key_shares = shares.iter().map(|share| {
            let big_share: num_bigint::BigUint = share.to_owned().into();
            g.pow(big_share.to_u64_digits())
        }).collect::<Vec<_>>();
        let mut mpk = public_key_shares[0];
        for i in 1..shares.len() {
            mpk = mpk * shares[i];
        }
        ScalarField::from(mpk)
    }

    fn reencrypt() {
        todo!("Not yet implemented");
    }

}


/// a participant in the protocol
pub struct Actor {
    // todo
    pub slot: u8,
    pub share: Option<ScalarField>,
}

impl Actor {
    /// generates a random polynomial over the given field, then calculates shares
    pub fn generate_shares<R: Rng + Sized>(&self, n: u8, t: u8, mut r: R) 
        -> (DensePolynomial<ScalarField>, Vec<Fp<MontBackend<FieldConfig, 4>, 4>>) {
        let rand_poly = DensePolynomial::<ScalarField>::rand(t as usize, &mut r);
        let shares = (0..n).map(|k| {
            rand_poly.clone().evaluate(&ScalarField::from(k))
        }).collect::<Vec<_>>();
        (rand_poly, shares)
    }

    pub fn derive_pubkey(g: ScalarField) {

    }

}
