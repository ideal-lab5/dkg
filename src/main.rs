use ark_ec::{Group, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand, FftField, Fp256, MontBackend, BigInteger, FpConfig};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use num_bigint::BigUint;
use ark_std::rand::Rng;
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

pub type G = ark_ed_on_bls12_377::EdwardsProjective;
pub type ScalarField = <G as Group>::ScalarField;

/// In the first go through, we make some assumptions that make things really simple
/// First, we assume that each 'actor' or participant can only have one secret share at a time (i.e. can only participate in one society)
/// And we also assume that all society communication/network broadcasts are atomic
fn main() {
    let t = 2;
    let n = 3;
    let mut rng = ChaCha20Rng::seed_from_u64(23u64);
    // create n actors
    let actors: Vec<Actor<ScalarField>> = (1..n).map(|i| Actor::<ScalarField>::new(i, t, rng.clone())).collect::<Vec<_>>();
    // create a new society (here, each member already has a secret poly)
    let society = Society::new(actors, n, t);
    // generate keys
    society.dkg(rng.clone());
    let mpk = society.derive_pubkey(rng.clone());
    println!("pubkey: {:?}", mpk.to_string());

    // now we want to reconstruct the secret key
    let msk = society.derive_secret_key();
    println!("secret key : {:?}", msk.to_string());

    // now verify: is <mpk, msk> a valid point on the curve? should be
    
} 

pub struct Society<F: Field> {
    // will be made blind eventually
    pub participants: Vec<Actor<F>>,
    pub shares: u8,
    pub threshold: u8,
}

/// A society is a collection of participants that can generate shares amongst themselves,
/// derive a pubkey, and reencrypt a secret
impl<F: Field + PrimeField> Society<F> {
    fn new(participants: Vec<Actor<F>>, shares: u8, threshold: u8) -> Self {
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
    fn derive_pubkey<R: Rng + Sized>(&self, mut r: R) -> F  {
        let g = F::rand(&mut r);
        let public_key_shares = self.participants.iter().map(|p| {
            p.derive_pubkey_scalar_field(g)
        }).collect::<Vec<_>>();
        let mut mpk: F = public_key_shares[0];
        for i in 1..public_key_shares.len() {
            mpk = mpk * public_key_shares[i];
        }
        mpk
    }

    fn derive_secret_key(&self) -> F {
        let secret_shares = self.participants.iter().map(|p| {
            p.secret()
        }).collect::<Vec<_>>();
        secret_shares.iter().fold(F::from(0u64), |total ,curr| {
            total + curr
        })
    }

    // fn reencrypt() {
    //     todo!("Not yet implemented");
    // }

}

#[derive(Clone)]
/// a participant in the protocol
/// for now we assume that each participant can only 
/// participate in a single society
pub struct Actor<F: Field> {
    pub slot: u8,
    pub poly: DensePolynomial<F>,
}

/// implementation of an actor
/// a member of the society who should 
/// participate in the DKG
impl<F: Field + PrimeField> Actor<F> {

    /// instantiates a new actor with a threshold value and a random polynomial with degree = threshold
    /// 
    /// * `t`: the thresold value to set. This will be the 'threshold' in the TSS scheme
    /// * `r`: The random number generator used to generate the polynomial
    /// 
    pub fn new<R: Rng + Sized>(slot: u8, t: u8, mut r: R) -> Actor<F> {
        let rand_poly = DensePolynomial::<F>::rand(t as usize, &mut r);
        Self {
            slot: slot, poly: rand_poly
        }
    }

    /// Calculate shares for the actor's polynomial
    /// 
    /// * n: calculate {f(1), ..., f(n)}
    /// 
    pub fn calculate_shares(&self, n: u8) -> Vec<F> {
        (1..n).map(|k| {
            self.poly.clone().evaluate(&F::from(k))
        }).collect::<Vec<_>>()
    }

    /// Given a group generator g for the multiplicative group over a finite field (ScalarField),
    /// calculate g^s to get a public key share
    /// 
    /// * g: the generator
    ///
    pub fn derive_pubkey_scalar_field(&self, g: F) -> F {
        let secret = self.poly.clone().evaluate(&F::from(0u64));
        // let big_secret: BigUint = secret.to_owned().into();
        let big_secret: BigUint = secret.into_bigint().into();
        g.pow(big_secret.to_u64_digits())
    }

    pub fn secret(&self) -> F {
        self.poly.clone().evaluate(&F::from(0u64))
    }

}
