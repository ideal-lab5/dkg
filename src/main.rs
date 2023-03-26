
use std::{
    collections::HashMap,
    time::SystemTime,
    ops::Mul,
};
use ark_ec::{Group};
use ark_ff::{MontBackend, Fp};
use ark_test_curves::{
    secp256k1::{
        Config, G1Projective as G, Fr as ScalarField,
    },
    Field, short_weierstrass::Projective
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

fn main() {
    let t = 2;
    let n = 3;
    let g = G::generator();
    let rng = ChaCha20Rng::seed_from_u64(31u64);
    // create n actors
    let actors = (1..n).map(|i| Actor{ slot: i } ).collect();
    // create a new society
    let society = Society::new(actors, n, t, g);
    // generate keys
    let shares = society.dkg(rng);
    // derive a public key
    society.derive_pubkey(g, shares);
    // encrypt something
    //share it
    // decrypt it

}

pub struct KeyShare;
pub struct Commitment;

#[derive(Clone)]
pub struct PublicVerificationKey {
    pub coefficients: Vec<Projective<Config>>,
}

impl PublicVerificationKey {
    /// evaluate the pkv at some point x
    /// $f(x) = C_0 * C_1^{x^1} * ... * C_t^{x^t}$
    pub fn evaluate(&self, x: ScalarField) -> Projective<Config> {
        let mut result = self.coefficients[0];
        for i in 1..self.coefficients.len() {
            let big_i: num_bigint::BigUint = ScalarField::from(i as i32).into();
            result = self.coefficients[i].mul(x.pow(big_i.to_u64_digits()));
        }
        result
    }
}

pub struct Society {
    // will be made blind eventually
    pub participants: Vec<Actor>,
    pub shares: u8,
    pub threshold: u8, 
    pub generator: Projective<Config>,
}

impl Society {
    fn new(participants: Vec<Actor>, shares: u8, threshold: u8, generator: Projective<Config>) -> Self {
        Self {
            participants, shares, threshold, generator,
        }
    }

    /// ultimately issue (commitment, share)
    fn dkg(&self, rng: ChaCha20Rng) -> 
            Vec<Vec<(Fp<MontBackend<ark_test_curves::secp256k1::FrConfig, 4>, 4>, ark_ec::short_weierstrass::Projective<ark_test_curves::secp256k1::Config>)>> 
        {
        let mut shares = Vec::new();
        for p in self.participants.iter() {
            // each participant generates shares
            let participant_shares = p.generate_shares(self.shares, self.threshold, rng.clone(), self.generator);
            shares.push(participant_shares);
        }   
        // ASSUME OR SIMULATE: sharing phase. This is all on one machine.
        // SKIP: DISPUTES; For now we assume all values are valid.
        shares
    }

    /// Given a group generator 'g', the public key is the product of the group generator raised to all secret keys
    /// that is, mpk = sum(g^{s}; for all secrets s)
    /// 
    /// `generator`: The generator to be used to calculate a public key
    /// 
    fn derive_pubkey(
        &self, 
        generator: Projective<Config>, 
        shares: Vec<Vec<(Fp<MontBackend<ark_test_curves::secp256k1::FrConfig, 4>, 4>, ark_ec::short_weierstrass::Projective<ark_test_curves::secp256k1::Config>)>>)  {
        // TODO
    }

}

/// a participant in the protocol
pub struct Actor {
    // todo
    pub slot: u8,
}

impl Actor {

    fn new(slot: u8) -> Self {
        Actor{ slot }
    }
    /// generates a random polynomial over the given field
    /// then calculates shares and commitments and returns them
    pub fn generate_shares<R: Rng + Sized>(&self, n: u8, t: u8, mut r: R, g: Projective<Config>) -> Vec<(Fp<MontBackend<ark_test_curves::secp256k1::FrConfig, 4>, 4>, Projective<Config>)>{
        let rand_poly = DensePolynomial::<ScalarField>::rand(t as usize, &mut r);
        let commitment_poly = generate_poly_commitment(g, rand_poly.clone());
         (0..n).map(|k| {
            let secret_share = rand_poly.clone().evaluate(&ScalarField::from(k));
            let commitment = commitment_poly.clone().evaluate(ScalarField::from(k));
            (secret_share, commitment)
        }).collect::<Vec<_>>()
    }
}
// each coefficient's commitment is $g^{coefficient}$
// so then, I can just do the product of those, generate coefficients 
// for the new polynomial
//
// i.e. I'm taking $f(x) = c_0 + c_1 * x + ... + c_t x^t$
// then commiting to them and defining new coefficients for the public verification key
// $[g^{c_0}, g^{c_1}, ..., g^{c_n}]$
//
fn generate_poly_commitment(g: Projective<Config>, poly: DensePolynomial<ScalarField>) -> PublicVerificationKey {
    let commitments: Vec<Projective<Config>> = poly.coeffs().iter().map(|c: &ScalarField| {
        // commitment = g^c
        g.mul(c)
    }).collect::<Vec<_>>();
    PublicVerificationKey { coefficients: commitments }
}


// /// perform DKG with s shares and t threshold
// fn distributed_key_generation(s: i32, t: usize) {
//     // let mut rng = rand::thread_rng();
//     let now = SystemTime::now();
//     println!("Starting DKG with {:?} shares and {:?} threshold", s, t);
//     let mut rng = test_rng();
    
//     // we need to get a generator of the group G
//     let generator = G::generator();
//     let mut dealer_secret_poly: Vec<DensePolynomial<ScalarField>> = Vec::new();
//     let mut dealer_pvps: Vec<PublicVerificationKey> = Vec::new();
//     // this maps the share that dealers receive from other dealers
//     // i.e. if i makes a share for j, s_{i \to j}, then this is in the map as:
//     // j -> {i, s_{t \to j}}
//     let mut dealer_shares: HashMap<i32, (i32, ScalarField)> = HashMap::new();
//     //  1. SHARING PHASE: each dealer generates a random polynomial f(x) and distributes shares publicly
//     for i in 0..s {
//         // generate t degree random poly over the scalar field
//         let rand_poly = DensePolynomial::<ScalarField>::rand(t, &mut rng);
//         let dealer_pvp = generate_poly_commitment(generator, rand_poly.clone());
//         dealer_secret_poly.push(rand_poly.clone());
//         dealer_pvps.push(dealer_pvp);
//         for j in 1..s {
//             // create shares
//             let share_i_j = rand_poly.clone().evaluate(&ScalarField::from(j));
//             dealer_shares.insert(j, (i, share_i_j));
//         }
//     }

//     // Assume that through some mechanism, the shares are distributed to where they need to be
//     // since we're assuming all shares are valid, we won't try to verify any shares right now
    
//     // println!("Created dealer secret polys: {:?}", dealer_secret_poly);
//     // println!("Created dealer secret shares: {:?}", dealer_shares);
//     // let f = dealer_pvps[0].clone();
//     // let evaluation = f.evaluate(ScalarField::from(1));
//     // println!("Evaluated the public verification poly: f({:?}) = {:?}", 1, evaluation);

//     let pubkey_shares: Vec<Projective<Config>> = dealer_secret_poly.iter().map(|f| {
//         let secret = f.coeffs()[0];
//         // for each share, calculate a public key
//         // this probably isn't right
//         let pubkey_share = generator.mul(secret); // but that's just scalar multiplication, not what I want
//         pubkey_share
//     }).collect();
//     // now just multiply them all together
//     let mut mpk = pubkey_shares[0].clone();
//     // we'll just assume every share is valid
//     for i in 1..s {
//         let pk = pubkey_shares[i as usize];
//         // okay so I want to multiply them..not add..
//         mpk = pk + mpk;
//     }

//     println!("Calculated group mpk: {:?}", mpk);
    
//     match now.elapsed() {
//         Ok(elapsed) => {
//             println!("DKG Complete: time elapsed: {} ms", elapsed.as_millis());
//         }
//         Err(e) => {
//             println!("Error: {e:?}");
//         }
//     }
// }
