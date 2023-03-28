
use std::{
    collections::HashMap,
    time::SystemTime,
    ops::Mul,
};
use ark_ec::{Group, bls12::Bls12};
use ark_ff::{MontBackend, Fp, PrimeField};
use ark_test_curves::{
    ed_on_bls12_381::{
        EdwardsConfig as Config, Projective as G, Fr as ScalarField, FrConfig as FieldConfig,
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
    let shares = society.dkg(rng);
    // ASSUME OR SIMULATE: sharing phase. This is all on one machine.
    // SKIP: DISPUTES (verify, unverify, zk snarks); For now we assume all values are valid.
    // the secret shares are the first element of each of the abov 
    let secret_shares = shares.iter().map(|x| x[0]).collect();
    // derive a public key
    let mpk = society.derive(secret_shares);
    let big_mpk: num_bigint::BigUint = mpk.to_owned().into();
    let pubkey_bytes = big_mpk.to_bytes_le();
    println!("Calculated a public key: {:?}", pubkey_bytes);
    println!("Calculated a public key w/ len: {:?}", pubkey_bytes.len());
    // encrypt something
    //share it
    // decrypt it

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
        // let g = G::generator();
        let g = ScalarField::from(2i32);
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
// // each coefficient's commitment is $g^{coefficient}$
// // so then, I can just do the product of those, generate coefficients 
// // for the new polynomial
// //
// // i.e. I'm taking $f(x) = c_0 + c_1 * x + ... + c_t x^t$
// // then commiting to them and defining new coefficients for the public verification key
// // $[g^{c_0}, g^{c_1}, ..., g^{c_n}]$
// //
// fn generate_poly_commitment(g: Projective<Config>, poly: DensePolynomial<ScalarField>) -> PublicVerificationKey {
//     let commitments: Vec<Projective<Config>> = poly.coeffs().iter().map(|c: &ScalarField| {
//         // commitment = g^c
//         // TOD
//         // We can compute the pairing of two points on the curve, either monolithically...
// // let e1 = Bls12_381::pairing(a, b);
// // // ... or in two steps. First, we compute the Miller loop...
// // let ml_result = Bls12_381::miller_loop(a, b);
// // // ... and then the final exponentiation.
// // let e2 = Bls12_381::final_exponentiation(ml_result).unwrap();
// // assert_eq!(e1, e2);
//         g.mul(c)
//     }).collect::<Vec<_>>();
//     PublicVerificationKey { coefficients: commitments }
// }


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
