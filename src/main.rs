
use std::{
    collections::HashMap,
    time::SystemTime,
    ops::Mul,
};
use ark_ec::{Group};
// We'll use the BLS12-381 G1 curve for this example.
// This group has a prime order `r`, and is associated with a prime field `Fr`.
use ark_test_curves::{
    bls12_381::{
        g2::Config, G2Projective as G, Fr as ScalarField
    },
    Field, short_weierstrass::Projective
};
use ark_std::test_rng;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};

fn main() {
    distributed_key_generation(3, 2);
}
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

fn distributed_key_generation(s: i32, t: usize) {
    // let mut rng = rand::thread_rng();
    let now = SystemTime::now();
    println!("Starting DKG with {:?} shares and {:?} threshold", s, t);
    let mut rng = test_rng();
    
    // we need to get a generator of the group G
    let generator = G::generator();
    let mut dealer_secret_poly: Vec<DensePolynomial<ScalarField>> = Vec::new();
    let mut dealer_pvps: Vec<PublicVerificationKey> = Vec::new();
    // this maps the share that dealers receive from other dealers
    // i.e. if i makes a share for j, s_{i \to j}, then this is in the map as:
    // j -> {i, s_{t \to j}}
    let mut dealer_shares: HashMap<i32, (i32, ScalarField)> = HashMap::new();
    // each dealer
    for i in 0..s {
        // generate t degree random poly over the scalar field
        let rand_poly = DensePolynomial::<ScalarField>::rand(t, &mut rng);
        let dealer_pvp = generate_poly_commitment(generator, rand_poly.clone());
        dealer_secret_poly.push(rand_poly.clone());
        dealer_pvps.push(dealer_pvp);
        
        for j in 1..s {
            // create shares
            let share_i_j = rand_poly.clone().evaluate(&ScalarField::from(j));
            dealer_shares.insert(j, (i, share_i_j));
        }
    }
    
    // println!("Created dealer secret polys: {:?}", dealer_secret_poly);
    // println!("Created dealer secret shares: {:?}", dealer_shares);
    // let f = dealer_pvps[0].clone();
    // let evaluation = f.evaluate(ScalarField::from(1));
    // println!("Evaluated the public verification poly: f({:?}) = {:?}", 1, evaluation);

    let pubkey_shares: Vec<Projective<Config>> = dealer_secret_poly.iter().map(|f| {
        let secret = f.coeffs()[0];
        // for each share, calculate a public key
        // this probably isn't right
        let pubkey_share = generator.mul(secret); // but that's just scalar multiplication, not what I want
        pubkey_share
    }).collect();
    println!("num secrets recovered: {:?}", pubkey_shares.len());
    // now just multiply them all together
    let mut mpk = pubkey_shares[0].clone();
    // we'll just assume every share is valid
    for i in 1..s {
        let pk = pubkey_shares[i as usize];
        // okay so I want to multiply them..not add..
        mpk = pk + mpk;
    }

    println!("Calculated group mpk: {:?}", mpk);
    
    match now.elapsed() {
        Ok(elapsed) => {
            println!("DKG Complete: time elapsed: {} ms", elapsed.as_millis());
        }
        Err(e) => {
            println!("Error: {e:?}");
        }
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
fn generate_poly_commitment(g: Projective<Config>, poly: DensePolynomial<ScalarField>) 
    -> PublicVerificationKey {
    let commitments: Vec<Projective<Config>> = poly.coeffs().iter().map(|c: &ScalarField| {
        // commitment = g^c
        g.mul(c)
    }).collect::<Vec<_>>();
    PublicVerificationKey { coefficients: commitments }
}
