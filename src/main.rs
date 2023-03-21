
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};
use ark_ff::{Field, PrimeField};
use ark_std::{test_rng, One, UniformRand, Zero, rand::RngCore};
use ark_test_curves::{bls12_381::{Fq as F, G1_GENERATOR_X}};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};

fn main() {
    distributed_key_generation(10, 6);
}

// based on: https://github.com/poanetwork/threshold_crypto/blob/d81953b55d181311c2a4eed2b6c34059fcf3fdae/src/poly.rs#L967
fn distributed_key_generation(s: i32, t: usize) {
    // let mut rng = rand::thread_rng();
    let now = SystemTime::now();
    println!("Starting DKG with {:?} shares and {:?} threshold", s, t);
    let mut rng = test_rng();
    // get prime modulus associated with `F`
    let modulus = <F as PrimeField>::MODULUS;
    println!("The order of the field is {:?}", modulus);
    let g = G1_GENERATOR_X;
    // technically a generator 
    // let g = F::one();

    let mut dealer_secrets = HashMap::<i32, F>::new();
    let mut dealer_commitments = HashMap::<i32, DensePolynomial<F>>::new();
    // 1. The sharing phase: each dealer generates a random polynomial
    //    Then, each dealer generates shares for each of the other dealers
    //    and generates a commitment to the polynomial
    // 
    for i in 1..s  {
        let mut dealer_shares = HashMap::<i32, F>::new();
        // TODO: randomly sample t coefficients from F, with first elt as secret
        let rand_poly = DensePolynomial::<F>::rand(t, &mut rng);
        // generate a commitment to the polynomial
        let commitment = generate_poly_commitment(g, rand_poly.clone());
        // first coefficient is the secret
        let secret = rand_poly.coeffs()[0];
        dealer_secrets.insert(i, secret);
        dealer_commitments.insert(i, commitment);
        for j in 1..s {
            // evaluate the polynomial at each index except your own
            if j != i {
                // the secret share $s_{i \to j}$
                let share = rand_poly.evaluate(&F::from(j as i32));
                dealer_shares.insert(j as i32, share);
            }
        }    
    }
    // Now we will just imagine this is where the shares would be encrypted and transmitted through some network
    // beep boop ....

    // 2. The Disputes phase
    // For now, I'm skiipping this because I know all of the share are valid
    // commitments are verified here, so that's where the dealer_commitments and dealer_shares map are used

    // 3. Derive a master public key
    // for now, I'll just try doing this with the first t+1 shares
    // and use the same group generator that I used above
    // to derive this we take the sum of the generator raised to each dealer's secret 
    let pubkey_shares = dealer_secrets.iter().map(|(_, secret)| {
        generate_pubkey_share(g, *secret)
    }).collect::<Vec<_>>();
    let pubkey = generate_pubkey(pubkey_shares.as_slice());
    println!("Generated master public key: {:?}", pubkey);
    
    match now.elapsed() {
        Ok(elapsed) => {
            // it prints '2'
            println!("DKG Complete: time elapsed: {} ms", elapsed.as_millis());
        }
        Err(e) => {
            // an error occurred!
            println!("Error: {e:?}");
        }
    }

}

// // a^{p-1} != 1 => a is a generator for the group G.
// // is this actually true? I need to verify and prove this...
// fn find_generator(identity: F, modulus: F, rng: &mut RngCore) -> F {
//     let mut a = F::rand(rng);
//     if pow(a, modulus - F::one()) != identity {
//         a
//     } 
//     find_generator(identity, modulus, rng)
// }

// each coefficient's commitment is $g^{coefficient}$
// so then, I can just do the product of those, generate coefficients 
// for the new polynomial
//
// i.e. I'm taking $f(x) = c_0 + c_1 * x + ... + c_t x^t$
// then commiting to them and defining new coefficients for the public verification key
// $[g^{c_0}, g^{c_1}, ..., g^{c_n}]$
//
fn generate_poly_commitment(g: F, poly: DensePolynomial<F>) -> DensePolynomial<F> {
    let commitments = poly.coeffs().iter().map(|c: &F| {
        // convert the coefficient c to it's u64 representation, least significant bit first
        let big_c: num_bigint::BigUint = c.to_owned().into();
        let big_c_digits = big_c.to_u64_digits();
        g.pow(big_c_digits)
    }).collect::<Vec<_>>();
    DensePolynomial::<F>::from_coefficients_vec(commitments)
}

fn generate_pubkey(pubkey_shares: &[F]) -> F {
    let mut pubkey = pubkey_shares[0];

    pubkey_shares[1..].iter().for_each(|share| {
        pubkey = pow(pubkey, *share);
    });

    pubkey
}

fn generate_pubkey_share(h: F, share: F) -> F {
    pow(h, share)
}

fn pow(f: F, g: F) -> F {
    let big_g: num_bigint::BigUint = g.to_owned().into();
    let big_g_digits = big_g.to_u64_digits();
    f.pow(big_g_digits)
}
