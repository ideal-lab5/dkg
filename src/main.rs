use threshold_crypto::{
    G1Affine, Fr, IntoFr,
    group::CurveAffine,
    ff::Field,
    poly::{BivarPoly, Poly},
};

use std::collections::BTreeMap;

fn main() {
    distributed_key_generation(5, 3, 2);
}

// based on: https://github.com/poanetwork/threshold_crypto/blob/d81953b55d181311c2a4eed2b6c34059fcf3fdae/src/poly.rs#L967
fn distributed_key_generation(num_shares: usize, threshold: i32, tolerance: usize) {
    let mut rng = rand::thread_rng();
    println!("Starting DKG with {:?} dealers", threshold);
 
    // For distributed key generation, a number of dealers, only one of who needs to be honest,
    // generates random bivariate polynomials and publicly commits to them. In practice, the
    // dealers can e.g. be any `tolerance + 1` nodes.
    let bi_polys: Vec<BivarPoly> = (0..threshold)
        .map(|_| {
            BivarPoly::random(tolerance, &mut rng)
        })
        .collect();
    // create a commitment to the polynomial
    let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();
    // create empty vec to hold secret keys
    let mut sec_keys = vec![Fr::zero(); num_shares];

    // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
    // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
    // verify the values they received, and collect them.
    for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
        for m in 1..=num_shares {
            // Node `m` receives its row and verifies it.
            let row_poly = bi_poly.row(m);
            let row_commit = bi_commit.row(m);
            assert_eq!(row_poly.commitment(), row_commit);
            // Node `s` receives the `s`-th value and verifies it.
            for s in 1..=num_shares {
                let val = row_poly.evaluate(s);
                let val_g1 = G1Affine::one().mul(val);
                assert_eq!(bi_commit.evaluate(m, s), val_g1);
                // The node can't verify this directly, but it should have the correct value:
                assert_eq!(bi_poly.evaluate(m, s), val);                                                       
            }

            // A cheating dealer who modified the polynomial would be detected.
            let x_pow_2 =
                Poly::monomial(2);
            let five = Poly::constant(5i32.into_fr());
            let wrong_poly = row_poly.clone() + x_pow_2 * five;
            assert_ne!(wrong_poly.commitment(), row_commit);

            // If `2 * tolerance + 1` nodes confirm that they received a valid row, then at
            // least `tolerance + 1` honest ones did, and sent the correct values on to node
            // `s`. So every node received at least `tolerance + 1` correct entries of their
            // column/row (remember that the bivariate polynomial is symmetric). They can
            // reconstruct the full row and in particular value `0` (which no other node knows,
            // only the dealer). E.g. let's say nodes `1`, `2` and `4` are honest. Then node
            // `m` received three correct entries from that row:
            let received: BTreeMap<_, _> = [1, 2, 4]
                .iter()
                .map(|&i| (i, bi_poly.evaluate(m, i)))
                .collect();
            let my_row =
                Poly::interpolate(received);
            assert_eq!(bi_poly.evaluate(m, 0), my_row.evaluate(0));
            assert_eq!(row_poly, my_row);

            // The node sums up all values number `0` it received from the different dealer. No
            // dealer and no other node knows the sum in the end.
            sec_keys[m - 1].add_assign(&my_row.evaluate(Fr::zero()));
        }
    }

    // Each node now adds up all the first values of the rows it received from the different
    // dealers (excluding the dealers where fewer than `2 * tolerance + 1` nodes confirmed).
    // The whole first column never gets added up in practice, because nobody has all the
    // information. We do it anyway here; entry `0` is the secret key that is not known to
    // anyone, neither a dealer, nor a node:
    let mut sec_key_set = Poly::zero();
    for bi_poly in &bi_polys {
        sec_key_set += bi_poly
            .row(0);
    }
    for m in 1..=num_shares {
        assert_eq!(sec_key_set.evaluate(m), sec_keys[m - 1]);
    }

    // The sum of the first rows of the public commitments is the commitment to the secret key
    // set.
    let mut sum_commit = Poly::zero()
        .commitment();
    for bi_commit in &pub_bi_commits {
        sum_commit += bi_commit.row(0);
    }
    assert_eq!(sum_commit, sec_key_set.commitment());
    println!("DKG Complete!");
}