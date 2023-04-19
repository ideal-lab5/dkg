use ark_bls12_381::{
    G1Projective as G1,
    G2Projective as G2
};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

/// Represents a public key in both G1 and G2
// // #[derive(Serialize)]
#[derive(Clone)]
pub struct PublicKey {
    pub g1: G1,
    pub g2: G2,
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
