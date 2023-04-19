//!
//! 
//! 
//!

#[cfg(test)]
mod test;

pub mod dkg {

    use ark_ec::{
        AffineRepr, CurveGroup,
        pairing::Pairing,
    };
    use ark_ff::UniformRand;
    use ark_poly::{
        polynomial::univariate::DensePolynomial,
        DenseUVPolynomial, Polynomial,
    };
    use ark_serialize::CanonicalSerialize;
    use ark_std::{
        ops::Mul,
        rand::Rng,
    };
    use sha2::Digest;
    
    use ark_bls12_381::{
        Bls12_381, Fr,
        G1Projective as G1, G2Affine, 
        G2Projective as G2
    };
    
    // use serde::{
    //     Serialize, Deserialize, 
    //     ser::{ Serializer, SerializeStruct },
    //     de::{ Deserializer }
    // };
    // use wasm_bindgen::prelude::*;
    
    use ark_std::vec::Vec;

    // #[derive(Serialize, Deserialize)]
    // pub struct Share {
    //     pub share: Vec<u8>,
    //     pub commitment: Vec<u8>,
    // }

    // // #[wasm_bindgen]
    // #[derive(Serialize, Deserialize, Clone, Debug)]
    // pub struct SerializablePublicKey {
    //     /// the public key in G1
    //     pub g1: Vec<u8>,
    //     /// the public key in G2
    //     pub g2: Vec<u8>,
    // }

    // /// Represents the ciphertext
    // #[derive(Serialize, Deserialize, Debug)]
    // pub struct SerializableCiphertext {
    //     /// the recovery key
    //     pub u: Vec<u8>,
    //     /// the ciphered message
    //     pub v: Vec<u8>,
    //     /// the verification key
    //     pub w: Vec<u8>,
    // }

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

    /// a serializable wrapper to represent polynomial coefficiants in the field Fr
    /// when serialized, this struct represents coefficients as big endian byte arrays 
    #[derive(Clone, Debug)]
    pub struct BEPoly {
        pub coeffs: Vec<Fr>,
    }

    // impl BEPoly {
    //     fn new(dense_poly: DensePolynomial<Fr>) -> BEPoly {
    //         BEPoly {
    //             coeffs: dense_poly.coeffs().to_vec(),
    //         }
    //     }
    // }

    // impl Serialize for BEPoly {
    //     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    //     where
    //         S: Serializer,
    //     {
    //         let mut state = serializer.serialize_struct("BEPoly", 1)?;
    //         // each coefficient as big endian
    //         let be_coeffs = self.coeffs.clone().into_iter().map(|c| {
    //             let big_c: num_bigint::BigUint = Fr::into(c);
    //             big_c.to_bytes_be()
    //         }).collect::<Vec<_>>();
    //         state.serialize_field("coeffs", &be_coeffs)?;
    //         state.end()
    //     }
    // }

    // impl<'de> Deserialize<'de> for BEPoly {
    //     fn deserialize<D>(deserializer: D) -> Result<BEPoly, D::Error>
    //         where D: Deserializer<'de>
    //     {
    //         let input: Vec<Vec<u8>> = Deserialize::deserialize(deserializer)?;
    //         let coeffs: Vec<Fr> = input.into_iter().map(|i| {
    //             let big_c = num_bigint::BigUint::from_bytes_be(&i);
    //             Fr::from(big_c)
    //         }).collect::<Vec<_>>();
    //         Ok(BEPoly {
    //             coeffs: coeffs,
    //         })
    //     }
    // }

    // #[wasm_bindgen]
    // pub fn w_keygen(seed: u64, threshold: u8) -> Result<JsValue, serde_wasm_bindgen::Error> {
    //     serde_wasm_bindgen::to_value(&s_keygen(seed, threshold))
    // }

    // #[wasm_bindgen]
    // pub fn w_calculate_secret(be_poly: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
    //     let be_poly: BEPoly = serde_wasm_bindgen::from_value(be_poly)?;
    //     serde_wasm_bindgen::to_value(&s_calculate_secret(be_poly))
    // }

    // #[wasm_bindgen]
    // pub fn w_calculate_pubkey(
    //     r1: u64, 
    //     r2: u64, 
    //     secret: JsValue
    // ) -> Result<JsValue, serde_wasm_bindgen::Error> {
    //     // the secret key is encoded as big endian
    //     let sk_be : Vec<u8> = serde_wasm_bindgen::from_value(secret)?;
    //     let pk = s_calculate_pubkey(r1, r2, sk_be);
    //     serde_wasm_bindgen::to_value(&pk)
    // }

    // // #[wasm_bindgen]
    // // pub fn w_verify_pubkey(pubkey_bytes: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // //     let pk = serde_wasm_bindgen::from_value(pubkey_bytes)?;

    // // }

    // #[wasm_bindgen]
    // pub fn w_calculate_shares(
    //     n: u8, 
    //     coeffs_blob: JsValue
    // ) -> Result<JsValue, serde_wasm_bindgen::Error> {
    //     let poly: BEPoly = serde_wasm_bindgen::from_value(coeffs_blob)?;
    //     Ok(calculate_shares(n, poly.coeffs))
    // }

    // #[wasm_bindgen]
    // pub fn w_combine_pubkeys(
    //     pk1: JsValue, 
    //     pk2: JsValue
    // ) -> Result<JsValue, serde_wasm_bindgen::Error> {
    //     let w_pk1: SerializablePublicKey = 
    //         serde_wasm_bindgen::from_value(pk1).unwrap();
    //     let w_pk2: SerializablePublicKey = 
    //         serde_wasm_bindgen::from_value(pk2).unwrap();
    //     let combined_pk = s_combine_pubkeys(w_pk1, w_pk2);
    //     serde_wasm_bindgen::to_value(&combined_pk)
    // }

    // #[wasm_bindgen]
    // pub fn w_combine_secrets(s1: Vec<u8>, s2: Vec<u8>) -> Vec<u8> {
    //     s_combine_secrets(s1, s2)
    // }

    // #[wasm_bindgen]
    // pub fn w_encrypt(
    //     seed: u64, 
    //     r1: u64, 
    //     msg: Vec<u8>, 
    //     pk: JsValue
    // ) -> Result<JsValue, serde_wasm_bindgen::Error> {
    //     let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk)?;
    //     serde_wasm_bindgen::to_value(&s_encrypt(seed, r1, msg, wpk))
    // }

    // #[wasm_bindgen]
    // pub fn w_threshold_decrypt(
    //     r2: u64, 
    //     ciphertext_blob: JsValue, 
    //     sk: Vec<u8>
    // ) -> Vec<u8> {
    //     let ciphertext: SerializableCiphertext = 
    //         serde_wasm_bindgen::from_value(ciphertext_blob).unwrap();
    //     threshold_decrypt(r2, ciphertext, sk)
    // }

    // pub fn s_keygen(seed: u64, threshold: u8) -> BEPoly {
    //     let rng = ChaCha20Rng::seed_from_u64(seed);
    //     let poly = keygen(threshold as usize, rng);
    //     BEPoly::new(poly)
    // }

    // pub fn s_calculate_secret(be_poly: BEPoly) -> Vec<u8> {
    //     let f = DensePolynomial::<Fr>::from_coefficients_vec(be_poly.coeffs);
    //     let secret: Fr = calculate_secret(f);
    //     let big_secret: num_bigint::BigUint = secret.into();
    //     big_secret.to_bytes_be()
    // }

    // pub fn calculate_shares(n: u8, coeffs: Vec<Fr>) -> JsValue {
    //     let h2 = G2::generator();
    //     let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    //     let shares: Vec<(Fr, G2)> = do_calculate_shares(n, h2, f);
    //     let serializable_shares: Vec<Share> = shares.iter().map(|(s, c)| {
    //         let big_s: num_bigint::BigUint = Fr::into(*s);
    //         let bytes_be_s = big_s.to_bytes_be();
    //         // TODO: get proper vec size, that one is way too big
    //         let mut commitments_bytes = Vec::with_capacity(1000);
    //         c.serialize_compressed(&mut commitments_bytes).unwrap();
    //         Share {
    //             share: bytes_be_s, 
    //             commitment: commitments_bytes,
    //         }
    //     }).collect::<Vec<_>>();

    //     // bincode::serialize(&serializable_shares).unwrap()
    //     serde_wasm_bindgen::to_value(&serializable_shares).unwrap()
    // }

    // /// calculate the public key in G1 and G2 for a given secret
    // /// the secret should be encoded as big endian
    // pub fn s_calculate_pubkey(r1: u64, r2: u64, secret_be: Vec<u8>) -> SerializablePublicKey {
    //     // try recover secret
    //     let big_secret: num_bigint::BigUint = num_bigint::BigUint::from_bytes_be(&secret_be);
    //     let sk = Fr::from(big_secret);
    //     let h1 = G1::generator().mul(Fr::from(r1)); 
    //     let h2 = G2::generator().mul(Fr::from(r2));
    //     let pubkey = calculate_pubkey(h1, h2, sk);
    //     // could make bytes the size of both key
    //     // then when deserializing, just make sure I use the right number of bytes for each key
    //     let mut bytes_1 = Vec::with_capacity(1000);
    //     pubkey.g1.serialize_compressed(&mut bytes_1).unwrap();

    //     let mut bytes_2 = Vec::with_capacity(1000);
    //     pubkey.g2.serialize_compressed(&mut bytes_2).unwrap();
        
    //     SerializablePublicKey {
    //         g1: bytes_1,
    //         g2: bytes_2,
    //     }
    // }

    // /// will give the master pubkey in G2 only
    // pub fn s_combine_pubkeys(pk1: SerializablePublicKey, pk2: SerializablePublicKey) -> SerializablePublicKey {
    //     let pubkey1 = PublicKey {
    //         g1: G1::deserialize_compressed(&pk1.g1[..]).unwrap(),
    //         g2: G2::deserialize_compressed(&pk1.g2[..]).unwrap(),
    //     };

    //     let pubkey2 = PublicKey {
    //         g1: G1::deserialize_compressed(&pk2.g1[..]).unwrap(),
    //         g2: G2::deserialize_compressed(&pk2.g2[..]).unwrap(),
    //     };

    //     let sum = combine_pubkeys(pubkey1, pubkey2);

    //     let mut g1_bytes = Vec::with_capacity(1000);
    //     sum.g1.serialize_compressed(&mut g1_bytes).unwrap();

    //     let mut g2_bytes = Vec::with_capacity(1000);
    //     sum.g2.serialize_compressed(&mut g2_bytes).unwrap();
    //     SerializablePublicKey {
    //         g1: g1_bytes,
    //         g2: g2_bytes,
    //     }
    // }

    // pub fn s_combine_secrets(s1: Vec<u8>, s2: Vec<u8>) -> Vec<u8> {
    //     // each secret is encoded as big endian
    //     let big_s1 = num_bigint::BigUint::from_bytes_be(&s1);
    //     let big_s2 = num_bigint::BigUint::from_bytes_be(&s2);
    //     // // convert both to field elements
    //     let x1 = Fr::from(big_s1);
    //     let x2 = Fr::from(big_s2);
    //     let x = combine_secrets(x1, x2);
    //     let big_x: num_bigint::BigUint = x.into();
    //     big_x.to_bytes_be()
    // }

    // pub fn s_encrypt(seed: u64, r1: u64, msg: Vec<u8>, pk: SerializablePublicKey) -> SerializableCiphertext {
    //     let mut rng = ChaCha20Rng::seed_from_u64(seed);
    //     let h1 = G1::generator().mul(Fr::from(r1));
    //     // let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk).unwrap();
    //     let gpk = G2::deserialize_compressed(&pk.g2[..]).unwrap();
    //     let m = slice_to_array_32(&msg).unwrap();
    //     let out = encrypt(m, h1, gpk, &mut rng);
    //     let mut u_bytes = Vec::with_capacity(1000);
    //     let mut v_bytes = Vec::with_capacity(1000);
    //     out.u.serialize_compressed(&mut u_bytes).unwrap();
    //     out.v.serialize_compressed(&mut v_bytes).unwrap();
    //     SerializableCiphertext{
    //         u: u_bytes,
    //         v: out.v,
    //         w: v_bytes,
    //     }
    // }

    // /// sk is encoded as big endian
    // pub fn threshold_decrypt(r2: u64, ciphertext: SerializableCiphertext, sk: Vec<u8>) -> Vec<u8> {
    //     let h2 = G2::generator().mul(Fr::from(r2));
    //     let big_sk = num_bigint::BigUint::from_bytes_be(&sk);
    //     let x = Fr::from(big_sk);
    //     // convert c.u to group element
    //     let u = G1::deserialize_compressed(&ciphertext.u[..]).unwrap();
    //     let decryption_key = u.mul(x);
    //     let recovered_message = decrypt(ciphertext.v, decryption_key, h2);
    //     recovered_message.to_vec()
    // }

    /*
        TODO: put into new file?
    */

    /// generate a new random polynomial over the field Fr
    pub fn keygen<R: Rng + Sized>(t: usize, mut rng: R) -> DensePolynomial<Fr> {
        DensePolynomial::<Fr>::rand(t as usize, &mut rng)
    }

    /// calculate the polynomial evaluated at 0
    pub fn calculate_secret(f: DensePolynomial<Fr>) -> Fr {
        f.clone().evaluate(&<Fr>::from(0u64))
    }

    /// calculate the public key in G1 and G2
    /// 
    /// * `h1`: A generator of G1
    /// * `h2`: A generator of G2
    /// * `sk`: A secret key in the field Fr
    /// 
    pub fn calculate_pubkey(h1: G1, h2: G2, sk: Fr) -> PublicKey {
        PublicKey {
            g1: h1.mul(sk),
            g2: h2.mul(sk),
        }
    }

    /// calculate shares and commitments {(f(i), g2^f(i))} for i in [n]
    ///
    /// * `n`: The number of shares to calculate
    /// * `g2`: A generator of G2 (progective)
    /// * `poly`: A polynomial over Fr
    /// 
    pub fn do_calculate_shares(n: u8, g2: G2, poly: DensePolynomial<Fr>) -> Vec<(Fr, G2)> {
        (1..n+1).map(|k| {
            // don't calculate '0'th share because that's the secret
            let secret_share = poly.clone().evaluate(&<Fr>::from(k)); 
            // calculate commitment 
            let c = g2.mul(secret_share);
            (secret_share, c) 
        }).collect::<Vec<_>>()
    }

    /// combine two public keys
    pub fn combine_pubkeys(pk1: PublicKey, pk2: PublicKey) -> PublicKey {
        PublicKey {
            g1: pk1.g1 + pk2.g1,
            g2: pk1.g2 + pk2.g2,
        }
    }

    /// combine two secrets
    pub fn combine_secrets(sk1: Fr, sk2: Fr) -> Fr {
        sk1 + sk2
    }

    /// encrypts the message to a given public key
    pub fn encrypt<R: Rng + Sized>(
        m: &[u8;32], 
        g1: G1, 
        pubkey: G2, 
        rng: &mut R
    ) -> Ciphertext {
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

    /// decrypts a message using the provided key shares
    pub fn decrypt(
        ct: Vec<u8>, 
        sk: G1, 
        g2:  G2
    ) -> Vec<u8> {
        let r = Bls12_381::pairing(sk, g2);
        let mut ret = Vec::new();
        r.serialize_compressed(&mut ret).unwrap();
        ret = sha256(&ret);
        // decode the message
        for (i, ri) in ret.iter_mut().enumerate().take(32) {
            *ri ^= ct[i];
        }
        ret
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
}
