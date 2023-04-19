//!
//! Wasm wrappers for using the dkg lib in the browser
//! 
//!
use wasm_bindgen::prelude::*;
use dkg_core::ser::*;

 #[wasm_bindgen]
pub fn w_keygen(seed: u64, threshold: u8) -> Result<JsValue, serde_wasm_bindgen::Error> {
    serde_wasm_bindgen::to_value(&s_keygen(seed, threshold))
}

#[wasm_bindgen]
pub fn w_calculate_secret(be_poly: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let be_poly: BEPoly = serde_wasm_bindgen::from_value(be_poly)?;
    serde_wasm_bindgen::to_value(&s_calculate_secret(be_poly))
}

#[wasm_bindgen]
pub fn w_calculate_pubkey(
    r1: u64, 
    r2: u64, 
    secret: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // the secret key is encoded as big endian
    let sk_be : Vec<u8> = serde_wasm_bindgen::from_value(secret)?;
    let pk = s_calculate_pubkey(r1, r2, sk_be);
    serde_wasm_bindgen::to_value(&pk)
}

// #[wasm_bindgen]
// pub fn w_verify_pubkey(pubkey_bytes: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
//     let pk = serde_wasm_bindgen::from_value(pubkey_bytes)?;

// }

#[wasm_bindgen]
pub fn w_calculate_shares(
    n: u8, 
    coeffs_blob: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let poly: BEPoly = serde_wasm_bindgen::from_value(coeffs_blob)?;
    Ok(s_calculate_shares(n, poly.coeffs))
}

#[wasm_bindgen]
pub fn w_combine_pubkeys(
    pk1: JsValue, 
    pk2: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let w_pk1: SerializablePublicKey = 
        serde_wasm_bindgen::from_value(pk1).unwrap();
    let w_pk2: SerializablePublicKey = 
        serde_wasm_bindgen::from_value(pk2).unwrap();
    let combined_pk = s_combine_pubkeys(w_pk1, w_pk2);
    serde_wasm_bindgen::to_value(&combined_pk)
}

#[wasm_bindgen]
pub fn w_combine_secrets(s1: Vec<u8>, s2: Vec<u8>) -> Vec<u8> {
    s_combine_secrets(s1, s2)
}

#[wasm_bindgen]
pub fn w_encrypt(
    seed: u64, 
    r1: u64, 
    msg: Vec<u8>, 
    pk: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk)?;
    serde_wasm_bindgen::to_value(&s_encrypt(seed, r1, msg, wpk))
}

#[wasm_bindgen]
pub fn w_threshold_decrypt(
    r2: u64, 
    ciphertext_blob: JsValue, 
    sk: Vec<u8>
) -> Vec<u8> {
    let ciphertext: SerializableCiphertext = 
        serde_wasm_bindgen::from_value(ciphertext_blob).unwrap();
    threshold_decrypt(r2, ciphertext, sk)
}

// pub fn s_keygen(seed: u64, threshold: u8) -> BEPoly {
//     let rng = ChaCha20Rng::seed_from_u64(seed);
//     let poly = dkg_core::dkg::keygen(threshold as usize, rng);
//     BEPoly::new(poly)
// }

// pub fn s_calculate_secret(be_poly: BEPoly) -> Vec<u8> {
//     let f = DensePolynomial::<Fr>::from_coefficients_vec(be_poly.coeffs);
//     let secret: Fr = dkg_core::dkg::calculate_secret(f);
//     let big_secret: num_bigint::BigUint = secret.into();
//     big_secret.to_bytes_be()
// }

// pub fn s_calculate_shares(n: u8, coeffs: Vec<Fr>) -> JsValue {
//     let h2 = G2::generator();
//     let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
//     let shares: Vec<(Fr, G2)> = dkg_core::dkg::calculate_shares(n, h2, f);
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
//     let pubkey = dkg_core::dkg::calculate_pubkey(h1, h2, sk);
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

//     let sum = dkg_core::dkg::combine_pubkeys(pubkey1, pubkey2);

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
//     let x = dkg_core::dkg::combine_secrets(x1, x2);
//     let big_x: num_bigint::BigUint = x.into();
//     big_x.to_bytes_be()
// }

// pub fn s_encrypt(seed: u64, r1: u64, msg: Vec<u8>, pk: SerializablePublicKey) -> SerializableCiphertext {
//     let mut rng = ChaCha20Rng::seed_from_u64(seed);
//     let h1 = G1::generator().mul(Fr::from(r1));
//     // let wpk: SerializablePublicKey = serde_wasm_bindgen::from_value(pk).unwrap();
//     let gpk = G2::deserialize_compressed(&pk.g2[..]).unwrap();
//     let m = slice_to_array_32(&msg).unwrap();
//     let out = dkg_core::dkg::encrypt(m, h1, gpk, &mut rng);
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
//     let recovered_message = dkg_core::dkg::decrypt(ciphertext.v, decryption_key, h2);
//     recovered_message.to_vec()
// }