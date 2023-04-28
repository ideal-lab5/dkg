//!
//! Wasm wrappers for using the dkg lib in the browser
//! 

use wasm_bindgen::prelude::*;
use dkg_core::{
    ser,
    ser::*,
};

 #[wasm_bindgen]
pub fn keygen(seed: u64, threshold: u8) -> Result<JsValue, serde_wasm_bindgen::Error> {
    serde_wasm_bindgen::to_value(&ser::keygen(seed, threshold))
}

#[wasm_bindgen]
pub fn calculate_secret(be_poly: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let be_poly: BEPoly = serde_wasm_bindgen::from_value(be_poly)?;
    serde_wasm_bindgen::to_value(&ser::calculate_secret(be_poly))
}

#[wasm_bindgen]
pub fn calculate_pubkey(
    r1: u64, 
    r2: u64, 
    secret: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // the secret key is encoded as big endian
    let sk_be : Vec<u8> = serde_wasm_bindgen::from_value(secret)?;
    let pk = ser::calculate_pubkey(r1, r2, sk_be);
    serde_wasm_bindgen::to_value(&pk)
}

#[wasm_bindgen]
pub fn calculate_shares_and_commitments(
    t: u8,
    n: u8,
    r2: u64,
    coeffs_blob: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let poly: BEPoly = serde_wasm_bindgen::from_value(coeffs_blob)?;
    serde_wasm_bindgen::to_value(
        &ser::calculate_shares_and_commitments(
            t, n, r2, poly,
        ))
}

#[wasm_bindgen]
pub fn verify_share(
    r2: u64,
    share_bytes: Vec<u8>, // big endian bytes
    commitment_bytes: Vec<u8>, // serialize_compressed
) -> Result<bool, serde_wasm_bindgen::Error> {
    Ok(ser::verify_share(r2, share_bytes, commitment_bytes))
}

#[wasm_bindgen]
pub fn combine_pubkeys(
    pk1: JsValue, 
    pk2: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let w_pk1: SerializablePublicKey = 
        serde_wasm_bindgen::from_value(pk1)?;
    let w_pk2: SerializablePublicKey = 
        serde_wasm_bindgen::from_value(pk2)?;
    let combined_pk = ser::combine_pubkeys(w_pk1, w_pk2);
    serde_wasm_bindgen::to_value(&combined_pk)
}

#[wasm_bindgen]
pub fn combine_secrets(s1: Vec<u8>, s2: Vec<u8>) -> Vec<u8> {
    ser::combine_secrets(s1, s2)
}

#[wasm_bindgen]
pub fn hash_h(
    r1: u64,
    x: Vec<u8>,
) -> Vec<u8> {
    ser::hash_h(r1, &x)
}

#[wasm_bindgen]
pub fn sign(
    seed: u64,
    message: Vec<u8>,
    secret_key: Vec<u8>,
    r: u64,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let params = ser::signature_setup(seed, r);
    serde_wasm_bindgen::to_value(&ser::sign(seed, message, secret_key, params))
}

#[wasm_bindgen]
pub fn verify(
    seed: u64,
    message: Vec<u8>,
    public_key: JsValue,
    signature: JsValue,
    r: u64,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let params = ser::signature_setup(seed, r);
    let pk: ser::SerializablePublicKey = serde_wasm_bindgen::from_value(public_key)?;
    let sig: ser::SerializableSignature = serde_wasm_bindgen::from_value(signature)?;
    serde_wasm_bindgen::to_value(&ser::verify(seed, message, pk, sig, params))
}

#[wasm_bindgen]
pub fn encrypt(
    seed: u64, 
    r1: u64, 
    msg: Vec<u8>, 
    pk_g2: Vec<u8>
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let ct = ser::encrypt(seed, r1, msg, pk_g2);
    serde_wasm_bindgen::to_value(&ct)
}

#[wasm_bindgen]
pub fn threshold_decrypt(
    r2: u64,
    ciphertext: Vec<u8>,
    u: Vec<u8>,
    sk: Vec<u8>
) -> Result<Vec<u8>, serde_wasm_bindgen::Error> {
    Ok(ser::threshold_decrypt(r2, ciphertext, u, sk))
}

#[wasm_bindgen]
pub fn verify_ciphertext(
    g1: Vec<u8>, // g1
    u: Vec<u8>, // g1
    h: Vec<u8>, // g2
    w: Vec<u8>, // g2
) -> bool {
    ser::verify_ciphertext(g1, u, h, w)
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
