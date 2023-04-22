//!
//! Wasm wrappers for using the dkg lib in the browser
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

#[wasm_bindgen]
pub fn w_calculate_shares(
    t: u8,
    n: u8, 
    coeffs_blob: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let poly: BEPoly = serde_wasm_bindgen::from_value(coeffs_blob)?;
    serde_wasm_bindgen::to_value(&s_calculate_shares(t, n, poly.coeffs))
}

#[wasm_bindgen]
pub fn w_verify_share(
    r2: u64,
    share_bytes: Vec<u8>, // big endian bytes
    commitment_bytes: Vec<u8>, // serialize_compressed
) -> Result<bool, serde_wasm_bindgen::Error> {
// ) -> bool {
    // get both as Vec<u8>
    // let share_be: Vec<u8> = serde_wasm_bindgen::from_value(share_bytes)?;
    // let commitment: Vec<u8> = serde_wasm_bindgen::from_value(commitment_bytes)?;
    Ok(s_verify_share(r2, share_bytes, commitment_bytes))
}

#[wasm_bindgen]
pub fn w_combine_pubkeys(
    pk1: JsValue, 
    pk2: JsValue
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let w_pk1: SerializablePublicKey = 
        serde_wasm_bindgen::from_value(pk1)?;
    let w_pk2: SerializablePublicKey = 
        serde_wasm_bindgen::from_value(pk2)?;
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
) -> Result<Vec<u8>, serde_wasm_bindgen::Error> {
    let ciphertext: SerializableCiphertext = 
        serde_wasm_bindgen::from_value(ciphertext_blob)?;
    Ok(threshold_decrypt(r2, ciphertext, sk))
}
