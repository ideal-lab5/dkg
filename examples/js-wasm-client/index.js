import * as wasm from "dkg";

export function keygen(seed, threshold) {
    return wasm.w_keygen(BigInt(seed), threshold);
}

export function calculateSecret(poly) {
    return wasm.w_calculate_secret(poly)
}

export function calculatePublicKey(r1, r2, secret) {
    return wasm.w_calculate_pubkey(BigInt(r1), BigInt(r2), secret);
}

export function calculateShares(shares, coeffsBlob) {
    return wasm.w_calculate_shares(shares, coeffsBlob);
}

export function combinePubkeys(pk1, pk2) {
    return wasm.w_combine_pubkeys(pk1, pk2);
}

export function combineSecrets(s1, s2) {
    return wasm.w_combine_secrets(s1, s2);
}

export function thresholdEncrypt(seed, r1, message, pk) {
    return wasm.w_encrypt(BigInt(seed), BigInt(r1), message, pk);
}

export function thresholdDecrypt(r2, ciphertextBlob, sk) {
    return wasm.w_threshold_decrypt(BigInt(r2), ciphertextBlob, sk);
}

// a very basic example
function basicExample() {
    // bytes for the coefficients of a randomn polynomial
    let coeffsBlob = keygen(23, 2);
    console.log('generated serialized secret poly: ' + coeffsBlob);
    // now derive a secret key
    let secret = calculateSecret(coeffsBlob);
    console.log('calculated secret key: ' + secret);
    // derive a public key
    let pubkey = calculatePublicKey(23, 646, 239993401, secret);
    console.log('calculated pubkey: ' + JSON.stringify(pubkey));
    // derive secret shares
    let shares = calculateShares(3, coeffsBlob);
    console.log('calculated shares: ' + JSON.stringify(shares)); 
}

// an example dkg using the wasm bindings
function dkgExample() {
    let n = 3;
    let t = 2;
    let seed = 23;
    let r1 = 89430;
    let r2 = 110458345;
    // for each participant in the protocol
    // each shareholder generates shares for its polynomial
    let secrets = [];
    let pubkeys = [];
    Array(n).fill(0).map((_, i) => {
        let rand_poly = keygen(seed, t);
        console.log(JSON.stringify(rand_poly.coeffs));
        let secret = calculateSecret(rand_poly.coeffs);
        secrets.push(secret);
        let pubkey = calculatePublicKey(r1, r2, secret)
        pubkeys.push(pubkey);
    });

    // now we want to calculate the master public key
    // we'll do this by iterating over the keys and comining them with the combine function
    let mpk = pubkeys.reduce((a, b) => combinePubkeys(a, b));
    console.log('created mpk: ' + JSON.stringify(mpk));

    // then recover a threshold of secret keys
    let msk = secrets.reduce((a, b) => combineSecrets(a, b));
    console.log('calculated threshold secret key: ' + msk);

    // now we want to use this to encrypt a message
    let message = new TextEncoder().encode('not random entropy of 32 bytes!!');
    let ciphertext = thresholdEncrypt(23, r1, message, mpk);
    console.log('Calculated ciphertext: ' + JSON.stringify(ciphertext));

    // and use it to decrypt a message
    let recoveredPlaintext = thresholdDecrypt(r2, ciphertext, msk);
    console.log('recovered: ' + recoveredPlaintext);
    console.log('original: ' + message);
}

dkgExample();
// basicExample();
