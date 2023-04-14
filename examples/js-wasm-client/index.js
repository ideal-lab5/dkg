import * as wasm from "dkg";

export function keygen(seed, threshold) {
    return wasm.keygen(BigInt(seed), threshold);
}

export function calculateSecret(coeffsBlob) {
    return wasm.calculate_secret(coeffsBlob)
}

export function calculatePublicKey(seed, r1, r2, secret) {
    return wasm.calculate_pubkey(BigInt(seed), BigInt(r1), BigInt(r2), secret);
}

export function calculateShares(shares, coeffsBlob) {
    return wasm.calculate_shares(shares, coeffsBlob);
}

export function combinePubkeys(pk1, pk2) {
    return wasm.combine_pubkeys(pk1, pk2);
}

export function combineSecrets(s1, s2) {
    return wasm.combine_secrets(s1, s2);
}

export function thresholdEncrypt(seed, r1, message, pk) {
    return wasm.threshold_encrypt(BigInt(seed), r1, message, pk);
}

export function thresholdDecrypt(r2, ciphertextBlob, sk) {
    return wasm.threshold_decrypt(r2, ciphertextBlob, sk);
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

    let r1 = 89430;
    let r2 = 110458345;

    let shareholders = [];
    // create a group of shareholders
    Array(n).fill(0).map((_, i) => {
        shareholders.push({
            slot: i,
            poly: keygen(i, t),
        });
    });
    console.log('created shareholders');

    // // now, each shareholder generates shares for its polynomial
    let secrets = [];
    let pubkeys = [];
    shareholders.forEach(shareholder => {
        // let shares = calculateShares(t, shareholder.poly);
        // then 'distribute' the shares to other participants
        let secret = calculateSecret(shareholder.poly);
        // console.log('generated secret: ' + secret);
        let pubkey = calculatePublicKey(23, r1, r2, secret);
        secrets.push(secret);
        pubkeys.push(pubkey);
    });

    // now we want to calculate the master public key
    // we'll do this by iterating over the keys and comining them with the combine function
    let mpk = pubkeys.reduce((a, b) => combinePubkeys(a, b));
    console.log('created mpk: ' + JSON.stringify(mpk["p2"]));

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
