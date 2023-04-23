import * as wasm from "dkg";

export function keygen(seed, threshold) {
    return wasm.keygen(BigInt(seed), threshold);
}

export function calculateSecret(poly) {
    return wasm.calculate_secret(poly)
}

export function calculatePublicKey(r1, r2, secret) {
    return wasm.calculate_pubkey(BigInt(r1), BigInt(r2), secret);
}

export function calculateShares(threshold, shares, r2, coeffsBlob) {
    return wasm.calculate_shares_and_commitments(threshold, shares, BigInt(r2), coeffsBlob);
}

export function combinePubkeys(pk1, pk2) {
    return wasm.combine_pubkeys(pk1, pk2);
}

export function combineSecrets(s1, s2) {
    return wasm.combine_secrets(s1, s2);
}

export function verifyShare(r2, share, commitment) {
    return wasm.verify_share(BigInt(r2), share, commitment);
}

export function schnorrSign(seed, message, sk, r) {
    return wasm.sign(BigInt(seed), message, sk, BigInt(r));
}

export function schnorrVerify(seed, message, pk, sig, r) {
    return wasm.verify(BigInt(seed), message, pk, sig, BigInt(r));
}

export function thresholdEncrypt(seed, r1, message, pk) {
    return wasm.encrypt(BigInt(seed), BigInt(r1), message, pk);
}

export function thresholdDecrypt(r2, ciphertextBlob, sk) {
    return wasm.threshold_decrypt(BigInt(r2), ciphertextBlob, sk);
}

// a very basic example
function basicExample() {
    // bytes for the coefficients of a random polynomial
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
function dkgSimulation() {
    let n = 3;
    let t = 2;
    let seed = 23;
    // todo: verify generator?
    let r1 = 89430;
    let r2 = 110445;
    // for each participant in the protocol
    // each shareholder generates shares for its polynomial
    let secrets = [];
    let pubkeys = [];
    // this is a map of index -> array(share, commitment)
    let shares = [];
    Array(n).fill(0).map((_, i) => {
        let rand_poly = keygen(seed, t);
        console.log(JSON.stringify(rand_poly.coeffs));
        let secret = calculateSecret(rand_poly.coeffs);
        secrets.push(secret);
        let pubkey = calculatePublicKey(r1, r2, secret)
        pubkeys.push(pubkey);
        // calculate shares
        let sharesAndCommitments = calculateShares(t, n, r2, rand_poly.coeffs);
        shares.push(sharesAndCommitments);
    });

    // each particpant verifies their shares received
    Array(n).fill(0).map((_, i) => {
        let myShares = shares[i];
        myShares.forEach(item => {
            console.log('share validity ' + 
                verifyShare(r2, item.share, item.commitment));
        });
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

function signaturesTest() {
    let t = 2;
    let r1 = 5661;
    let r2 = 949490;
    let seed = 231;
    let message = new TextEncoder().encode("msg to sign");

    let rand_poly = keygen(seed, t);
    let secret = calculateSecret(rand_poly.coeffs);
    let pubkey = calculatePublicKey(r1, r2, secret)

    let sig = schnorrSign(seed, message, secret, r1);
    let isValid = schnorrVerify(seed, message, pubkey, sig, r1);
    console.log('isValid = ' + isValid);

}

dkgSimulation();
// basicExample();
// signaturesTest();
