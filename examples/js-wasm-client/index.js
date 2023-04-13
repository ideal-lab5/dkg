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

// Q: Can I derive a master public key with javascript? sure, why not?
// mpk is the sum of all pubkye
function dkgExample() {
    let n = 5;
    let t = 3;
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
    let pubkeys = [];
    shareholders.forEach(shareholder => {
        let shares = calculateShares(t, shareholder.poly);
        // then 'distribute' the shares to other particiipants...
        // not sure if I can do that right now, need to figure out how to properly serialize first...
        let secret = calculateSecret(shareholder.poly);
        console.log('generated secret: ' + secret);
        let pubkey = calculatePublicKey(23, 89430, 110458345, secret);
        pubkeys.push(pubkey);
    });

    console.log('pubkey ' + pubkeys.reduce((a, b) => a + b))
    // % MODULUS??
}

dkgExample();
// basicExample();
