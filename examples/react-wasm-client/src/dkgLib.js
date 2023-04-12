/* global BigInt */
// import * as wasm from "dkg/dkg.js";

/**
 * Generate a secret polynomial
 * @param {*} seed A seed to generate the random number gen from
 * @param {*} threshold The threshold value (i.e. degree) to use when creating the polynomial
 */
export function keygen(seed, threshold) {
    import("dkg/dkg.js").then((js) => {
        console.log("wasm is ready");
        // wasm = js;
        alert("Generated secret key: " + js.keygen(BigInt(23), 3)); 
    });
}
