let wasm;
// import("./node_modules/dkg/dkg.js").then((js) => {
//         console.log("wasm is ready");
//         wasm = js;
//         // js.keygen(BigInt(seed), threshold);
//     });
function setup() {
    import("dkg/dkg.js").then((js) => {
        console.log("wasm is ready");
        wasm = js;
    });
}

/**
 * Generate a secret polynomial
 * @param {*} seed A seed to generate the random number gen from
 * @param {*} threshold The threshold value (i.e. degree) to use when creating the polynomial
 */
function keygen(seed, threshold) {
    if (wasm == null) {
        alert("wasm blob is null");
    } else {
        return wasm.keygen(BigInt(seed), threshold);
    }
}

setup();
keygen(23, 3);

module.exports = {keygen, setup};