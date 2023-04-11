# DKG/VSS 

This is a library for threshold cryptography. Specifically, it is a verifiable secret sharing scheme intended to be used on top of a distributed network.

## Overview

This is an implementation of the DKG and VSS scheme required for [Blind DKG]().

### DKG
This is a proof of concept distributed key generation protocol. Currently, it uses BLS12-381. It allows users to articipate in dkg together.

Expose wasm calls to:

- derive secret polynomials (includes secret key)
- verify shares
- encrypt/decrypt shares
- encrypt messages
- decrypt ciphertext

## Installation

build with 

``` bash
cargo build
```

run the dkg example with

``` bash
cargo run
```

## Compiling wasm build

From the root directory
``` bash
cd dkg
# build
wasm-pack build --target web
wasm-pack build --target bundler
# link to npm repo
cd pkg
npm link
```

Then, 

``` bash
# either enable legacy openssl or downgrade to node v16
export NODE_OPTIONS=--openssl-legacy-provider
cd example
npm link dkg
npm install
npm run serve
```

Open the application at http://localhost:8080

