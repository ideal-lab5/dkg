# WASM DKG with plain JS + Webpack

wasm wrappers for the dkg core library, allows for use within the browser

## Build

First build the dkg lib and the wasm. From the [dkg-wasm](../dkg-wasm/) directory, run:

``` bash
cargo build
# we to build for bundler when using vanilla js/webpack
wasm-pack build --target bundler
```