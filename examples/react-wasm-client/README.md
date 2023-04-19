# WASM DKG with React

wasm wrappers for the dkg core library, allows for use within the browser

## Build

First build the dkg lib and the wasm. From the [dkg-wasm](../dkg-wasm/) directory, run:

``` bash
cargo build
# build for web target
wasm-pack build --target web
```

## Troubleshooting

If you encounter an error like: `export 'default' (imported as 'init') was not found in 'dkg'`, this most likely indicates that the wasm library was builder with `--target bunder`. To fix this, rebuild the wasm using `--target web` only.