# JS + Wasm DKG Example

## build

```
npm i
```

## Troubleshooting

If you see an error `Module parse failed: Unexpected token` in `dkg-wasm/pkg/wasm_dkg.js`, then you need to enable the legacy openssl provider:

``` bash
export NODE_OPTIONS=--openssl-legacy-provider
```