# DKG

This library is an implementation of the distributed key generator required for [blind DKG](TODO).

## Overview

[dkg-core](./dkg-core/): supports both std and no-std. When built with std, it exposes functions that can be called from the dkg-wasm module. |

[dkg-wasm](./dkg-wasm/): exposes wasm bindings around the dkg-core functions. Can be compiled to wasm.

[examples](./examples/): examples of usage of the dkg-wasm library

