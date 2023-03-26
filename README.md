# Magi

This is a library for threshold cryptography. Specifically, it is a verifiable secret sharing scheme intended to be used on top of a distributed network.

## Overview

This is an implementation of the scheme detailed in [Blind DKG]().

### DKG
This is a proof of concept distributed key generation protocol. The protocol is based on the Feldman VSS scheme. The intention is to augment the design, similar to the ethDKG protocol, to use ZK SNARKs within the disputes process.

## Installation

build with 

``` bash
cargo build --release
```

run the dkg example with

``` bash
cargo run
```

## Key Gen

