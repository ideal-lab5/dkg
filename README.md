# DKG/VSS 

This is a library for threshold cryptography. Specifically, it is a verifiable secret sharing scheme intended to be used on top of a distributed network.

## Overview

This is an implementation of the DKG and VSS scheme required for [Blind DKG]().

### DKG
This is a proof of concept distributed key generation protocol. Currently, it uses BLS12-381.

## Installation

build with 

``` bash
cargo build
```

run the dkg example with

``` bash
cargo run
```

