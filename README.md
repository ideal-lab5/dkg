# DKG/VSS 

This is a library for threshold cryptography. Specifically, it is a verifiable secret sharing scheme intended to be used on top of a distributed network.

## Overview

This is an implementation of the scheme detailed in [Blind DKG]().

Ok so I have an elliptic curve group, and my coefficients are coming from a finite field of order r.
Now, what I'm trying to do is derive a new public key. Mathematically speaking, this is done by taking the product of the group generator raised to each secret.
However, this is where I'm facing a huge challenge.

So, there are two main types in use, Projective<Config> for group elements, and Fp<MontBackend<FrConfig, 4>, 4> for field elements.
The group generator is given a a Projective<Config>, however, the coefficients (i.e. secrets) that I'm generating are in the field...
So, if I want to calculate the product of the group generator exponentiated to a field element... argh this is confusing. 

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

