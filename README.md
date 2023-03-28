# DKG/VSS 

This is a library for threshold cryptography. Specifically, it is a verifiable secret sharing scheme intended to be used on top of a distributed network.

## Overview

This is an implementation of the scheme detailed in [Blind DKG]().

### DKG
This is a proof of concept distributed key generation protocol. The protocol is based on the Feldman VSS scheme. The intention is to augment the design, similar to the ethDKG protocol, to use ZK SNARKs within the disputes process.

![encrypt](https://substackcdn.com/image/fetch/f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fbb7f7e58-8b13-4869-b832-51057fcaa2c5_441x350.png)

![decrypt](https://substackcdn.com/image/fetch/f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fa1fb2edd-12fc-411e-a189-0ff421a6b68a_365x244.png)

## Installation

build with 

``` bash
cargo build --release
```

run the dkg example with

``` bash
cargo run
```

