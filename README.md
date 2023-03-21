# Distributed Key Generation

This is a distributed key generation mechanism using the arkworks library.

## Overview

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