# DKG Core

This is a library for threshold cryptography. Specifically, it is a verifiable secret sharing scheme intended to be used on top of a distributed network.

## Overview

This is an implementation of the DKG and VSS scheme required for [Blind DKG]().

### DKG
This is a proof of concept distributed key generation protocol. Currently, it uses BLS12-381. It allows users to articipate in dkg together.

- [x] derive secret polynomials (includes secret key)
- [x] calculate shares and commitments
- [x] calculate keypairs and group keypairs
- [x] encrypt messages
- [x] decrypt ciphertext
- [ ] verify shares
- [ ] ZK snarks for issuing disputes
- [ ] baseline performance


