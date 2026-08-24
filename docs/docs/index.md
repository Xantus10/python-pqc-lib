# Python PQC lib

## About

Welcome to the documentation for `python_pqc_lib`! This package provides python implementations of PQC (Post-Quantum Cryptography) algorithms mentioned in [the NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography).

## Algorithms implemented

### ML KEM

ML KEM ([NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)) is a **key encapsulation mechanism** which is set to replace currently used ECDH (Elliptic curve Diffie-Hellman) and other key exchange mechanisms.

The algorithm itself is based on MLWE (Modular Learning With Errors) problem which is believed to be quantum resistant.

## ML DSA

ML DSA ([NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)) is a **digital signature algorithm** based on the same principles as `ML KEM`.

## SLH DSA

SLH DSA ([NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)) is a **digital signature algorithm** based purely on hashes. Specifically it relies on schemes like WOTS+, FORS and Merkle trees to create a signature. It was created as a fallback in case the module lattice problem (For ML DSA) turns out to be less secure than thought.

## Security notice

While the solution is always tested to be functional and best effort was made to adhere to the NIST standards and specifications, I do not guarantee that the algorithm is secure.

Also, since this is an implementation written purely in python, while it can be used in smaller projects, production code should make use of something like the [PQC Code package](https://github.com/pq-code-package).

