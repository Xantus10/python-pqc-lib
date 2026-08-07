# Python PQC library

This is a package containing my python implementations of Post Quantum Cryptography algorithms. In all cases I try to adhere to NIST standards or other official materials.

## Algorithms

Currently supports the following algorithms:

- Key encapsulation
    - `ML KEM` - [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)
- Digital signature
    - blank

## Dependencies

- numpy

## Security notice

While the solution is always tested to be functional and best effort was made to adhere to the NIST standards and specifications, I do not guarantee that the algorithm is secure.

Also, since this is an implementation written purely in python, while it can be used in smaller projects, production code should make use of something like the [PQC Code package](https://github.com/pq-code-package).

## TODO

- Implement ML DSA
- Remove duplicit ML code
- Test with (NIST ACVP)[https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files]
- Add automated tests
- Implement SLH DSA
