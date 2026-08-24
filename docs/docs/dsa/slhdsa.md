Stateless Hash-Based Digital Signature Standard as defined in [NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).

## `class SLHDSA`

Class representing an SLH DSA state

### `SLHDSA.__init__(parameters: SLHDSA_Parameters)`

Class representing an SLH DSA state

`Args`

- `parameters` : [SLHDSA_Parameters](#slhdsa_parameters)
    - A special list of parameters, you should **always** pass an imported constant and **never** a raw list

### `SLHDSA.KeyGen()`

Generate keys for SLH DSA

Keys are stored internally. See [public_key](#slhdsapublic_key)

### `SLHDSA.Sign(msg: bytes, ctx: bytes = b'')`

Sign a message using SLH DSA

`Args`

- msg : bytes
    - The message to be signed
- ctx : bytes
    - The context string

`Returns`

The SLH DSA signature

`Raises`

- `ValueError`: The context string is too long

### `SLHDSA.HashSign(msg: bytes, hash_alg: PreHash_Alg, ctx: bytes = b'')`

Sign a message using SLH DSA pre-hash variant

`Args`

- msg : bytes
    - The message to be signed
- hash_alg : [PreHash_Alg](../util.md#prehash_alg)
    - The hash algorithm to use for pre-hash
- ctx : bytes
    - The context string

`Returns`

The SLH DSA signature

`Raises`

- `ValueError`: The context string is too long or Invalid hash alg was provided

### `SLHDSA.Verify(msg: bytes, sig: bytes, public_key: bytes, ctx: bytes = b'')`

Verify an SLH DSA signature

`Args`

- msg : bytes
    - The signed message
- sig : bytes
    - The signature
- public_key : bytes
    - The public key to use
- ctx : bytes
    - The context string

`Returns`

True if the signature is valid

`Raises`

- `ValueError`: The context string is too long

### `SLHDSA.HashVerify(msg: bytes, sig: bytes, public_key: bytes, hash_alg: PreHash_Alg, ctx: bytes = b'')`

Verify a pre-hash SLH DSA signature

`Args`

- msg : bytes
    - The signed message
- sig : bytes
    - The signature
- public_key : bytes
    - The public key to use
- hash_alg : [PreHash_Alg](../util.md#prehash_alg)
    - The hash algorithm to use for pre-hash
- ctx : bytes
    - The context string

`Returns`

True if the signature is valid

`Raises`

- `ValueError`: The context string is too long or Invalid hash alg was provided

### `SLHDSA.public_key`

The byte form of the public key used for verifying a signature. (or `None` if the key hasn't been generated yet)

### `SLHDSA._secret_key`

The byte form of the secret key used for signing. (or `None` if the key hasn't been generated yet). This value should be kept private.

## SLHDSA_Parameters

This is a type for a list of parameters for SLH DSA.

The parameter sets can be differentiated by the following parameters:

- Base hash function to use
    - `SHA2`
    - `SHAKE`
- Number of security bits (directly corresponds to security category)
    - `128` - Security category 1
    - `192` - Security category 3
    - `256` - Security category 5
- Small signature vs Fast signing
    - `s` - Will produce smaller signature (About 1/2 of `f`) at the cost of computation time
    - `f` - Will run faster than `s`, but will produce larger signature

### SLHDSA_SHA2_128_SMALL

- Hash: SHA2
- Security category: 1
- Prioritize: Small signature

### SLHDSA_SHA2_128_FAST

- Hash: SHA2
- Security category: 1
- Prioritize: Fast signing

### SLHDSA_SHA2_192_SMALL

- Hash: SHA2
- Security category: 3
- Prioritize: Small signature

### SLHDSA_SHA2_192_FAST

- Hash: SHA2
- Security category: 3
- Prioritize: Fast signing

### SLHDSA_SHA2_256_SMALL

- Hash: SHA2
- Security category: 5
- Prioritize: Small signature

### SLHDSA_SHA2_256_FAST

- Hash: SHA2
- Security category: 5
- Prioritize: Fast signing


### SLHDSA_SHAKE_128_SMALL

- Hash: SHAKE
- Security category: 1
- Prioritize: Small signature

### SLHDSA_SHAKE_128_FAST

- Hash: SHAKE
- Security category: 1
- Prioritize: Fast signing

### SLHDSA_SHAKE_192_SMALL

- Hash: SHAKE
- Security category: 3
- Prioritize: Small signature

### SLHDSA_SHAKE_192_FAST

- Hash: SHAKE
- Security category: 3
- Prioritize: Fast signing

### SLHDSA_SHAKE_256_SMALL

- Hash: SHAKE
- Security category: 5
- Prioritize: Small signature

### SLHDSA_SHAKE_256_FAST

- Hash: SHAKE
- Security category: 5
- Prioritize: Fast signing
