# ML DSA

Module-Lattice-Based Digital Signature Standard as defined in [NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).

## `class MLDSA`

The class representing the state of the ML DSA algorithm.

### `MLDSA.__init__(parameters: MLDSA_Parameters)`

The constructor for ML DSA.

`Args`

- `parameters` : [MLDSA_Parameters](#mldsa_parameters)
    - A special list of parameters, you should **always** pass an imported constant and **never** a raw list

### `MLDSA.KeyGen()`

Generate keys for ML DSA.

Keys are stored internally. See [public_key](#mldsapublic_key)

### `MLDSA.Sign(message: bytes, context: bytes)`

Sign a message and a context string.

`Args`

- `message` : bytes
    - The message to sign
- `context` : bytes
    - Optional context string of max length 255 bytes

`Returns`

The byte representation of the signature

`Raises`

- `ValueError`: Context is longer than 255 bytes

### `MLDSA.HashSign(message: bytes, context: bytes, hash_alg: 'sha256' | 'sha512' | 'shake128')`

Sign a digest of the message and context string.

`Args`

- `message` : bytes
    - The message to sign
- `context` : bytes
    - Optional context string of max length 255 bytes
- `hash_alg` : 'sha256' | 'sha512' | 'shake128'
    - Hash function to use

`Returns`

The byte representation of the signature

`Raises`

- `ValueError`: Context is longer than 255 bytes or Invalid hash alg was provided

### `MLDSA.Verify(public_key: bytes, message: bytes, sig: bytes, context: bytes)`

Verify a signature.

`Args`

- `public_key` : bytes
    - The byte representation of the public key
- `message` : bytes
    - The signed message
- `sig`: bytes
    - The signature
- `context` : bytes
    - Optional context string of max length 255 bytes

`Returns`

True if the signature matches

`Raises`

- `ValueError`: Invalid argument was provided

### `MLDSA.HashVerify(public_key: bytes, message: bytes, sig: bytes, context: bytes, hash_alg: 'sha256' | 'sha512' | 'shake128')`

Verify a signature.

`Args`

- `public_key` : bytes
    - The byte representation of the public key
- `message` : bytes
    - The signed message
- `sig`: bytes
    - The signature
- `context` : bytes
    - Optional context string of max length 255 bytes
- `hash_alg` : 'sha256' | 'sha512' | 'shake128'
    - Hash function to use

`Returns`

True if the signature matches

`Raises`

- `ValueError`: Invalid argument was provided

### `MLDSA.public_key`

The byte form of the public key used for verifying a signature. (or `None` if the key hasn't been generated yet)

### `MLDSA.__secret_key`

The byte form of the secret key used for signing. (or `None` if the key hasn't been generated yet). This value is kept private.

## MLDSA_Parameters

This is a type for a list of parameters for ML DSA. Currently there are three parameter sets:

### MLDSA_44

A parameter set for ML DSA. Corresponds to NIST security strength category 2.

### MLDSA_65

A parameter set for ML DSA. Corresponds to NIST security strength category 3.

### MLDSA_87

A parameter set for ML DSA. Corresponds to NIST security strength category 5.
