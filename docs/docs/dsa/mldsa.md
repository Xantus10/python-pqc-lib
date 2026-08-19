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

### `MLDSA.HashSign(message: bytes, hash_alg: MLDSA_Hash_Alg, context: bytes)`

Sign a digest of the message and context string.

`Args`

- `message` : bytes
    - The message to sign
- `hash_alg` : [MLDSA_Hash_Alg](#mldsamldsa_hash_alg)
    - Hash function to use
- `context` : bytes
    - Optional context string of max length 255 bytes

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

### `MLDSA.HashVerify(public_key: bytes, message: bytes, sig: bytes, hash_alg: MLDSA_Hash_Alg, context: bytes)`

Verify a signature.

`Args`

- `public_key` : bytes
    - The byte representation of the public key
- `message` : bytes
    - The signed message
- `sig`: bytes
    - The signature
- `hash_alg` : [MLDSA_Hash_Alg](#mldsamldsa_hash_alg)
    - Hash function to use
- `context` : bytes
    - Optional context string of max length 255 bytes

`Returns`

True if the signature matches

`Raises`

- `ValueError`: Invalid argument was provided

### `MLDSA.ExportPublicKeyPEM()`

Export the public key in PEM PKCS#8 DER format

`Returns`

The PEM string (or None if the key hasn't been generated)

### `MLDSA.ExportSecretKeyPEM()`

Export the secret key (in seed form) in PEM PKCS#8 DER format

**!!! The secret key should stay private !!!**

`Returns`

The PEM string (or None if the key hasn't been generated)

### `MLDSA.public_key`

The byte form of the public key used for verifying a signature. (or `None` if the key hasn't been generated yet)

### `MLDSA._secret_key`

The byte form of the secret key used for signing. (or `None` if the key hasn't been generated yet). This value should be kept private.

### `MLDSA._seed`

The random seed used for key generation (This value should be handled with the same level of secrecy as [secret key](#mldsa_secret_key))

### `MLDSA.SUPPORTED_HASH_ALGS`

A set containing the names of all the supported hash algorithms for pre-hash ML DSA.

### `MLDSA._HASH_BIT_STRENGTHS`

Defined hash bit strengths for hashes used in pre-hash ML DSA. Generally a hash of bit strength of at least $\lambda$ bits. (For more information, see [the NIST specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) - Last paragraph of section 5.4)

### `MLDSA.MLDSA_Hash_Alg`

A type string literal of the following

- `SHA2-224` - (Don't use, insufficient bit strength)
- `SHA2-256`
- `SHA2-384`
- `SHA2-512`
- `SHA3-224` - (Don't use, insufficient bit strength)
- `SHA3-256`
- `SHA3-384`
- `SHA3-512`
- `SHAKE-128`
- `SHAKE-512`

## MLDSA_Parameters

This is a type for a list of parameters for ML DSA. Currently there are three parameter sets:

### MLDSA_44

A parameter set for ML DSA. Corresponds to NIST security strength category 2.

### MLDSA_65

A parameter set for ML DSA. Corresponds to NIST security strength category 3.

### MLDSA_87

A parameter set for ML DSA. Corresponds to NIST security strength category 5.
