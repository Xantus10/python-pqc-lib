
### `SUPPORTED_HASH_ALGS`

A set containing the names of all the supported hash algorithms for pre-hash versions of DSA schemes.

### `HASH_BIT_STRENGTHS`

Defined hash bit strengths for hashes used in pre-hash versions of DSA schemes. Generally a hash of bit strength of at least n bits (the same as the scheme).

### `PreHash_Alg`

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