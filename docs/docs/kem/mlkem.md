# ML KEM

Module-Lattice-Based Key-Encapsulation Mechanism as defined in [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf).

## `class ML KEM`

The class representing the state of the ML KEM algorithm.

### `MLKEM.__init__(parameters: MLKEM_Parameters)`

The constructor for ML KEM.

`Args`

- `parameters` : [MLKEM_Parameters](#mlkem_parameters)
    - A special list of parameters, you should **always** pass an imported constant and **never** a raw list

### `MLKEM.KeyGen()`

Generate keys for ML KEM.

Keys are stored internally. See [encaps_key](#mlkemencaps_key)

### `MLKEM.Encapsulate(ek: bytes)`

Generate and encapsulate a shared key

`Args`

- `ek` : bytes
    - The encapsulation key to use

`Returns`

A tuple of `(shared_key, encapsulated_key)`

`Raises`

- `TypeError`: If the provided encapsulation key is not bytes
- `ValueError`: The encapsulation key is not valid (invalid length or values)

### `MLKEM.Decapsulate(ciphertext: bytes)`

Decrypt the ciphertext into a shared key

`Args`

- `ciphertext` : bytes
    - The encapsulated shared key

`Returns`

The shared key

`Raises`

- `TypeError`: If the provided ciphertext is not bytes
- `ValueError`: The ciphertext has invalid length

### `MLKEM.encaps_key`

The byte form of the encapsulation key (or `None` if the key hasn't been generated yet)

### `MLKEM._decaps_key`

The byte form of the decapsulation key (or `None` if the key hasn't been generated yet). This value should be kept private.

## MLKEM_Parameters

This is a type for a list of parameters for ML KEM. Currently there are three parameter sets:

### MLKEM_512

A parameter set for ML KEM. Corresponds to NIST security strength category 1.

### MLKEM_768

A parameter set for ML KEM. Corresponds to NIST security strength category 3.

### MLKEM_1024

A parameter set for ML KEM. Corresponds to NIST security strength category 5.
