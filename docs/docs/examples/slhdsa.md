# Example SLH DSA usage

## Normal signature

```python
from python_pqc_lib.dsa import SLHDSA, SLHDSA_SHA2_192_FAST


### SIGNER SIDE

signer = SLHDSA(SLHDSA_SHA2_192_FAST)

signer.KeyGen()

message = b'Hello, World!'
context = b'ML DSA example'

signature = signer.Sign(message, context)

###

# Signer then sends somebody the message, context and signature. When requested, he will provide the public key.

### VERIFICATION SIDE

verification = SLHDSA(SLHDSA_SHA2_192_FAST)

result = verification.Verify(message, signature, signer.public_key, context)

assert result

###
```

## Hash signature

```python
from python_pqc_lib.dsa import SLHDSA, SLHDSA_SHA2_192_FAST


### SIGNER SIDE

signer = SLHDSA(SLHDSA_SHA2_192_FAST)

signer.KeyGen()

message = b'Hello, World!'
context = b'ML DSA example'

signature = signer.HashSign(message, 'SHA3-512', context)

###

# Signer then sends somebody the message, context and signature. When requested, he will provide the public key.

# Signer also needs to provide the digest algorithm chosen either as a string or as OID.

### VERIFICATION SIDE

verification = SLHDSA(SLHDSA_SHA2_192_FAST)

result = verification.HashVerify(message, signature, signer.public_key, 'SHA3-512', context)

assert result

###
```
