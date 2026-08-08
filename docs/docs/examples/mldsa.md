# Example ML DSA usage

## Normal signature

```python
from python_pqc_lib.dsa import MLDSA, MLDSA_65


### SIGNER SIDE

signer = MLDSA(MLDSA_65)

signer.KeyGen()

message = b'Hello, World!'
context = b'ML DSA example'

signature = signer.Sign(message, context)

###

# Signer then sends somebody the message, context and signature. When requested, he will provide the public key.

### VERIFICATION SIDE

verification = MLDSA(MLDSA_65)

result = verification.Verify(signer.public_key, message, signature, context)

assert result

###
```

## Hash signature

```python
from python_pqc_lib.dsa import MLDSA, MLDSA_65


### SIGNER SIDE

signer = MLDSA(MLDSA_65)

signer.KeyGen()

message = b'Hello, World!'
context = b'ML DSA example'

signature = signer.HashSign(message, context, 'sha512')

###

# Signer then sends somebody the message, context and signature. When requested, he will provide the public key.

# Signer also needs to provide the digest algorithm chosen either as a string or as OID.

### VERIFICATION SIDE

verification = MLDSA(MLDSA_65)

result = verification.HashVerify(signer.public_key, message, signature, context, 'sha512')

assert result

###
```
