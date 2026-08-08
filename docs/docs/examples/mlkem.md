# Example ML KEM usage

```python
from python_pqc_lib.kem import MLKEM, MLKEM_768


### ALICE SIDE

alice = MLKEM(MLKEM_768)

# Alice generates her keys
alice.KeyGen()

###

# Now alice sends her encaps_key to bob

### BOB SIDE

bob = MLKEM(MLKEM_768)

recieved_key = alice.encaps_key

bob_shared_key, encapsulated_key = bob.Encapsulate(recieved_key)

###

# Now bob sends the encapsulated_key to alice

### ALICE SIDE

alice_shared_key = alice.Decapsulate(encapsulated_key)

###

# Now both sides should have matching shared keys

assert alice_shared_key == bob_shared_key
```
