"""Constants for SLH DSA"""


from typing import Literal

type _SLHDSA_Hash = Literal['SHA2', 'SHAKE']
"""Hash functions for SLH DSA to use"""
type _SLHDSA_Constants = list[int]
"""
Numeric constants for SLH DSA

(n, h, d, h_sec, a, k, lgw, m)
"""

_SLHDSA_128_S = [16, 63, 7, 9, 12, 14, 4, 30]
_SLHDSA_128_F = [16, 66, 22, 3, 6, 33, 4, 34]
_SLHDSA_192_S = [24, 63, 7, 9, 14, 17, 4, 39]
_SLHDSA_192_F = [24, 66, 22, 3, 8, 33, 4, 42]
_SLHDSA_256_S = [32, 64, 8, 8, 14, 22, 4, 47]
_SLHDSA_256_F = [32, 68, 17, 4, 9, 35, 4, 49]

type SLHDSA_Parameters = tuple[_SLHDSA_Hash, _SLHDSA_Constants]
"""
Parameter set for SLH DSA

`0` - Hash type

`1` - SLH DSA Constants (n, h, d, h_sec, a, k, lgw, m)
"""

SLHDSA_SHA2_128_SMALL = ('SHA2', _SLHDSA_128_S)
"""
SLH DSA parameter set

- Hash: SHA2
- Security category: 1
- Prioritize: Small signature
"""
SLHDSA_SHA2_128_FAST = ('SHA2', _SLHDSA_128_F)
"""
SLH DSA parameter set

- Hash: SHA2
- Security category: 1
- Prioritize: Fast signing
"""
SLHDSA_SHA2_192_SMALL = ('SHA2', _SLHDSA_192_S)
"""
SLH DSA parameter set

- Hash: SHA2
- Security category: 3
- Prioritize: Small signature
"""
SLHDSA_SHA2_192_FAST = ('SHA2', _SLHDSA_192_F)
"""
SLH DSA parameter set

- Hash: SHA2
- Security category: 3
- Prioritize: Fast signing
"""
SLHDSA_SHA2_256_SMALL = ('SHA2', _SLHDSA_256_S)
"""
SLH DSA parameter set

- Hash: SHA2
- Security category: 5
- Prioritize: Small signature
"""
SLHDSA_SHA2_256_FAST = ('SHA2', _SLHDSA_256_F)
"""
SLH DSA parameter set

- Hash: SHA2
- Security category: 5
- Prioritize: Fast signing
"""

SLHDSA_SHAKE_128_SMALL = ('SHKE2', _SLHDSA_128_S)
"""
SLH DSA parameter set

- Hash: SHAKE
- Security category: 1
- Prioritize: Small signature
"""
SLHDSA_SHAKE_128_FAST = ('SHAKE', _SLHDSA_128_F)
"""
SLH DSA parameter set

- Hash: SHAKE
- Security category: 1
- Prioritize: Fast signing
"""
SLHDSA_SHAKE_192_SMALL = ('SHKE2', _SLHDSA_192_S)
"""
SLH DSA parameter set

- Hash: SHAKE
- Security category: 3
- Prioritize: Small signature
"""
SLHDSA_SHAKE_192_FAST = ('SHAKE', _SLHDSA_192_F)
"""
SLH DSA parameter set

- Hash: SHAKE
- Security category: 3
- Prioritize: Fast signing
"""
SLHDSA_SHAKE_256_SMALL = ('SHKE2', _SLHDSA_256_S)
"""
SLH DSA parameter set

- Hash: SHAKE
- Security category: 5
- Prioritize: Small signature
"""
SLHDSA_SHAKE_256_FAST = ('SHAKE', _SLHDSA_256_F)
"""
SLH DSA parameter set

- Hash: SHAKE
- Security category: 5
- Prioritize: Fast signing
"""
