import pytest

from python_pqc_lib.kem.mlkem.encoding import *

### Standard Unit tests

bytes_bits_tuples = [
  (b'\x00', [0, 0, 0, 0, 0, 0, 0, 0]),
  (b'\x01', [1, 0, 0, 0, 0, 0, 0, 0]),
  (b'\x02', [0, 1, 0, 0, 0, 0, 0, 0]),
  (b'\x0f', [1, 1, 1, 1, 0, 0, 0, 0]),
  (b'\x10', [0, 0, 0, 0, 1, 0, 0, 0]),
  (b'\x11', [1, 0, 0, 0, 1, 0, 0, 0]),
  (b'\xff', [1, 1, 1, 1, 1, 1, 1, 1]),
  (b'\x00\x00', [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
  (b'\x01\x00', [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
  (b'\x00\x01', [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
  (b'\xff\xff', [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
  (b'', [])
]

@pytest.mark.parametrize(['B', 'b'], bytes_bits_tuples)
def test_B2b(B: bytes, b: list[int]):
  assert bytes_to_bits(B) == b

@pytest.mark.parametrize(['b', 'B'], [(v[1], v[0]) for v in bytes_bits_tuples])
def test_b2B(b: list[int], B: bytes):
  assert bits_to_bytes(b) == B


compression_identity = [
  (0, 0),
  (1, 1),
  (2, 2),
  (3, 4),
  (4, 5),
  (5, 6),
  (6, 7),
  (7, 9),
  (1000, 1230),
  (1664, 2047),
  (1665, 2049),
  (2000, 2461),
  (3327, 4094),
  (3328, 4095)
]

@pytest.mark.parametrize(['raw', 'c'], compression_identity)
def test_compress_identity(raw: int, c: int):
  assert compress(raw, 12) == c

@pytest.mark.parametrize(['raw', 'c'], [(v[1], v[0]) for v in compression_identity])
def test_decompress_identity(raw: int, c: int):
  assert decompress(raw, 12) == c

compression_lossy = {
  11: [
    (0, 0), (1, 1), (2, 1), (3, 2), (4, 2),
    (5, 3), (6, 4), (7, 4), (1000, 615),
    (1664, 1024), (1665, 1024), (2000, 1230),
    (3327, 2047), (3328, 2047)
  ],
  10: [
    (0, 0), (1, 0), (2, 1), (3, 1), (4, 1),
    (5, 2), (6, 2), (7, 2), (1000, 308),
    (1664, 512), (1665, 512), (2000, 615),
    (3327, 1023), (3328, 0)
  ],
  5: [
    (0, 0), (1, 0), (2, 0), (3, 0), (4, 0),
    (5, 0), (6, 0), (7, 0), (52, 0), (53, 1),
    (1000, 10), (1664, 16), (1665, 16),
    (2000, 19), (3327, 0), (3328, 0)
  ],
  4: [
    (0, 0), (1, 0), (2, 0), (3, 0), (4, 0),
    (5, 0), (6, 0), (7, 0), (104, 0), (105, 1),
    (1000, 5), (1664, 8), (1665, 8),
    (2000, 10), (3327, 0), (3328, 0)
  ]
}

@pytest.mark.parametrize(['raw', 'd', 'c'],
                         [(v[0], k, v[1]) for k, val_list in compression_lossy.items() for v in val_list])
def test_compress_lossy(raw: int, d: int, c: int):
  assert compress(raw, d) == c

decompression_lossy = {
  11: [
    (0, 0), (1, 2), (2, 3), (3, 5), (4, 7),
    (615, 1000), (1024, 1665), (1230, 1999),
    (2047, 3327)
  ],
  10: [
    (0, 0), (1, 3), (2, 7), (308, 1001),
    (512, 1665), (615, 1999), (1023, 3326)
  ],
  5: [
    (0, 0), (1, 104), (10, 1040), (16, 1665),
    (19, 1977), (31, 3225)
  ],
  4: [
    (0, 0), (1, 208), (5, 1040), (8, 1665),
    (10, 2081), (15, 3121)
  ]
}

@pytest.mark.parametrize(['raw', 'd', 'c'],
                         [(v[0], k, v[1]) for k, val_list in decompression_lossy.items() for v in val_list])
def test_decompress_lossy(raw: int, d: int, c: int):
  assert decompress(raw, d) == c

### Exception tests



### Round trip tests




compress_max_errors = {
  1: 833,   # d = 1 (Message bits)
  4: 105,   # d = 4 (v for ML-KEM-512/768)
  5: 53,    # d = 5 (v for ML-KEM-1024)
  10: 2,    # d = 10 (u for ML-KEM-512/768)
  11: 1,    # d = 11 (u for ML-KEM-1024)
}

def modular_distance(x: int, y: int) -> int:
  diff = abs(x - y) % Q
  return min(diff, Q - diff)

