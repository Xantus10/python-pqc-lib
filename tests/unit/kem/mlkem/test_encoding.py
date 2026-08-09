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
]

@pytest.mark.parametrize(['B', 'b'], bytes_bits_tuples)
def test_B2b(B: bytes, b: list[int]):
  assert bytes_to_bits(B) == b

@pytest.mark.parametrize(['b', 'B'], [(v[1], v[0]) for v in bytes_bits_tuples])
def test_b2B(b: list[int], B: bytes):
  assert bits_to_bytes(b) == B

### Exception tests



### Round trip tests


