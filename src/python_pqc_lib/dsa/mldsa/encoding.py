"""Encoding an type conversion functions"""

import numpy as np

from .constants import Q

from typing import Any

def int_to_bits(x: int, bit_len: int = 8) -> list[int]:
  """
  Convert an integer to a bit array of len bit_len

  Args:
    x (int): Integer to convert
    bit_len (int): The length of the result

  Returns:
    An array of 0/1 values
  """
  ret = [0 for _ in range(bit_len)]
  for i in range(bit_len):
    ret[i] = x % 2
    x //= 2
  return ret

def bits_to_int(x: list[int]) -> int:
  """
  Convert a bit array to integer

  Args:
    x (int[]): Integer array to convert

  Returns:
    The result integer
  """
  ret = 0
  for i in range(1, len(x)+1):
    ret = 2*ret + x[len(x) - i]
  return ret

def bytes_to_bits(data: bytes) -> list[int]: # Same as ML KEM
  """
  Return a bit string of the data bytes

  Args:
    data (bytes): The data

  Returns:
    An array of 0/1 integers based on the bits
  """
  bits = []
  for byte in data:
    for i in range(8):
      bits.append((byte >> i) & 1)
  return bits

def bits_to_bytes(data: list[int]) -> bytes: # Same as ML KEM
  """
  Return a byte string of the data bits

  Args:
    data (bits): The data

  Returns:
    A byte string of the bits
  """
  ret = bytearray()
  for i in range(0, len(data), 8):
    cur_byte = 0
    for j in range(8):
      cur_byte |= data[i+j] << j
    ret.append(cur_byte)

  return bytes(ret)


def coeffFromThreeBytes(b: bytes) -> int | None:
  """
  Create an integer coefficient in range 0...q-1 from three byte values

  Args:
    b (bytes): 3 bytes

  Returns:
    The generated integer or None
  """
  b2 = b[2]
  if b2 > 127: b2 -= 128
  z = 65536 * b2 + 256 * b[1] + b[0]
  if z < Q: return z
  return None

def coeffFromHalfByte(b: int, eta: int) -> int | None:
  """
  Create an integer coefficient in range -eta...eta from three byte values

  Args:
    b (int): The integer in range 0...15
    eta (int): Range for the generation

  Returns:
    The generated integer or None
  """
  if eta == 2 and b < 15: return 2 - (b % 5)
  if eta == 4 and b < 9: return 4 - b
  return None


def simpleBitPack(pol: np.typing.NDArray[Any], range_high: int) -> bytes:
  """
  Encode a polynomial into bytes

  Args:
    pol (int[]): The polynomial to encode
    range_high (int): All coefficients must be in range 0...range_high

  Returns:
    The bytes representing the polynomial
  """
  bit_len = range_high.bit_length()
  return bits_to_bytes([bit for i in pol for bit in int_to_bits(i, bit_len)])

def bitPack(pol: np.typing.NDArray[Any], range_low: int, range_high: int) -> bytes:
  """
  Encode a polynomial into bytes

  Args:
    pol (int[]): The polynomial to encode
    range_low (int): The lowest possible value in pol (negative)
    range_high (int): The largest possible value in pol (positive)

  Returns:
    The bytes representing the polynomial
  """
  bit_len = (-range_low + range_high).bit_length()
  return bits_to_bytes([bit for i in pol for bit in int_to_bits(range_high - i, bit_len)])

def simpleBitUnpack(b: bytes, range_high: int) -> np.typing.NDArray[Any]:
  """
  Decode polynomial coefficients from bytes

  Args:
    b (bytes): The byte representation of the polynomial
    range_high (int): All coefficients must be in range 0...range_high

  Returns:
    NDArray representing the polynomial
  """
  bit_len = range_high.bit_length()
  z = bytes_to_bits(b)
  ret = np.array([bits_to_int(z[i * bit_len:(i+1) * bit_len]) for i in range(256)], np.int64)
  return ret

def bitUnpack(b: bytes, range_low: int, range_high: int) -> np.typing.NDArray[Any]:
  """
  Decode polynomial coefficients from bytes

  Args:
    b (bytes): The byte representation of the polynomial
    range_low (int): The lowest possible value in pol (negative)
    range_high (int): The largest possible value in pol (positive)

  Returns:
    NDArray representing the polynomial
  """
  bit_len = (-range_low + range_high).bit_length()
  z = bytes_to_bits(b)
  ret = np.array([bits_to_int(z[i * bit_len:(i+1) * bit_len]) for i in range(256)], np.int64)
  ret *= -1
  ret += range_high
  return ret


def hintBitPack(h: np.typing.NDArray[Any], omega: int) -> bytes:
  """
  BitPack a hint MVector efficiently

  Args:
    h (int[k][N]): The hint MVector
    omega (int): How many non-zero coefficients (at most) are in h

  Returns:
    The hint encoded in bytes
  """
  ret = bytearray(omega + len(h))
  ix = 0
  for i in range(len(h)):
    for j in range(256):
      if h[i, j] != 0:
        ret[ix] = j
        ix += 1
    ret[omega + i] = ix
  return bytes(ret)

def hintBitUnpack(b: bytes, k: int, omega: int) -> np.typing.NDArray[Any]:
  """
  BitPack a hint MVector efficiently

  Args:
    b (bytes): The encoded hint
    k (int): Rank of the result MVector
    omega (int): How many non-zero coefficients (at most) are in hint

  Returns:
    Hint NDArray with coefficients

  Raises:
    IndexError: The bytes input is malformed / incorrectly formatted
  """
  ret = np.zeros((k, 256), dtype=np.int64)
  ix = 0
  for i in range(k):
    if b[omega + i] < ix or b[omega + i] > omega: raise IndexError('Malformed bytes input for hint')
    first = ix
    while ix < b[omega + i]:
      if ix > first:
        if b[ix - 1] >= b[ix]: raise IndexError('Malformed bytes input for hint')
      ret[i, b[ix]] = 1
      ix += 1
  for i in range(ix, omega):
    if b[i] != 0: raise IndexError('Malformed bytes input for hint')
  return ret


def centered_mod(x: int, q: int):
  """
  Compute a x % q with result in range -q/2...q/2

  Args:
    x (int): The number
    q (int): The modulo

  Returns:
    The remainder centered around 0
  """
  res = x % q
  if res > (q-1) // 2:
    res -= q
  return res

def power2Round(r: int, d: int) -> tuple[int, int]:
  """
  Decompose an integer into two parts - multiplier and constant

  Args:
    r (int): The integer to decompose
    d (int): Number of bits

  Returns:
    A multiplier and a constant so that r = m * 2**d + c
  """
  r_pos = r % Q
  r0 = centered_mod(r_pos, 2**d)
  return (r_pos - r0) // (2**d), r0

def power2RoundVec(r: np.typing.NDArray[Any], d: int) -> tuple[np.typing.NDArray[Any], np.typing.NDArray[Any]]:
  """
  Apply the power2Round function to all numbers in an NDArray and return the mult and const arrays

  Args:
    r (int[k][N]): The 2D MVector NDArray
    d (int): Number of bits

  Returns:
    Two new NDArrays mult[] and const[]
  """
  mult = np.zeros(r.shape, dtype=np.int64)
  const = np.zeros(r.shape, dtype=np.int64)
  for i in range(r.shape[0]):
    for j in range(r.shape[1]):
      mult[i, j], const[i, j] = power2Round(r[i, j], d)
  return mult, const

def decompose(r: int, gamma2: int) -> tuple[int, int]:
  """
  Decompose an integer into two parts - multiplier and constant

  Args:
    r (int): The integer to decompose
    gamma2 (int): The multiplier part

  Returns:
    A multiplier and a constant so that r = m * 2gamma + c
  """
  r_pos = r % Q
  r0 = centered_mod(r_pos, 2 * gamma2)
  if r_pos - r0 == Q - 1:
    r1 = 0
    r0 -= 1
  else:
    r1 = (r_pos - r0) // (2 * gamma2)
  return r1, r0

def highBits(r: int, gamma2: int) -> int:
  """
  Return the mult part of decompose

  Args:
    r (int): The integer to decompose
    gamma2 (int): Rounding range

  Returns:
    The mult part of decompose
  """
  return decompose(r, gamma2)[0]

def lowBits(r: int, gamma2: int) -> int:
  """
  Return the const part of decompose

  Args:
    r (int): The integer to decompose
    gamma2 (int): Rounding range

  Returns:
    The const part of decompose
  """
  return decompose(r, gamma2)[1]


def makeHint(to_add: int, base: int, gamma2: int) -> bool:
  """
  Find whether adding to_add will change the high bits of base

  Args:
    to_add (int): Number to add
    base (int): Number whose high bits are examined
    gamma2 (int): Rounding range

  Returns:
    True when the high bits change
  """
  base_high = highBits(base, gamma2)
  res_high = highBits(base + to_add, gamma2)
  return base_high != res_high

def useHint(hint: bool, r: int, gamma2: int):
  """
  Return the high bits of r, adjusted based on hint

  Args:
    hint (bool): Result of makeHint
    r (int): Number to act on
    gamma2 (int): Rounding range

  Returns:
    Adjusted high bits of r
  """
  mod = (Q - 1) // (2 * gamma2)
  r1, r0 = decompose(r, gamma2)
  if hint and r0 > 0: return (r1 + 1) % mod
  if hint and r0 <= 0: return (r1 - 1) % mod
  return r1

