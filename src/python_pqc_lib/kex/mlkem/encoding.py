"""
Various encoding and compression mechanisms used by ML KEM
"""

import numpy as np

from typing import Any

from .constants import N, Q

def bytes_to_bits(data: bytes) -> list[int]:
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

def bits_to_bytes(data: list[int]) -> bytes:
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


def compress(x: int | np.typing.NDArray[Any], d: int) -> int | np.typing.NDArray[Any]:
  """
  Compress an integer x down to d-bits

  Args:
    x (int | int[]): The integer from range Q we want to compress (or a numpy ndarray)
    d (int): How many target bits should the int fit into

  Returns:
    The compressed integer (or int[])
  """
  d_two = 1 << d
  compressed = (2 * d_two * x + Q) // (2 * Q)
  return compressed % d_two

def decompress(x: int | np.typing.NDArray[Any], d: int) -> int | np.typing.NDArray[Any]:
  """
  Decompress an integer x from d-bits

  Args:
    x (int | int[]): The integer from range Q we want to decompress (or a numpy ndarray)
    d (int): How many bits is the integer

  Returns:
    The decompressed integer (or int[])
  """
  d_two = 1 << d
  decompressed = (2 * Q * x + d_two) // (2 * d_two)
  return decompressed


def byte_encode(arr: np.typing.NDArray[Any], d: int) -> bytes:
  """
  Encode a 1D array of ints into bytes

  The integers are supposed to be mod 2**d (or mod q for d==12)

  Args:
    arr (int[]): The input array
    d (int): How many bits one integer takes up

  Returns:
    A byte string representation of the input array
  """
  b = [0 for _ in range(len(arr) * d)]
  for i in range(len(arr)):
    num = arr[i]
    for j in range(d):
      b[i * d + j] = num % 2
      num = (num - b[i * d + j]) // 2
  return bits_to_bytes(b)

def byte_decode(b: bytes, d: int) -> list[int]:
  """
  Decode the integers into an 1D array

  The integers are supposed to be mod 2**d (or mod q for d==12)

  Args:
    b (bytes): The input array
    d (int): How many bits one integer takes up

  Returns:
    A list of integers
  """
  bits = bytes_to_bits(b)
  m = Q if d == 12 else 2**d
  ret = [0 for _ in range(N)]
  for i in range(N):
    for j in range(d):
      ret[i] += bits[i * d + j] * (2**j)
    ret[i] %= m
  return ret
