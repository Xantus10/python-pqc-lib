"""
Various encoding and compression mechanisms used by ML KEM
"""

import numpy as np

from typing import Any

from .constants import Q


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

