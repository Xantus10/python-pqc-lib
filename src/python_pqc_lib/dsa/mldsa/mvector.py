from __future__ import annotations

import numpy as np

from typing import Any

from .constants import Q, ZETA

class MVector:
  """A representation of a module vector"""
  def __init__(self, np_array: np.typing.NDArray[Any], isntt = False):
    """
    A representation of a module vector

    Args:
      np_array (int[k][N]): NumPy array of the coefficients
      isntt (bool): Are the coefficients ntt representations
    """
    self.arr = np_array
    self.isntt = isntt

  @staticmethod
  def from_coefficients(coefficients: list[list[int]], isntt = False) -> MVector:
    """
    Construct a vector from a list of coefficients

    Args:
      coefficients (int[k][N]): The coefficients of the polynomials
    """
    arr = np.array(coefficients, dtype=np.int64)
    return MVector(arr, isntt)

  @staticmethod
  def simpleNTT(n: np.typing.NDArray[Any]):
    """
    Perform NTT on a single polynomial

    This function **modifies** the original array

    Args:
      n (int[]) - The polynomial 1D NDArray
    """
    i = 0
    ln = 128
    while ln >= 1: # in ML KEM this is 2, so that we have incomplete NTT
      start = 0
      while start < 256:
        i += 1
        zeta = ZETA[i]
        for j in range(start, start + ln):
          t = (zeta * n[j + ln]) % Q
          n[j + ln] = (n[j] - t) % Q
          n[j] = (n[j] + t) % Q
        start += 2*ln
      ln //= 2

  def NTT(self) -> MVector:
    """
    Compute the NTT representation of this vector

    Returns:
      The NTT MVector

    Raises:
      ValueError: The vector is already NTT representation
    """
    if self.isntt: raise ValueError('Vector is already an NTT representation')
    

    ntt = self.arr.copy()
    for n in ntt:
      MVector.simpleNTT(n)
    return MVector(ntt, isntt=True)

  @staticmethod
  def simpleInvNTT(n: np.typing.NDArray[Any]):
    """
    Perform an inverse NTT on a single polynomial

    This function **modifies** the original array

    Args:
      n (int[]) - The polynomial 1D NDArray
    """
    i = 256
    ln = 1
    while ln < 256:
      start = 0
      while start < 256:
        i -= 1
        zeta = ZETA[i]
        for j in range(start, start + ln):
          t = n[j]
          n[j] = (n[j + ln] + t) % Q
          n[j + ln] = (zeta * ((n[j + ln] - t) % Q)) % Q
        start += 2*ln
      ln *= 2
    n *= 8347681
    n %= Q

  def invNTT(self) -> MVector:
    """
    Compute the inverse NTT of this vector

    Returns:
      The coefficient space MVector

    Raises:
      ValueError: The vector is not an NTT representation
    """
    if not self.isntt: raise ValueError('Vector is not an NTT representation')

    invntt = self.arr.copy()
    for n in invntt:
      MVector.simpleInvNTT(n)
    return MVector(invntt, isntt=False)

  def __mul__(self, other: MVector | np.typing.NDArray[Any] | int) -> np.typing.NDArray[Any] | MVector:
    """
    MVector multiplication

    MVec * MVec = Pol

    MVec * Pol = MVec

    Args:
      other (MVector | int[] | int): The other operand (MVector or 1D NDArray or constant)

    Returns:
      The result

    Raises:
      TypeError: Other operand is not of type MVector or a polynomial or a constant
      ValueError: Both operands need to be NTTs to be multiplied
      IndexError: The rank of the module vectors is not the same
    """
    if isinstance(other, type(self)):
      if not (self.isntt and other.isntt): raise ValueError('Both operands need to be NTTs to be multiplied')
      k = len(self.arr)
      if k != len(other.arr): raise IndexError('The rank of the module vectors is not the same')
      new = np.zeros((256,), dtype=np.int64)
      for i in range(k):
        new += self.arr[i] * other.arr[i]
      return new
    elif isinstance(other, type(self.arr)):
      if not self.isntt: raise ValueError('Self is not NTT and cannot be multiplied')
      new = self.arr.copy()
      for i in range(len(new)): # Its an NDArray, I think the loop might be unnecessary
        new[i] *= other
      return MVector(new, isntt=True)
    elif isinstance(other, int):
      new = self.arr.copy()
      for i in range(len(new)):
        new[i] *= other
      return MVector(new, isntt=self.isntt)
    else:
      raise TypeError(f'Multiplication is not supported for MVector and {type(other).__class__.__name__}')

  def __add__(self, other: MVector) -> MVector:
    """
    MVector-MVector addition

    Args:
      other (MVector): The other vector

    Returns:
      A new result vector

    Raises:
      TypeError: Other operand is not of type MVector
      ValueError: Both operands need to be either NTT or coefficient form
      IndexError: The rank of the module vectors is not the same
    """
    if not isinstance(other, type(self)): raise TypeError(f'Addition is not supported for MVector and {type(other).__class__.__name__}')
    if not (self.isntt == other.isntt): raise ValueError('Both operands need to be in the same domain (NTT vs coefficient)')
    k = len(self.arr)
    if k != len(other.arr): raise IndexError('The rank of the module vectors is not the same')
    new = (self.arr + other.arr) % Q
    return MVector(new, isntt=self.isntt)

  def __sub__(self, other: MVector) -> MVector:
    """
    MVector-MVector subtraction

    Args:
      other (MVector): The other vector

    Returns:
      A new result vector

    Raises:
      TypeError: Other operand is not of type MVector
      ValueError: Both operands need to be either NTT or coefficient form
      IndexError: The rank of the module vectors is not the same
    """
    if not isinstance(other, type(self)): raise TypeError(f'Subtraction is not supported for MVector and {type(other).__class__.__name__}')
    if not (self.isntt == other.isntt): raise ValueError('Both operands need to be in the same domain (NTT vs coefficient)')
    k = len(self.arr)
    if k != len(other.arr): raise IndexError('The rank of the module vectors is not the same')
    new = (self.arr - other.arr) % Q
    return MVector(new, isntt=self.isntt)

  def infinityNorm(self) -> int:
    """
    Return the max coefficient under centered_mod Q

    Returns:
      The largest abs coefficient in the MVector
    """
    centered = self.centered_modQ()
    return int(np.max(np.abs(centered.arr)))

  def centered_modQ(self) -> MVector:
    """
    Return the result MVector with coefficients centered mod Q

    Returns:
      The result MVector with coefficients centered mod Q
    """
    mod = self.arr % Q
    return MVector(np.where(mod > ((Q-1) // 2), mod - Q, mod), isntt=self.isntt)
