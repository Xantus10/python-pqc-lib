import numpy as np

from typing import Any

from .constants import Q, ZETA
from .math_helper import multiplyNTTs

class MVector:
  """A representation of a module vector"""
  def __init__(self, np_array: np.typing.NDArray[Any], isntt = False):
    """
    A representation of a module vector
    """
    self.arr = np_array
    self.isntt = isntt

  @staticmethod
  def from_coefficients(coefficients: list[list[int]], isntt = False) -> 'MVector':
    """
    Construct a vector from a list of coefficients

    Args:
      coefficients (int[][]): The coefficients of the polynomials
    """
    arr = np.array(coefficients, dtype=np.int64)
    return MVector(arr, isntt)

  def NTT(self) -> 'MVector':
    """
    Compute the NTT representation of this vector

    Returns:
      The NTT MVector

    Raises:
      ValueError: The vector is already NTT representation
    """
    if self.isntt: raise ValueError('Vector is already an NTT representation')
    def _singleNTT(n: np.typing.NDArray[Any]):
      i = 1
      ln = 128
      while ln >= 2:
        start = 0
        while start < 256:
          zeta = ZETA[i]
          i += 1
          for j in range(start, start + ln):
            t = (zeta * n[j + ln]) % Q
            n[j + ln] = (n[j] - t) % Q
            n[j] = (n[j] + t) % Q
          start += 2*ln
        ln //= 2

    ntt = self.arr.copy()
    for n in ntt:
      _singleNTT(n)
    return MVector(ntt, isntt=True)

  def invNTT(self) -> 'MVector':
    """
    Compute the inverse NTT of this vector

    Returns:
      The coefficient space MVector

    Raises:
      ValueError: The vector is not an NTT representation
    """
    if not self.isntt: raise ValueError('Vector is not an NTT representation')
    def _singleInvNTT(n: np.typing.NDArray[Any]):
      i = 127
      ln = 2
      while ln <= 128:
        start = 0
        while start < 256:
          zeta = ZETA[i]
          i -= 1
          for j in range(start, start + ln):
            t = n[j]
            n[j] = (n[j + ln] + t) % Q
            n[j + ln] = (zeta * (n[j + ln] - t)) % Q
          start += 2*ln
        ln *= 2
      for i in range(len(n)):
        n[i] *= 3303
        n[i] %= Q

    invntt = self.arr.copy()
    for n in invntt:
      _singleInvNTT(n)
    return MVector(invntt, isntt=False)

  def __mul__(self, other: 'MVector') -> 'MVector':
    """
    MVector-MVector multiplication

    Args:
      other (MVector): The other vector

    Returns:
      A new result vector

    Raises:
      TypeError: Other operand is not of type MVector
      ValueError: Both operands need to be NTTs to be multiplied
      IndexError: The rank of the module vectors is not the same
    """
    if not isinstance(other, type(self)): raise TypeError(f'Multiplication is not supported for MVector and {type(other).__class__.__name__}')
    if not (self.isntt and other.isntt): raise ValueError('Both operands need to be NTTs to be multiplied')
    if len(self.arr) != len(other.arr): raise IndexError('The rank of the module vectors is not the same')
    res = []
    for i in range(len(self.arr)):
      res.append(multiplyNTTs(self.arr[i], other.arr[i]))
    return MVector.from_coefficients(res, isntt=True)

