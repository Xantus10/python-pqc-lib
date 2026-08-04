import numpy as np

from typing import Any

from .constants import N, Q
from .math_helper import multiplyNTTs
from .mvector import MVector

class MMatrix:
  """A representation of a module matrix"""
  def __init__(self, np_array: np.typing.NDArray[Any]):
    """
    A representation of a module matrix

    Args:
      np_array (int[k][k][N]): NumPy array of the ntt matrix coefficients
    """
    self.arr = np_array

  @staticmethod
  def from_coefficients(coefficients: list[list[int]]) -> 'MMatrix':
    """
    Construct a matrix from a list of coefficients

    Args:
      coefficients (int[k][k][N]): The coefficients of the polynomials
    """
    arr = np.array(coefficients, dtype=np.int64)
    return MMatrix(arr)

  def __matmul__(self, other: 'MVector') -> 'MVector':
      """
      MMatrix-MVector multiplication
  
      Args:
        other (MVector): The vector
  
      Returns:
        A new result vector
  
      Raises:
        TypeError: Other operand is not of type MVector
        ValueError: The vector needs to be NTT to allow multiplication
        IndexError: The rank is not the same
      """
      if not isinstance(other, MVector): raise TypeError(f'Matrix multiplication is not supported for MMatrix and {type(other).__class__.__name__}')
      if not other.isntt: raise ValueError('The vector needs to be NTT to allow multiplication')
      k = len(other.arr)
      if len(self.arr[0]) != k: raise IndexError('The rank is not the same')
      new = np.zeros((k, N), dtype=np.int64)
      for i in range(k):
        for j in range(k):
          new[i] += multiplyNTTs(self.arr[i, j], other.arr[j])
          new[i] %= Q
      return MVector(new, isntt=True)

  def transpose(self) -> 'MMatrix':
    """
    Transpose the matrix by the k x k axis

    Returns:
      The transposed MMatrix
    """
    trans_arr = np.transpose(self.arr, (1, 0, 2))
    return MMatrix(trans_arr)
