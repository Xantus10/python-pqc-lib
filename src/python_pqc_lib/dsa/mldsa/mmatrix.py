import numpy as np

from typing import Any

from .constants import Q
from .mvector import MVector

class MMatrix:
  """A representation of a module matrix"""
  def __init__(self, np_array: np.typing.NDArray[Any]):
    """
    A representation of a module matrix

    Args:
      np_array (int[k][l][N]): NumPy array of the ntt matrix coefficients
    """
    self.arr = np_array
    self.k, self.l, _ = np_array.shape

  @staticmethod
  def from_coefficients(coefficients: list[list[int]]) -> 'MMatrix':
    """
    Construct a matrix from a list of coefficients

    Args:
      coefficients (int[k][l][N]): The coefficients of the polynomials
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
      if self.l != len(other.arr): raise IndexError('The rank is not the same')
      new = np.zeros((self.k, 256), dtype=np.int64)
      for i in range(self.k):
        for j in range(self.l):
          new[i] += self.arr[i, j] * other.arr[j]
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
