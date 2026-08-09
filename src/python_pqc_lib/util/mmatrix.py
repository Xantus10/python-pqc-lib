from __future__ import annotations

import numpy as np

from typing import Any, Callable

from .mvector import MVector_type


class MMatrix_type:
  """A representation of a module matrix"""
  Q = 0
  """The modulus Q"""
  def __init__(self, np_array: np.typing.NDArray[Any]):
    """
    A representation of a module matrix

    Args:
      np_array (int[k][l][N]): NumPy array of the ntt matrix coefficients
    """
    self.arr = np_array
    self.k, self.l, self.N = np_array.shape
    raise NotImplementedError()

  @staticmethod
  def from_coefficients(coefficients: list[list[int]]) -> MMatrix_type:
    """
    Construct a matrix from a list of coefficients

    Args:
      coefficients (int[k][l][N]): The coefficients of the polynomials
    """
    raise NotImplementedError()

  def __matmul__(self, other: MVector_type) -> MVector_type:
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
    raise NotImplementedError()

  def transpose(self) -> MMatrix_type:
    """
    Transpose the matrix by the k x k axis

    Returns:
      The transposed MMatrix
    """
    raise NotImplementedError()


def MMatrix_Factory(
    modulus_q: int,
    MVector_class: Callable[[Any], MVector_type],
    mult_function: Callable[[np.typing.NDArray[Any], np.typing.NDArray[Any]], np.typing.NDArray[Any]] = lambda a, b: a * b
    ):
  """
  Factory for MMatrix classes

  Args:
    modulus_q (int): The Q to use
    MVector_class: The local MVector class implementation
    mult_function ((int[], int[]) -> int[]): The per-polynomial multiplication function to use

  Returns:
    The MMatrix class
  """
  class MMatrix:
    """A representation of a module matrix"""
    Q = modulus_q
    """The modulus Q"""
    def __init__(self, np_array: np.typing.NDArray[Any]):
      """
      A representation of a module matrix

      Args:
        np_array (int[k][l][N]): NumPy array of the ntt matrix coefficients
      """
      self.arr = np_array
      self.k, self.l, self.N = np_array.shape

    @staticmethod
    def from_coefficients(coefficients: list[list[int]]) -> MMatrix:
      """
      Construct a matrix from a list of coefficients

      Args:
        coefficients (int[k][l][N]): The coefficients of the polynomials
      """
      arr = np.array(coefficients, dtype=np.int64)
      return MMatrix(arr)

    def __matmul__(self, other: MVector_type) -> MVector_type:
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
      if not isinstance(other, MVector_type): raise TypeError(f'Matrix multiplication is not supported for MMatrix and {type(other).__class__.__name__}')
      if not other.isntt: raise ValueError('The vector needs to be NTT to allow multiplication')
      if self.l != other.k: raise IndexError('The rank is not the same')
      new = np.zeros((self.k, self.N), dtype=np.int64)
      for i in range(self.k):
        for j in range(self.l):
          new[i] += mult_function(self.arr[i, j], other.arr[j])
          new[i] %= self.Q
      return MVector_class(new, isntt=True)

    def transpose(self) -> MMatrix:
      """
      Transpose the matrix by the k x k axis

      Returns:
        The transposed MMatrix
      """
      trans_arr = np.transpose(self.arr, (1, 0, 2))
      return MMatrix(trans_arr)
  return MMatrix
