from __future__ import annotations

import numpy as np

from typing import Any, Callable

class MVector_type:
  """Base class for a module vector"""
  Q: int = 0
  """The modulus Q to use"""
  def __init__(self, np_array: np.typing.NDArray[Any], isntt = False):
    """
    A representation of a module vector

    Args:
      np_array (int[k][N]): NumPy array of the coefficients
      isntt (bool): Are the coefficients ntt representations
    """
    self.arr = np_array
    self.k, self.N = np_array.shape
    self.isntt = isntt
    raise NotImplementedError()

  @staticmethod
  def from_coefficients(coefficients: list[list[int]], isntt = False) -> MVector_type:
    """
    Construct a vector from a list of coefficients

    Args:
      coefficients (int[k][N]): The coefficients of the polynomials
    """
    raise NotImplementedError()

  @staticmethod
  def simpleNTT(n: np.typing.NDArray[Any]):
    raise NotImplementedError()

  def NTT(self) -> MVector_type:
    """
    Compute the NTT representation of this vector

    Returns:
      The NTT MVector

    Raises:
      ValueError: The vector is already NTT representation
    """
    raise NotImplementedError()

  @staticmethod
  def simpleInvNTT(n: np.typing.NDArray[Any]):
    """
    Perform an inverse NTT on a single polynomial

    This function **modifies** the original array

    Args:
      n (int[]) - The polynomial 1D NDArray
    """
    raise NotImplementedError()

  def invNTT(self) -> MVector_type:
    """
    Compute the inverse NTT of this vector

    Returns:
      The coefficient space MVector

    Raises:
      ValueError: The vector is not an NTT representation
    """
    raise NotImplementedError()

  def __mul__(self, other: np.typing.NDArray[Any] | int) -> MVector_type:
    """
    MVector multiplication

    For integers and polynomials, for MVec see __matmul__

    Args:
      other (int[] | int): The other operand (1D NDArray or constant)

    Returns:
      The result

    Raises:
      TypeError: Other operand is not a polynomial or a constant
      ValueError: MVector needs to be NTT to be multiplied with a polynomial
    """
    raise NotImplementedError()

  def __matmul__(self, other: MVector_type):
    """
    MVector-MVector multiplication

    For integers and polynomials see __mul__

    Args:
      other (MVector): The other MVector

    Returns:
      The result

    Raises:
      TypeError: Other operand is not an MVector
      ValueError: Both MVectors need to be NTTs to be multiplied
      IndexError: The rank of the module vectors is not the same
    """
    raise NotImplementedError()

  def __add__(self, other: MVector_type) -> MVector_type:
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
    raise NotImplementedError()

  def __sub__(self, other: MVector_type) -> MVector_type:
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
    raise NotImplementedError()

  def infinityNorm(self) -> int:
    """
    Return the max coefficient under centered_mod Q

    Returns:
      The largest abs coefficient in the MVector
    """
    raise NotImplementedError()

  def centered_modQ(self) -> MVector_type:
    """
    Return the result MVector with coefficients centered mod Q

    Returns:
      The result MVector with coefficients centered mod Q
    """
    raise NotImplementedError()


def MVector_Factory(
    modulus_q: int,
    simpleNTT: Callable[[np.typing.NDArray[Any]]],
    simpleInvNTT: Callable[[np.typing.NDArray[Any]]],
    mult_function: Callable[[np.typing.NDArray[Any], np.typing.NDArray[Any]], np.typing.NDArray[Any]] = lambda a, b: a * b
    ):
  """
  Factory for MVector classes

  Args:
    modulus_q (int): The Q to use
    simpleNTT ((int[]) -> None): Function performing NTT on a single polynomial
    simpleInvNTT ((int[]) -> None): Function performing invNTT on a single polynomial
    mult_function ((int[], int[]) -> int[]): The per-polynomial multiplication function to use

  Returns:
    The MVector class
  """
  class MVector(MVector_type):
    """Base class for a module vector"""
    Q: int = modulus_q
    """The modulus Q to use"""
    def __init__(self, np_array: np.typing.NDArray[Any], isntt = False):
      """
      A representation of a module vector

      Args:
        np_array (int[k][N]): NumPy array of the coefficients
        isntt (bool): Are the coefficients ntt representations
      """
      self.arr = np_array
      self.k, self.N = np_array.shape
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
      simpleNTT(n)

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
      simpleInvNTT(n)

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

    def __mul__(self, other: np.typing.NDArray[Any] | int) -> MVector:
      """
      MVector multiplication

      For integers and polynomials, for MVec see __matmul__

      Args:
        other (int[] | int): The other operand (1D NDArray or constant)

      Returns:
        The result

      Raises:
        TypeError: Other operand is not a polynomial or a constant
        ValueError: MVector needs to be NTT to be multiplied with a polynomial
      """
      if isinstance(other, type(self.arr)):
        if not self.isntt: raise ValueError('Self is not NTT and cannot be multiplied with a polynomial')
        new = self.arr.copy()
        new *= other
        new %= self.Q
        return MVector(new, isntt=True)
      elif isinstance(other, int):
        new = self.arr.copy()
        new *= other
        new %= self.Q
        return MVector(new, isntt=self.isntt)
      else:
        raise TypeError(f'Simple multiplication is not supported for MVector and {type(other).__class__.__name__}')

    def __matmul__(self, other: MVector):
      """
      MVector-MVector multiplication

      For integers and polynomials see __mul__

      Args:
        other (MVector): The other MVector

      Returns:
        The result

      Raises:
        TypeError: Other operand is not an MVector
        ValueError: Both MVectors need to be NTTs to be multiplied
        IndexError: The rank of the module vectors is not the same
      """
      if isinstance(other, type(self)):
        if not (self.isntt and other.isntt): raise ValueError('Both operands need to be NTTs to be multiplied')
        if self.k != other.k: raise IndexError('The rank of the module vectors is not the same')
        new = np.zeros((self.N,), dtype=np.int64)
        for i in range(self.k):
          new += mult_function(self.arr[i], other.arr[i])
          new %= self.Q
        return new
      else:
        raise TypeError(f'Matrix multiplication is not supported for MVector and {type(other).__class__.__name__}')

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
      if self.k != other.k: raise IndexError('The rank of the module vectors is not the same')
      new = (self.arr + other.arr) % self.Q
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
      if self.k != other.k: raise IndexError('The rank of the module vectors is not the same')
      new = (self.arr - other.arr) % self.Q
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
      mod = self.arr % self.Q
      return MVector(np.where(mod > ((self.Q-1) // 2), mod - self.Q, mod), isntt=self.isntt)
  return MVector
