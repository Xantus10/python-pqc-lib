"""
Math functions for ML KEM
"""

from numpy.typing import NDArray

from typing import Any

from .constants import N, Q, ZETA2


def multiplyNTTs(pol1: NDArray[Any], pol2: NDArray[Any]) -> list[int]:
  """
  Multiply NTT polynomials

  Args:
    pol1 (int[N]): First ntt polynomial
    pol2 (int[N]): Second ntt polynomial

  Returns:
    The result ntt polynomial coefficients
  """
  def _baseCaseMultiply(a0, a1, b0, b1, gamma):
    return (a0 * b0 + a1 * b1 * gamma) % Q, (a0 * b1 + a1 * b0) % Q

  new = [0 for _ in range(N)]

  for i in range(0, 256, 2):
    new[i], new[i+1] = _baseCaseMultiply(pol1[i], pol1[i+1], pol2[i], pol2[i+1], ZETA2[i//2])

  return new
