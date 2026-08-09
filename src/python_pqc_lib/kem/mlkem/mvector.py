import numpy as np

from typing import Any

from ...util.mvector import MVector_Factory, MVector_type

from .constants import N, Q, ZETA, ZETA2


def simpleNTT(n: np.typing.NDArray[Any]):
  """
  Perform NTT on a single polynomial

  This function **modifies** the original array

  Args:
    n (int[]) - The polynomial 1D NDArray
  """
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

def simpleInvNTT(n: np.typing.NDArray[Any]):
    """
    Perform an inverse NTT on a single polynomial

    This function **modifies** the original array

    Args:
      n (int[]) - The polynomial 1D NDArray
    """
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

def multiplyNTTs(pol1: np.typing.NDArray[Any], pol2: np.typing.NDArray[Any]) -> np.typing.NDArray[Any]:
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

  new = np.zeros((N,), dtype=np.int64)

  for i in range(0, 256, 2):
    new[i], new[i+1] = _baseCaseMultiply(pol1[i], pol1[i+1], pol2[i], pol2[i+1], ZETA2[i//2])

  return new


MVector = MVector_Factory(Q, simpleNTT, simpleInvNTT, multiplyNTTs)
