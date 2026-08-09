from __future__ import annotations

import numpy as np

from typing import Any

from ...util.mvector import MVector_Factory, MVector_type

from .constants import Q, ZETA

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

MVector = MVector_Factory(Q, simpleNTT, simpleInvNTT)
