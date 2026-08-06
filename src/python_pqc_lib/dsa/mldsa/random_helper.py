import numpy as np

from hashlib import shake_128 as g, shake_256 as h

from .encoding import bitUnpack, bytes_to_bits, coeffFromHalfByte, coeffFromThreeBytes
from .xof import XOF


def sampleInBall(seed: bytes, tau: int):
  """
  Sample a random polynomial with coefficients -1...1

  Args:
    seed (bytes): The seed to use for generation
    tau (int): The hamming weight (<=64)

  Returns:
    NDArray of the coefficients
  """
  ret = np.zeros((256,), dtype=np.int64)
  xof = XOF(h(seed))
  signs = bytes_to_bits(xof.Squeeze(8))
  for i in range(256 - tau, 256):
    j = xof.Squeeze(1)
    while j > i:
      xof.Squeeze(1)
    ret[i] = ret[j]
    ret[j] = pow(-1, signs[i + tau - 256])
  return ret

def sampleMatrixPol(seed: bytes, inp_j: int, inp_i: int):
  """
  Sample a random polynomial with coefficients 0...q-1

  Args:
    seed (bytes): The seed to use for generation
    inp_j (int): The second coord of the loop (inner)
    inp_i (int): The first coord of the loop (outer)

  Returns:
    NDArray of the coefficients
  """
  ret = np.zeros((256,), dtype=np.int64)
  xof = XOF(g(seed + inp_j.to_bytes() + inp_i.to_bytes()))
  i = 0
  while i < 256:
    cand = coeffFromThreeBytes(xof.Squeeze(3))
    if not cand is None:
      ret[i] = cand
      i += 1
  return ret

def sampleSmallPolynomial(seed: bytes, uniq2B: int, eta: int):
  """
  Sample a random polynomial with coefficients -eta...eta

  Args:
    seed (bytes): The seed to use for generation
    uniq2B (int): A 2 Byte unique value
    eta (int): The range for the generation

  Returns:
    NDArray of the coefficients
  """
  ret = np.zeros((256,), dtype=np.int64)
  xof = XOF(g(seed + uniq2B.to_bytes(2, byteorder='little')))
  i = 0
  while i < 256:
    b = xof.Squeeze(1)
    z1 = coeffFromHalfByte(b[0] % 16, eta)
    z2 = coeffFromHalfByte(b[0] // 16, eta)
    if not z1 is None:
      ret[i] = z1
      i += 1
    if not z2 is None and i < 256:
      ret[i] = z2
      i += 1
  return ret

def expandMask(seed: bytes, gamma1: int, l: int, uniq: int):
  """
  Sample a random polynomial with coefficients -gamma+1...gamma

  Args:
    seed (bytes): The seed to use for generation
    gamma1 (int): The range for the mask
    l (int): Order of the MVector
    uniq (int): A unique value

  Returns:
    2D NDArray of the coefficients
  """
  ret = np.zeros((l,256), dtype=np.int64)
  xof = XOF(g(seed))
  bit_len = 1 + ((gamma1-1).bit_length())
  rank = 0
  for rank in range(l):
    vals = h(seed + (uniq + rank).to_bytes(2, byteorder='little')).digest(32 * bit_len)
    ret[rank] = bitUnpack(vals, -gamma1 + 1, gamma1)
  return ret
