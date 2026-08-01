from hashlib import shake_128

from .constants import Q, N, MATRIX_SAMPLE_BOUND

_MATRIX_GEN_XOF_STEP_SIZE = 99

def generateMatrixPolynomial(rho: bytes, inp_j: int, inp_i: int):
  """
  Generate coefficients of the matrix polynomial

  Args:
    rho (bytes): The matrix seed
    inp_j (int): The second coord of the loop (inner)
    inp_i (int): The first coord of the loop (outer)
  """
  seed = rho + inp_j.to_bytes() + inp_i.to_bytes()
  xof = shake_128(seed)
  xof_ix = 0
  safety_index = 0
  ret = []
  while len(ret) < N:
    cur_bytes = xof.digest(xof_ix + _MATRIX_GEN_XOF_STEP_SIZE)[xof_ix:]
    xof_ix += _MATRIX_GEN_XOF_STEP_SIZE
    i = 0
    while i < _MATRIX_GEN_XOF_STEP_SIZE:
      d1 = cur_bytes[i] + 256 * (cur_bytes[i+1] % 16)
      d2 = cur_bytes[i+1] // 16 + 16 * cur_bytes[i+2]
      if d1 < Q: ret.append(d1)
      if d2 < Q and len(ret) < N: ret.append(d2)
      i += 3
    safety_index += 1
    if safety_index > MATRIX_SAMPLE_BOUND: raise RuntimeError('ML-KEM.KeyGen: Matrix generation entered infinite while loop')
  return ret


