"""
Main ML DSA class
"""
import numpy as np

from secrets import token_bytes

from .constants import MLDSA_Parameters, Q
from .encoding import power2RoundVec, simpleBitPack, bitPack
from .mmatrix import MMatrix
from .mvector import MVector
from .random_helper import sampleInBall, sampleMatrixPol, sampleSmallPolynomial, h

class MLKEM:
  """Class representing an ML KEM state"""
  def __init__(self, parameters: MLDSA_Parameters):
    """
    Class representing an ML KEM state

    Args:
      parameters (MLKEM_Parameters): Special list of parameters for ML KEM
    """
    # Parameters
    self.d = parameters[0]
    self.tau = parameters[1]
    self.lambd = parameters[2]
    self.gamma1 = parameters[3]
    self.gamma2 = parameters[4]
    self.k = parameters[5]
    self.l = parameters[6]
    self.eta = parameters[7]
    self.omega = parameters[8]
    # Raw math objects
    self.__matrix: MMatrix = None
    # Keys
    self.public_key = None
    self.__secret_key = None

  def generateMatrix(self, matrix_seed: bytes) -> MMatrix:
    """
    Generate the public matrix

    Args:
      matrix_seed (bytes): The seed for the matrix

    Returns:
      The generated MMatrix
    """
    return MMatrix.from_coefficients(
      [[sampleMatrixPol(matrix_seed, j, i) for j in range(self.l)] for i in range(self.k)]
    )

  def generateSecretVector(self, seed: bytes, uniq_n: int, eta: int, length: int) -> MVector:
    """
    Generate a small numbers vector

    Args:
      seed (bytes): The seed for the generation
      uniq_n (int): Integer to ensure uniquness
      eta (int): Eta to use
      length (int): Length l or k

    Returns:
      The generated MVector
    """
    vec_coefficients = [None for _ in range(length)]
    for i in range(length):
      vec_coefficients[i] = sampleSmallPolynomial(seed, uniq_n, eta)
      uniq_n += 1
    return MVector.from_coefficients(vec_coefficients)

  def __innerKeyGen(self, seed: bytes):
    """
    Handle key generation from seed

    Args:
      seed (bytes): The seed to sample from
    """
    tmp_rand = h(seed + self.k.to_bytes() + self.l.to_bytes()).digest(128)
    matrix_seed, secret_seed, random_k = tmp_rand[0:32], tmp_rand[32:96], tmp_rand[96:128]
    self.__matrix = self.generateMatrix(matrix_seed)
    secret_vec1 = self.generateSecretVector(secret_seed, 0, self.eta, self.l)
    secret_vec2 = self.generateSecretVector(secret_seed, self.l, self.eta, self.k)
    vec_t = (self.__matrix @ secret_vec1.NTT()).invNTT() + secret_vec2
    t1, t0 = power2RoundVec(vec_t.arr, self.d)
    self.public_key = matrix_seed + b''.join([simpleBitPack(p, 2**((Q-1).bit_length() - self.d)) for p in t1])
    pk_hash = h(self.public_key).digest(64)
    self.__secret_key = matrix_seed + random_k + pk_hash
    self.__secret_key += b''.join([bitPack(p, -self.eta, self.eta) for p in secret_vec1])
    self.__secret_key += b''.join([bitPack(p, -self.eta, self.eta) for p in secret_vec2])
    self.__secret_key += b''.join([bitPack(p, -(2**(self.d-1)) + 1, 2**(self.d-1)) for p in t0])


