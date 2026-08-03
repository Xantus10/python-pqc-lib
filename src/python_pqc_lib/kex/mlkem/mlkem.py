"""
Main ML KEM class
"""

from .constants import MLKEM_Parameters
from .encoding import byte_encode
from .mmatrix import MMatrix
from .mvector import MVector
from .random_helper import generateSmallPolynomial, generateMatrixPolynomial, hashG, prf

class MLKEM:
  """Class representing an ML KEM state"""
  def __init__(self, parameters: MLKEM_Parameters):
    """
    Class representing an ML KEM state
    
    Args:
      parameters (MLKEM_Parameters): Special list of parameters for ML KEM
    """
    # Parameters
    self.k = parameters[0]
    self.eta1 = parameters[1]
    self.eta2 = parameters[2]
    self.du = parameters[3]
    self.dv = parameters[4]
    # Raw math objects
    self.__matrix: MMatrix = None
    self.__secret_vec: MVector = None
    # Byte keys (temporary, will change)
    self.encaps_key, self.decaps_key = self.__PKEkeyGen(b'TEST')

  def __PKEkeyGen(self, random_d: bytes) -> tuple[bytes, bytes]:
    """
    The innermost KeyGen algorithm, contains the math

    Args:
      random_d (bytes): 32 bytes of randomness

    Returns:
      byte form of the encapsulation and decapsulation key
    """
    g = hashG(random_d + self.k.to_bytes())
    matrix_seed, error_seed = g[0:32], g[32:64]
    matrix_coefficients = [[generateMatrixPolynomial(matrix_seed, j, i) for j in range(self.k)] for i in range(self.k)]
    self.__matrix = MMatrix.from_coefficients(matrix_coefficients)
    uniq_n = 0
    secret_vec_coefficients = [None for _ in range(self.k)]
    for i in range(self.k):
      secret_vec_coefficients[i] = generateSmallPolynomial(prf(error_seed, uniq_n, self.eta1), self.eta1)
      uniq_n += 1
    self.__secret_vec = MVector.from_coefficients(secret_vec_coefficients).NTT()
    error_vec_coefficients = [None for _ in range(self.k)]
    for i in range(self.k):
      error_vec_coefficients[i] = generateSmallPolynomial(prf(error_seed, uniq_n, self.eta1), self.eta1)
      uniq_n += 1
    error_vec = MVector.from_coefficients(error_vec_coefficients).NTT()
    public_vec = (self.__matrix @ self.__secret_vec) + error_vec
    encaps_key = b''.join([byte_encode(public_vec.arr[i], 12) for i in range(self.k)]) + matrix_seed
    decaps_key = b''.join([byte_encode(self.__secret_vec.arr[i], 12) for i in range(self.k)])
    return encaps_key, decaps_key


