"""
Main ML KEM class
"""
from secrets import token_bytes

from .constants import MLKEM_Parameters
from .encoding import byte_encode
from .mmatrix import MMatrix
from .mvector import MVector
from .random_helper import generateSmallPolynomial, generateMatrixPolynomial, hashG, hashH, prf

class MLKEM:
  """Class representing an ML KEM state"""
  def __init__(self, parameters: MLKEM_Parameters, encapsulation_key: bytes = None):
    """
    Class representing an ML KEM state
    
    Args:
      parameters (MLKEM_Parameters): Special list of parameters for ML KEM
      encapsulation_key (bytes): Recieved encapsulation key to use for encapsulation
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
    # Byte keys
    self.encaps_key = None
    self.decaps_key = None
    if encapsulation_key:
      self.encaps_key = encapsulation_key
    else:
      self.encaps_key, self.decaps_key = self.__keyGen()

  def generateMatrix(self, matrix_seed: bytes) -> MMatrix:
    """
    Generate the public matrix

    Args:
      matrix_seed (bytes): The seed for the matrix

    Returns:
      The generated MMatrix
    """
    return MMatrix.from_coefficients(
      [[generateMatrixPolynomial(matrix_seed, j, i) for j in range(self.k)] for i in range(self.k)]
    )

  def generateVector(self, seed: bytes, uniq_n: int, eta: int) -> MVector:
    """
    Generate a small numbers vector (NTT transformed)

    Args:
      seed (bytes): The seed for the generation
      uniq_n (int): Integer to ensure uniquness
      eta (int): Eta to use

    Returns:
      The generated MVector
    """
    vec_coefficients = [None for _ in range(self.k)]
    for i in range(self.k):
      vec_coefficients[i] = generateSmallPolynomial(prf(seed, uniq_n, eta), eta)
      uniq_n += 1
    return MVector.from_coefficients(vec_coefficients).NTT()

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
    self.__matrix = self.generateMatrix(matrix_seed)
    uniq_n = 0
    self.__secret_vec = self.generateVector(error_seed, uniq_n, self.eta1)
    uniq_n += self.k
    error_vec = self.generateVector(error_seed, uniq_n, self.eta1)
    uniq_n += self.k
    public_vec = (self.__matrix @ self.__secret_vec) + error_vec
    encaps_key = b''.join([byte_encode(public_vec.arr[i], 12) for i in range(self.k)]) + matrix_seed
    decaps_key = b''.join([byte_encode(self.__secret_vec.arr[i], 12) for i in range(self.k)])
    return encaps_key, decaps_key

  def __innerKeyGen(self, random_d: bytes, random_z: bytes):
    """
    The middle KeyGen algorithm, for adding check info

    Args:
      random_d (bytes): 32 bytes of randomness
      random_z (bytes): 32 bytes of randomness

    Returns:
      byte form of the encapsulation and decapsulation key
    """
    ek, dk = self.__PKEkeyGen(random_d)
    dk += ek + hashH(ek) + random_z
    return ek, dk

  def __keyGen(self):
    random_d = token_bytes(32)
    random_z = token_bytes(32)
    return self.__innerKeyGen(random_d, random_z)
