"""
Main ML KEM class
"""
import numpy as np

from secrets import token_bytes

from .constants import MLKEM_Parameters, Q
from .encoding import byte_encode, byte_decode, compress, decompress
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
    self.__public_vec: MVector = None
    # Byte keys
    self.encaps_key = None
    self.decaps_key = None
    if encapsulation_key:
      self.encaps_key = encapsulation_key
      self.__matrix = self.generateMatrix(self.encaps_key[-32:]).transpose()
      self.__public_vec = MVector.from_coefficients([byte_decode(self.encaps_key[i:i+384], 12) for i in range(self.k)], isntt=True)
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
    Generate a small numbers vector

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
    return MVector.from_coefficients(vec_coefficients)

  def __PKEkeyGen(self, random_d: bytes) -> tuple[bytes, bytes]:
    """
    The innermost KeyGen algorithm, contains the math

    Args:
      random_d (bytes): 32 bytes of randomness

    Returns:
      Byte form of the encapsulation and decapsulation key
    """
    g = hashG(random_d + self.k.to_bytes())
    matrix_seed, error_seed = g[0:32], g[32:64]
    self.__matrix = self.generateMatrix(matrix_seed)
    uniq_n = 0
    self.__secret_vec = self.generateVector(error_seed, uniq_n, self.eta1).NTT()
    uniq_n += self.k
    error_vec = self.generateVector(error_seed, uniq_n, self.eta1).NTT()
    uniq_n += self.k
    self.__public_vec = (self.__matrix @ self.__secret_vec) + error_vec
    encaps_key = b''.join([byte_encode(self.__public_vec.arr[i], 12) for i in range(self.k)]) + matrix_seed
    decaps_key = b''.join([byte_encode(self.__secret_vec.arr[i], 12) for i in range(self.k)])
    return encaps_key, decaps_key

  def __innerKeyGen(self, random_d: bytes, random_z: bytes) -> tuple[bytes, bytes]:
    """
    The middle KeyGen algorithm, for adding check info

    Args:
      random_d (bytes): 32 bytes of randomness
      random_z (bytes): 32 bytes of randomness

    Returns:
      Byte form of the encapsulation and decapsulation key
    """
    ek, dk = self.__PKEkeyGen(random_d)
    dk += ek + hashH(ek) + random_z
    return ek, dk

  def __keyGen(self) -> tuple[bytes, bytes]:
    """
    Generate keys for ML KEM

    Returns:
      Byte form of the encapsulation and decapsulation key
    """
    random_d = token_bytes(32)
    random_z = token_bytes(32)
    return self.__innerKeyGen(random_d, random_z)


  def __PKEEncrypt(self, m: bytes, random_r: bytes) -> bytes:
    """
    Encapsulate a secret message m

    Args:
      m (bytes): The secret message (32 bytes)
      random_r (bytes): A source of randomness (32 bytes)

    Returns:
      The ciphertext u+v
    """
    uniq_n = 0
    self.__secret_vec = self.generateVector(random_r, uniq_n, self.eta1).NTT()
    uniq_n += self.k
    error_vec1 = self.generateVector(random_r, uniq_n, self.eta2)
    uniq_n += self.k
    error_pol2 = generateSmallPolynomial(prf(random_r, uniq_n, self.eta2), self.eta2)
    u = (self.__matrix @ self.__secret_vec).invNTT() + error_vec1
    m_encoded = decompress(np.array(byte_decode(m, 1), dtype=np.int64), 1)
    v = self.__public_vec * self.__secret_vec
    MVector.simpleInvNTT(v)
    v += m_encoded
    v %= Q
    v += error_pol2
    v %= Q
    c1 = b''.join([byte_encode(compress(u.arr[i], self.du), self.du) for i in range(self.k)])
    c2 = byte_encode(compress(v, self.dv), self.dv)
    return c1 + c2
