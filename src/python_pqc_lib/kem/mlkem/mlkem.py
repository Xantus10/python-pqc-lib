"""
Main ML KEM class
"""
import numpy as np
import hmac

from secrets import token_bytes

from .constants import MLKEM_Parameters, N, Q
from .encoding import byte_encode, byte_decode, compress, decompress
from .mmatrix import MMatrix
from .mvector import MVector
from .random_helper import generateSmallPolynomial, generateMatrixPolynomial, hashG, hashH, hashJ, prf

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
    # Byte keys
    self.encaps_key = None
    self.__decaps_key = None

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
    secret_vec = self.generateVector(error_seed, uniq_n, self.eta1).NTT()
    uniq_n += self.k
    error_vec = self.generateVector(error_seed, uniq_n, self.eta1).NTT()
    uniq_n += self.k
    public_vec = (self.__matrix @ secret_vec) + error_vec
    encaps_key = b''.join([byte_encode(public_vec.arr[i], 12) for i in range(self.k)]) + matrix_seed
    decaps_key = b''.join([byte_encode(secret_vec.arr[i], 12) for i in range(self.k)])
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

  def KeyGen(self):
    """
    Generate keys for ML KEM

    Keys are stored internally
    """
    random_d = token_bytes(32)
    random_z = token_bytes(32)
    self.encaps_key, self.__decaps_key = self.__innerKeyGen(random_d, random_z)

  def __PKEEncrypt(self, ek: bytes, m: bytes, random_r: bytes) -> bytes:
    """
    Encapsulate a secret message m

    Args:
      ek (bytes): The encapsulation key to use
      m (bytes): The secret message (32 bytes)
      random_r (bytes): A source of randomness (32 bytes)

    Returns:
      The ciphertext u+v
    """
    self.__matrix = self.generateMatrix(ek[-32:]).transpose()
    public_vec = MVector.from_coefficients([byte_decode(ek[i*384:(i+1)*384], 12) for i in range(self.k)], isntt=True)
    uniq_n = 0
    secret_vec = self.generateVector(random_r, uniq_n, self.eta1).NTT()
    uniq_n += self.k
    error_vec1 = self.generateVector(random_r, uniq_n, self.eta2)
    uniq_n += self.k
    error_pol2 = generateSmallPolynomial(prf(random_r, uniq_n, self.eta2), self.eta2)
    u = (self.__matrix @ secret_vec).invNTT() + error_vec1
    m_encoded = decompress(byte_decode(m, 1), 1)
    v = public_vec * secret_vec
    MVector.simpleInvNTT(v)
    v += m_encoded
    v %= Q
    v += error_pol2
    v %= Q
    c1 = b''.join([byte_encode(compress(u.arr[i], self.du), self.du) for i in range(self.k)])
    c2 = byte_encode(compress(v, self.dv), self.dv)
    return c1 + c2

  def __innerEncaps(self, ek: bytes, random_m: bytes) -> tuple[bytes, bytes]:
    """
    Derive and encapsulate a secret key

    Args:
      ek (bytes): The encapsulation key to use
      random_m (bytes): A source of randomness (32 bytes)

    Returns:
      A tuple of (shared_key, encapsulated_key)
    """
    g = hashG(random_m + hashH(ek))
    shared_key, random_r = g[0:32], g[32:64]
    encapsulated_key = self.__PKEEncrypt(ek, random_m, random_r)
    return shared_key, encapsulated_key

  def Encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
    """
    Generate and encapsulate a secret key

    Args:
      ek (bytes): The encapsulation key to use

    Returns:
      A tuple of (shared_key, encapsulated_key)
    """
    random_m = token_bytes(32)
    return self.__innerEncaps(ek, random_m)


  def __PKEDecrypt(self, dk: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt the ciphertext into a shared key

    Args:
      dk (bytes): Decapsulation key
      ciphertext (bytes): The encapsulated shared key

    Returns:
      The shared key
    """
    ct_boundary = 32 * self.du * self.k
    c1, c2 = ciphertext[0:ct_boundary], ciphertext[ct_boundary:]
    u_arr = np.zeros((self.k, N), dtype=np.int64)
    for i in range(self.k):
      u_arr[i] = decompress(byte_decode(c1[i * 32 * self.du:(i+1) * 32 * self.du], self.du), self.du)
    u = MVector(u_arr)
    v = decompress(byte_decode(c2, self.dv), self.dv)
    secret_vec = MVector.from_coefficients([byte_decode(dk[i*384:(i+1)*384], 12) for i in range(self.k)], isntt=True)
    mult = secret_vec * u.NTT()
    mult %= Q
    MVector.simpleInvNTT(mult)
    m_encoded = v - mult
    m_encoded %= Q
    return byte_encode(compress(m_encoded, 1), 1)

  def __innerDecaps(self, dk: bytes, ciphertext: bytes):
    """
    Decrypt the ciphertext into a shared key

    Args:
      dk (bytes): Decapsulation key
      ciphertext (bytes): The encapsulated shared key

    Returns:
      The shared key
    """
    keys_boundary = 768 * self.k + 32
    dec_key = dk[0:384 * self.k]
    enc_key = dk[384 * self.k:keys_boundary]
    ek_hash = dk[keys_boundary:keys_boundary + 32]
    random_z = dk[keys_boundary + 32:keys_boundary + 64]
    msg = self.__PKEDecrypt(dec_key, ciphertext)
    g = hashG(msg + ek_hash)
    shared_key, random_r = g[0:32], g[32:64]
    invalid_key = hashJ(random_z + ciphertext)
    control_ciphertext = self.__PKEEncrypt(enc_key, msg, random_r)
    success = hmac.compare_digest(ciphertext, control_ciphertext)
    return shared_key if success else invalid_key

  def Decapsulate(self, ciphertext: bytes):
    """
    Decrypt the ciphertext into a shared key

    Args:
      ciphertext (bytes): The encapsulated shared key

    Returns:
      The shared key
    """
    return self.__innerDecaps(self.__decaps_key, ciphertext)
