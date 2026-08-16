"""
Main ML DSA class
"""
import numpy as np

from secrets import token_bytes
from hashlib import sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256

from .constants import MLDSA_Parameters, Q, SIGN_BOUND, CHECK_SIZES
from .encoding import power2RoundVec, simpleBitPack, bitPack, simpleBitUnpack, bitUnpack, \
                      highBits, lowBits, makeHint, useHint, hintBitPack, hintBitUnpack
from .mmatrix import MMatrix, MMatrix_type
from .mvector import MVector, MVector_type
from .random_helper import sampleInBall, sampleMatrixPol, sampleSmallPolynomial, h, expandMask

from typing import Literal

class MLDSA:
  """Class representing an ML DSA state"""
  _HASH_BIT_STRENGTHS = {'SHA2-224': 112, 'SHA2-256': 128, 'SHA2-384': 192, 'SHA2-512': 256,
                         'SHA3-224': 112, 'SHA3-256': 128, 'SHA3-384': 192, 'SHA3-512': 256,
                         'SHAKE-128': 128, 'SHAKE-256': 256}
  SUPPORTED_HASH_ALGS = set(_HASH_BIT_STRENGTHS.keys())
  """Supported hash algorithms for HashSign"""
  type MLDSA_Hash_Alg = Literal['SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512',
                                'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
                                'SHAKE-128', 'SHAKE-256']

  def _handle_hash(self, message: bytes, hash_alg: MLDSA_Hash_Alg) -> tuple[bytes, bytes]:
    """
    Handle the hashing of message for Hash MLDSA

    Args:
      message (bytes): The message to hash
      hash_alg (MLDSA_Hash_Alg): The hash algorithm to use

    Returns:
      A tuple of oid, message_hash

    Raises:
      ValueError: Unsupported hash algorithm was provided
    """
    match hash_alg:
      case 'SHA2-224':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04'
        message_hash = sha224(message).digest()
      case 'SHA2-256':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
        message_hash = sha256(message).digest()
      case 'SHA2-384':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02'
        message_hash = sha384(message).digest()
      case 'SHA2-512':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03'
        message_hash = sha512(message).digest()
      case 'SHA3-224':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07'
        message_hash = sha3_224(message).digest()
      case 'SHA3-256':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08'
        message_hash = sha3_256(message).digest()
      case 'SHA3-384':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09'
        message_hash = sha3_384(message).digest()
      case 'SHA3-512':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a'
        message_hash = sha3_512(message).digest()
      case 'SHAKE-128':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b'
        message_hash = shake_128(message).digest(32)
      case 'SHAKE-256':
        oid = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c'
        message_hash = shake_256(message).digest(64)
      case _:
        raise ValueError(f'Unsupported hash algorithm \'{hash_alg}\'')
    return oid, message_hash

  def __init__(self, parameters: MLDSA_Parameters):
    """
    Class representing an ML DSA state

    Args:
      parameters (MLDSA_Parameters): Special list of parameters for ML DSA
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
    self.beta = self.tau * self.eta
    self._parameter_version = str(self.k) + str(self.l)
    # Raw math objects
    self.__matrix: MMatrix_type = None
    # Keys
    self.public_key = None
    self._secret_key = None

  def generateMatrix(self, matrix_seed: bytes) -> MMatrix_type:
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

  def generateSecretVector(self, seed: bytes, uniq_n: int, eta: int, length: int) -> MVector_type:
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

  def __innerKeyGen(self, seed: bytes) -> tuple[bytes, bytes]:
    """
    Handle key generation from seed

    Args:
      seed (bytes): The seed to sample from

    Returns:
      The public key and secret key
    """
    tmp_rand = h(seed + self.k.to_bytes() + self.l.to_bytes()).digest(128)
    matrix_seed, secret_seed, random_k = tmp_rand[0:32], tmp_rand[32:96], tmp_rand[96:128]
    self.__matrix = self.generateMatrix(matrix_seed)
    secret_vec1 = self.generateSecretVector(secret_seed, 0, self.eta, self.l)
    secret_vec2 = self.generateSecretVector(secret_seed, self.l, self.eta, self.k)
    vec_t = (self.__matrix @ secret_vec1.NTT()).invNTT() + secret_vec2
    t1, t0 = power2RoundVec(vec_t.arr, self.d)
    pk = matrix_seed + b''.join([simpleBitPack(p, (2**((Q-1).bit_length() - self.d)) - 1) for p in t1])
    pk_hash = h(pk).digest(64)
    sk = matrix_seed + random_k + pk_hash
    sk += b''.join([bitPack(p, -self.eta, self.eta) for p in secret_vec1.arr])
    sk += b''.join([bitPack(p, -self.eta, self.eta) for p in secret_vec2.arr])
    sk += b''.join([bitPack(p, -(2**(self.d-1)) + 1, 2**(self.d-1)) for p in t0])
    return pk, sk

  def _deterministicKeyGen(self, random_seed: bytes):
    """Deterministic version of KeyGen for testing purposes"""
    return self.__innerKeyGen(random_seed)

  def KeyGen(self):
    """
    Generate keys for ML DSA

    Keys are stored internally
    """
    random_seed = token_bytes(32)
    self.public_key, self._secret_key = self._deterministicKeyGen(random_seed)


  def __innerSign(self, secret_key: bytes, message: bytes, random_seed: bytes) -> bytes:
    """
    Perform the math for signing

    Args:
      secret_key (bytes): The secret key to sign with
      message_bits (bytes): The message to sign
      random_seed (bytes): The random seed to use

    Returns:
      The byte form of the signature

    Raises:
      RuntimeError: The while loop has exceeded its bound
    """
    matrix_seed = secret_key[0:32]
    random_k = secret_key[32:64]
    pk_hash = secret_key[64:128]
    svec_step_size = 32 * ((2 * self.eta).bit_length())
    svec1_end = 128 + svec_step_size * self.l
    secret_vec1 = MVector.from_coefficients(
      [bitUnpack(secret_key[i:i+svec_step_size], -self.eta, self.eta) for i in range(128, svec1_end, svec_step_size)]
    ).NTT()
    svec2_end = svec1_end + svec_step_size * self.k
    secret_vec2 = MVector.from_coefficients(
      [bitUnpack(secret_key[i:i+svec_step_size], -self.eta, self.eta) for i in range(svec1_end, svec2_end, svec_step_size)]
    ).NTT()
    tvec_step_size = 32 * self.d
    t0 = MVector.from_coefficients(
      [bitUnpack(secret_key[i:i+tvec_step_size], -(2**(self.d-1)) + 1, 2**(self.d-1)) for i in range(svec2_end, svec2_end + tvec_step_size * self.k, tvec_step_size)]
    )
    t0 = t0.NTT()

    self.__matrix = self.generateMatrix(matrix_seed)
    mi = h(pk_hash + message).digest(64)
    private_seed = h(random_k + random_seed + mi).digest(64)
    z, hint = None, None
    counter = 0
    while z is None or hint is None and counter:
      y = MVector(expandMask(private_seed, self.gamma1, self.l, counter))
      w = (self.__matrix @ y.NTT()).invNTT()
      w1 = MVector.from_coefficients([[highBits(w.arr[i, j], self.gamma2) for j in range(256)] for i in range(len(w.arr))])
      commit_hash = h(mi + b''.join([simpleBitPack(p, ((Q-1) // (2 * self.gamma2)) - 1) for p in w1.arr])).digest(self.lambd // 4)
      chall = sampleInBall(commit_hash, self.tau)
      chall_ntt = chall.copy()
      MVector.simpleNTT(chall_ntt)
      c_s1 = (secret_vec1 * chall_ntt).invNTT()
      c_s2 = (secret_vec2 * chall_ntt).invNTT()
      z = y + c_s1
      r_vec = w - c_s2
      r0 = MVector.from_coefficients([[lowBits(r_vec.arr[i, j], self.gamma2) for j in range(256)] for i in range(len(r_vec.arr))])
      if z.infinityNorm() >= self.gamma1 - self.beta or r0.infinityNorm() >= self.gamma2 - self.beta: z, hint = None, None
      else:
        c_t0 = (t0 * chall_ntt).invNTT()
        base = w - c_s2 + c_t0
        hint = np.array([[makeHint(-c_t0.arr[i, j], base.arr[i, j], self.gamma2) for j in range(256)] for i in range(len(c_t0.arr))], dtype=np.int8)
        if c_t0.infinityNorm() >= self.gamma2 or np.sum(hint) > self.omega: z, hint = None, None
      counter += self.l
      if counter > SIGN_BOUND: RuntimeError('ML-DSA: Sign entered infinite while loop')
    sig = commit_hash
    sig += b''.join([bitPack(p, -self.gamma1 + 1, self.gamma1) for p in z.centered_modQ().arr])
    sig += hintBitPack(hint, self.omega)
    return sig

  def _deterministicSign(self, message: bytes, context: bytes, random_seed: bytes):
    """Deterministic variant of Sign for testing purposes"""
    if len(context) > 255: raise ValueError('Context is too long')
    updated_message = b'\x00' + len(context).to_bytes() + context + message
    return self.__innerSign(self._secret_key, updated_message, random_seed)

  def Sign(self, message: bytes, context: bytes = b'') -> bytes:
    """
    Sign a message and a context string

    Args:
      message (bytes): The message to sign
      context (bytes): Context string of max length 255 bytes

    Returns:
      The signature

    Raises:
      ValueError: Context is longer than 255 bytes
    """
    random_seed = token_bytes(32)
    return self._deterministicSign(message, context, random_seed)

  def _deterministicHashSign(self, message: bytes, context: bytes, hash_alg: MLDSA_Hash_Alg, random_seed: bytes):
    if len(context) > 255: raise ValueError('Context is too long')
    oid, message_hash = self._handle_hash(message, hash_alg)
    updated_message = b'\x01' + len(context).to_bytes() + context + oid + message_hash
    return self.__innerSign(self._secret_key, updated_message, random_seed)

  def HashSign(self, message: bytes, hash_alg: MLDSA_Hash_Alg, context: bytes = b''):
    """
    Sign a message digest and a context string

    Args:
      message (bytes): The message to sign
      hash_alg (MLDSA_Hash_Alg): Which hash algorithm to use
      context (bytes): Context string of max length 255 bytes

    Returns:
      The signature

    Raises:
      ValueError: Context is longer than 255 bytes or Invalid hash alg was provided
    """
    random_seed = token_bytes(32)
    bit_strength = MLDSA._HASH_BIT_STRENGTHS.get(hash_alg)
    if not bit_strength is None and bit_strength < self.lambd: raise UserWarning(f'Requested hash ({hash_alg}) has bit strength of {bit_strength} bits, but at least {self.lambd} bits is required for MLDSA-{self._parameter_version}')
    return self._deterministicHashSign(message, context, hash_alg, random_seed)


  def __innerVerify(self, public_key: bytes, message: bytes, sig: bytes) -> bool:
    """
    Mathematically verify the signature

    Args:
      public_key (bytes): The public key to verify with
      message (bytes): The signed message to verify
      sig (bytes): The signature

    Returns:
      True if the signature matches
    """
    matrix_seed = public_key[0:32]
    t1_step_size = ((Q-1).bit_length() - self.d) * 32
    t1 = MVector.from_coefficients(
      [simpleBitUnpack(public_key[i:i+t1_step_size], (2**((Q-1).bit_length() - self.d)) - 1) for i in range(32, 32 + t1_step_size * self.k, t1_step_size)]
    )

    commit_hash = sig[0:self.lambd // 4]
    z_step_size = 32 * (1 + (self.gamma1 - 1).bit_length())
    hint_start = len(sig) - self.omega - self.k
    z = MVector.from_coefficients(
      [bitUnpack(sig[i:i+z_step_size], -self.gamma1 + 1, self.gamma1) for i in range(self.lambd//4, hint_start, z_step_size)]
    )
    try:
      hint = hintBitUnpack(sig[hint_start:], self.k, self.omega)
    except IndexError:
      return False

    self.__matrix = self.generateMatrix(matrix_seed)
    pk_hash = h(public_key).digest(64)
    mi = h(pk_hash + message).digest(64)
    chall = sampleInBall(commit_hash, self.tau)

    MVector.simpleNTT(chall)
    scaled_t: MVector_type = (t1 * (2**self.d)).NTT()
    w_approx = (self.__matrix @ z.NTT()).invNTT() - (scaled_t * chall).invNTT()
    w1 = w_approx.arr.copy()

    for i in range(self.k):
      for j in range(256):
        w1[i, j] = useHint(hint[i, j], w1[i, j], self.gamma2)
    check_commit_hash = h(mi + b''.join([simpleBitPack(p, ((Q-1) // (2 * self.gamma2)) - 1) for p in w1])).digest(self.lambd // 4)

    return z.infinityNorm() < self.gamma1 - self.beta and commit_hash == check_commit_hash

  def Verify(self, public_key: bytes, message: bytes, sig: bytes, context: bytes = b''):
    """
    Mathematically verify the signature

    Args:
      public_key (bytes): The public key to verify with
      message (bytes): The signed message to verify
      sig (bytes): The signature
      context (bytes): Context string of max length 255 bytes

    Returns:
      True if the signature matches

    Raises:
      ValueError: Invalid argument value was provided
    """
    if len(context) > 255: raise ValueError('Context is too long')
    if len(public_key) != CHECK_SIZES[self._parameter_version]['pk']: raise ValueError('Public key has invalid size')
    updated_message = b'\x00' + len(context).to_bytes() + context + message
    return self.__innerVerify(public_key, updated_message, sig)

  def HashVerify(self, public_key: bytes, message: bytes, sig: bytes, hash_alg: MLDSA_Hash_Alg, context: bytes = b''):
    """
    Mathematically verify the signature

    Args:
      public_key (bytes): The public key to verify with
      message (bytes): The signed message to verify
      sig (bytes): The signature
      hash (MLDSA_Hash_Alg): Which hash algorithm to use
      context (bytes): Context string of max length 255 bytes

    Returns:
      True if the signature matches

    Raises:
      ValueError: Invalid argument value was provided
    """
    if len(context) > 255: raise ValueError('Context is too long')
    if len(public_key) != CHECK_SIZES[self._parameter_version]['pk']: raise ValueError('Public key has invalid size')
    oid, message_hash = self._handle_hash(message, hash_alg)
    updated_message = b'\x01' + len(context).to_bytes() + context + oid + message_hash
    return self.__innerVerify(public_key, updated_message, sig)

  def _testSetSecretKey(self, sk: bytes):
    """Test function for explicitly setting secret key"""
    self._secret_key = sk
