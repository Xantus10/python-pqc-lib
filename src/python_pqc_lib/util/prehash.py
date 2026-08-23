from hashlib import sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256

from typing import Literal

HASH_BIT_STRENGTHS = {'SHA2-224': 112, 'SHA2-256': 128, 'SHA2-384': 192, 'SHA2-512': 256,
                       'SHA3-224': 112, 'SHA3-256': 128, 'SHA3-384': 192, 'SHA3-512': 256,
                       'SHAKE-128': 128, 'SHAKE-256': 256}
SUPPORTED_HASH_ALGS = set(HASH_BIT_STRENGTHS.keys())
"""Supported hash algorithms for HashSign"""
type PreHash_Alg = Literal['SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512',
                        'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
                        'SHAKE-128', 'SHAKE-256']

def handle_prehash(message: bytes, hash_alg: PreHash_Alg) -> tuple[bytes, bytes]:
  """
  Handle the hashing of message for PreHash variants of signature schemes

  Args:
    message (bytes): The message to hash
    hash_alg (PreHash_Alg): The hash algorithm to use

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
