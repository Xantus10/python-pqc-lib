from base64 import b64encode, b64decode

from typing import Literal


ALGORITHM_OID = {
  'mldsa-44': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11',
  'mldsa-65': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12',
  'mldsa-87': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13'
}

TAG_SEQUENCE = b'\x30'
TAG_BIT_STRING = b'\x03'

type Scheme = Literal['mlkem', 'mldsa']


def _construct_length(length: int):
  """
  Construct the length field

  Args:
    length (int): The content length

  Returns:
    The bytes of the length field
  """
  if length < 128:
    return length.to_bytes()
  else:
    to_bytes_len = max(1, (length.bit_length() + 7) // 8)
    byte_len = length.to_bytes(to_bytes_len)
    return (0x80 + len(byte_len)).to_bytes() + byte_len

def _algorithm_identifier(alg: Scheme, version: str):
  """
  Construct the AlgorithmIdentifier block

  Args:
    alg (Scheme): The name of the algorithm
    version (str): The version of the algorithm

  Returns:
    The bytes of the AlgorithmIdentifier

  Raises:
    KeyError: Unrecognized algorithm
  """
  alg_name = f'{alg}-{version}'
  oid = ALGORITHM_OID.get(alg_name)
  if oid is None: raise KeyError(f'Unrecognized algorithm {alg_name}!')
  return TAG_SEQUENCE + len(oid).to_bytes() + oid

def _subject_public_key(pk: bytes):
  """
  Construct the SubjectPublicKey block
  
  Args:
    pk (bytes): The public key bytes

  Returns:
    The bytes of the SubjectPublicKey

  Raises:
    KeyError: Unrecognized algorithm
  """
  # The pk is byte aligned
  pk = b'\x00' + pk
  
  return TAG_BIT_STRING + _construct_length(len(pk)) + pk

def _subject_public_key_info(alg: Scheme, version: str, pk: bytes):
  """
  Construct the SubjectPublicKeyInfo block

  Args:
    alg (Scheme): The name of the algorithm
    version (str): The version of the algorithm
    pk (bytes): The public key bytes

  Returns:
    The bytes of the SubjectPublicKey
  """
  alg_id_block = _algorithm_identifier(alg, version)
  pk_block = _subject_public_key(pk)
  return TAG_SEQUENCE + _construct_length(len(alg_id_block) + len(pk_block)) + alg_id_block + pk_block

def _make_pem(subject: Literal['PUBLIC KEY', 'PRIVATE KEY'], content: bytes):
  encoded_cont = b64encode(content).decode("utf-8")
  cont_arr = [encoded_cont[i:i+64] for i in range(0, len(encoded_cont), 64)]
  return f'-----BEGIN {subject}-----{'\n'}{'\n'.join(cont_arr)}{'\n'}-----END {subject}-----'

def export_public_key(alg: Scheme, version: str, pk: bytes):
  """
  Export the public key into PEM PKCS#8 DER format

  Args:
    alg (Scheme): The name of the algorithm
    version (str): The version of the algorithm
    pk (bytes): The public key bytes

  Returns:
    The PEM PKCS#8 DER public key
  """
  return _make_pem('PUBLIC KEY', _subject_public_key_info(alg, version, pk))

print(export_public_key('mldsa', '44', b'ab'*1312))
