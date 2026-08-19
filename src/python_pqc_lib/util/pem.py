from base64 import b64encode

from typing import Literal


ALGORITHM_OID = {
  'mldsa-44': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11',
  'mldsa-65': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12',
  'mldsa-87': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13',
  'mlkem-512': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x01',
  'mlkem-768': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x02',
  'mlkem-1024': b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x03'
}

TAG_SEQUENCE = b'\x30'
TAG_INTEGER = b'\x02'
TAG_BIT_STRING = b'\x03'
TAG_OCTET_STRING = b'\x04'
TAG_IMPLICIT_CONTEXT_SEED = b'\x80'
TAG_IMPLICIT_CONTEXT_EXPANDED = b'\x81'

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

def _version_block(version: int):
  """
  Construct the version number

  Args:
    version (int): The version number

  Returns:
    The bytes of Version
  """
  return TAG_INTEGER + b'\x01' + version.to_bytes()

def _private_key_octet_seed(seed: bytes):
  """
  Construct the private key octet
  
  Args:
    seed (bytes): The private seed

  Returns:
    The bytes of PrivateKey
  """
  inner_part = TAG_IMPLICIT_CONTEXT_SEED + _construct_length(len(seed)) + seed
  return TAG_OCTET_STRING + _construct_length(len(inner_part)) + inner_part

def _private_key_info(alg: Scheme, version: str, seed: bytes):
  """
  Construct the PrivateKeyInfo block

  Args:
    alg (Scheme): The name of the algorithm
    version (str): The version of the algorithm
    seed (bytes): The secret seed

  Returns:
    The bytes of the PrivateKeyInfo
  """
  version_block = _version_block(0)
  alg_id_block = _algorithm_identifier(alg, version)
  priv_key = _private_key_octet_seed(seed)
  return TAG_SEQUENCE + _construct_length(len(version_block) + len(alg_id_block) + len(priv_key)) \
         + version_block + alg_id_block + priv_key


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

def export_private_key_seed(alg: Scheme, version: str, seed: bytes):
  """
  Export the private key into PEM PKCS#8 DER format

  Args:
    alg (Scheme): The name of the algorithm
    version (str): The version of the algorithm
    seed (bytes): The secret seed (or multiple seeds concat)

  Returns:
    The PEM PKCS#8 DER private key
  """
  return _make_pem('PRIVATE KEY', _private_key_info(alg, version, seed))
