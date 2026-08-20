from hashlib import sha256, sha512, shake_256

def mgf1_sha256(seed: bytes, length: int) -> bytes:
  """
  The MGF1-SHA-256 function

  Args:
    seed (bytes): The secret seed
    length (int): The desired length of the mask

  Returns:
    The generated mask bytes

  Raises:
    ValueError: The requested length is too large
  """

  if length > 0xFFFFFFFF * 32:
    raise ValueError("Mask too long")

  ret = b""
  counter = 0

  while len(ret) < length:
    ret += sha256(seed + counter.to_bytes(4, byteorder="big")).digest()
    counter += 1

  return ret[:length]

def mgf1_sha512(seed: bytes, length: int) -> bytes:
  """
  The MGF1-SHA-512 function

  Args:
    seed (bytes): The secret seed
    length (int): The desired length of the mask

  Returns:
    The generated mask bytes

  Raises:
    ValueError: The requested length is too large
  """

  if length > 0xFFFFFFFF * 64:
    raise ValueError("Mask too long")

  ret = b""
  counter = 0

  while len(ret) < length:
    ret += sha512(seed + counter.to_bytes(4, byteorder="big")).digest()
    counter += 1

  return ret[:length]



