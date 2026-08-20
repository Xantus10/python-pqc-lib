from hashlib import sha256, sha512, shake_256
from hmac import HMAC

from .address import Address
from .constants import _SLHDSA_Hash

from abc import ABC, abstractmethod

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


class SLH_Hashes(ABC):
  """Hashes used by SLH DSA"""
  def __init__(self, m: int, n: int):
    """
    Hashes used by SLH DSA

    **Do not instantiate directly, use SLH_Hashes_SHA2 or SLH_Hashes_SHAKE**

    Args:
      m (int): Parameter m
      n (int): Parameter n (byte security level)
    """
    self.m = m
    self.n = n

  @abstractmethod
  def Hmsg(self, random_r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    pass

  @abstractmethod
  def PRF(self, pk_seed: bytes, sk_seed: bytes, addr: Address) -> bytes:
    pass

  @abstractmethod
  def PRFmsg(self, sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    pass

  @abstractmethod
  def F(self, pk_seed: bytes, addr: Address, msg1: bytes) -> bytes:
    pass

  @abstractmethod
  def H(self, pk_seed: bytes, addr: Address, msg2: bytes) -> bytes:
    pass

  @abstractmethod
  def Tl(self, pk_seed: bytes, addr: Address, msgl: bytes) -> bytes:
    pass

class SLH_Hashes_SHA2_cat_1(SLH_Hashes):
  """Hashes used by SLH DSA"""
  def __init__(self, m: int, n: int):
    """
    Hashes used by SLH DSA

    Args:
      m (int): Parameter m
      n (int): Parameter n (byte security level)
    """
    super().__init__(m, n)

  def Hmsg(self, random_r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    return mgf1_sha256(random_r + pk_seed + sha256(random_r + pk_seed + pk_root + msg).digest(), self.m)

  def PRF(self, pk_seed: bytes, sk_seed: bytes, addr: Address) -> bytes:
    return sha256(pk_seed + b'\x00'*(64-self.n) + addr.compressed() + sk_seed).digest()[:self.n]

  def PRFmsg(self, sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return HMAC(sk_prf, opt_rand + msg, sha256).digest()[:self.n]

  def F(self, pk_seed: bytes, addr: Address, msg1: bytes) -> bytes:
    return sha256(pk_seed + b'\x00'*(64-self.n) + addr.compressed() + msg1).digest()[:self.n]

  def H(self, pk_seed: bytes, addr: Address, msg2: bytes) -> bytes:
    return sha256(pk_seed + b'\x00'*(64-self.n) + addr.compressed() + msg2).digest()[:self.n]

  def Tl(self, pk_seed: bytes, addr: Address, msgl: bytes) -> bytes:
    return sha256(pk_seed + b'\x00'*(64-self.n) + addr.compressed() + msgl).digest()[:self.n]

class SLH_Hashes_SHA2_cat_3_5(SLH_Hashes):
  """Hashes used by SLH DSA"""
  def __init__(self, m: int, n: int):
    """
    Hashes used by SLH DSA

    Args:
      m (int): Parameter m
      n (int): Parameter n (byte security level)
    """
    super().__init__(m, n)

  def Hmsg(self, random_r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    return mgf1_sha512(random_r + pk_seed + sha512(random_r + pk_seed + pk_root + msg).digest(), self.m)

  def PRF(self, pk_seed: bytes, sk_seed: bytes, addr: Address) -> bytes:
    return sha256(pk_seed + b'\x00'*(64-self.n) + addr.compressed() + sk_seed).digest()[:self.n]

  def PRFmsg(self, sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return HMAC(sk_prf, opt_rand + msg, sha512).digest()[:self.n]

  def F(self, pk_seed: bytes, addr: Address, msg1: bytes) -> bytes:
    return sha256(pk_seed + b'\x00'*(64-self.n) + addr.compressed() + msg1).digest()[:self.n]

  def H(self, pk_seed: bytes, addr: Address, msg2: bytes) -> bytes:
    return sha512(pk_seed + b'\x00'*(128-self.n) + addr.compressed() + msg2).digest()[:self.n]

  def Tl(self, pk_seed: bytes, addr: Address, msgl: bytes) -> bytes:
    return sha512(pk_seed + b'\x00'*(128-self.n) + addr.compressed() + msgl).digest()[:self.n]

class SLH_Hashes_SHAKE(SLH_Hashes):
  """Hashes used by SLH DSA"""
  def __init__(self, m: int, n: int):
    """
    Hashes used by SLH DSA

    Args:
      m (int): Parameter m
      n (int): Parameter n (byte security level)
    """
    super().__init__(m, n)

  def Hmsg(self, random_r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    return shake_256(random_r + pk_seed + pk_root + msg).digest(self.m)

  def PRF(self, pk_seed: bytes, sk_seed: bytes, addr: Address) -> bytes:
    return shake_256(pk_seed + addr.addr + sk_seed).digest(self.n)

  def PRFmsg(self, sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return shake_256(sk_prf + opt_rand + msg).digest(self.n)

  def F(self, pk_seed: bytes, addr: Address, msg1: bytes) -> bytes:
    return shake_256(pk_seed + addr.addr + msg1).digest(self.n)

  def H(self, pk_seed: bytes, addr: Address, msg2: bytes) -> bytes:
    return shake_256(pk_seed + addr.addr + msg2).digest(self.n)

  def Tl(self, pk_seed: bytes, addr: Address, msgl: bytes) -> bytes:
    return shake_256(pk_seed + addr.addr + msgl).digest(self.n)

def SLH_Hashes_Factory(hash_set: _SLHDSA_Hash, m: int, n: int) -> SLH_Hashes:
  """
  Create an SLH_Hashes object for your parameter set

  Args:
    hash_set (_SLHDSA_Hash): The hash set in use
    m (int): The parameter m
    n (int): The parameter n (byte strength)

  Returns:
    The SLH_Hashes object ready to use

  Raises:
    ValueError: Invalid hash set was provided
  """
  match hash_set:
    case 'SHAKE':
      return SLH_Hashes_SHAKE(m, n)
    case 'SHA2':
      if n == 16:
        return SLH_Hashes_SHA2_cat_1(m, n)
      return SLH_Hashes_SHA2_cat_3_5(m, n)
    case _:
      raise ValueError(f'Invalid hash set was provided ({hash_set})')

