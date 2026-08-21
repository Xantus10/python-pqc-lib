

from .address import Address, AddressType
from .helper import base_2b, ceil_div, log2
from .slh_hashes import SLH_Hashes


class WOTS:
  """Class for WOTS+ methods"""
  def __init__(self, lgw: int, n: int, h: SLH_Hashes):
    """
    Class for WOTS+ methods

    Note: This class does not preserve state of keys, it only serves for storing runtime constants

    Args:
      lgw (int): The lgw parameter
      n (int): The n parameter (security bytes)
      h (SLH_Hashes): The hashes object
    """
    self.lgw = lgw
    self.n = n
    self.h = h
    # Calculated constants
    self.w = 2 ** lgw
    self.ln1 = (8 * n) // lgw
    self.ln2 = (log2(self.ln1 * (self.w - 1)) // lgw) + 1
    self.ln = self.ln1 + self.ln2
    self.shift_amount = (8 - ((self.ln2 * self.lgw) % 8)) % 8

  def chain(self, inp: bytes, start: int, no_steps: int, pk_seed: bytes, addr: Address) -> bytes:
    """
    Return the value of F iterated no_steps times on inp

    Args:
      inp (bytes): The input
      start (int): The start index
      no_steps (int): Number of iterations
      pk_seed (bytes): The public key seed
      addr (Address): Current node address (is modified)

    Returns:
      The final layer F value
    """
    ret = inp
    for i in range(start, start + no_steps):
      addr.set_hash_address(i)
      ret = self.h.F(pk_seed, addr, ret)
    return ret

  def pk_gen(self, sk_seed: bytes, pk_seed: bytes, addr: Address) -> bytes:
    """
    Generate a WOTS+ public key

    Args:
      sk_seed (bytes): The secret seed
      pk_seed (bytes): The public key seed
      addr (Address): Current node address

    Returns:
      A new WOTS+ public key
    """
    sk_addr = addr.copy()
    sk_addr.set_type_and_clear(AddressType.WOTS_PRF)
    sk_addr.set_keypair_address(addr.get_keypair_address())
    tmp_chains = [b'' for _ in range(self.ln)]
    for i in range(self.ln):
      sk_addr.set_chain_address(i)
      sk = self.h.PRF(pk_seed, sk_seed, sk_addr)
      addr.set_chain_address(i)
      tmp_chains[i] = self.chain(sk, 0, self.w - 1, pk_seed, addr)
    wots_pk_addr = addr.copy()
    wots_pk_addr.set_type_and_clear(AddressType.WOTS_PK)
    wots_pk_addr.set_keypair_address(addr.get_keypair_address())
    pk = self.h.Tl(pk_seed, wots_pk_addr, b''.join(tmp_chains))
    return pk

  def sign(self, raw_msg: bytes, sk_seed: bytes, pk_seed: bytes, addr: Address) -> list[bytes]:
    """
    Sign an n-byte message

    Args:
      raw_msg (bytes): The message to sign
      sk_seed (bytes): The secret seed
      pk_seed (bytes): The public key seed
      addr (Address): Current node address

    Returns:
      A WOTS+ signature
    """
    csum = 0
    msg = base_2b(raw_msg, self.lgw, self.ln1)
    for i in range(self.ln1):
      csum += self.w - 1 - msg[i]
    csum <<= self.shift_amount
    msg += base_2b(csum.to_bytes(ceil_div(self.ln2 * self.lgw, 8)), self.lgw, self.ln2)
    sk_addr = addr.copy()
    sk_addr.set_type_and_clear(AddressType.WOTS_PRF)
    sk_addr.set_keypair_address(addr.get_keypair_address())
    sig = [b'' for _ in range(self.ln)]
    for i in range(self.ln):
      sk_addr.set_chain_address(i)
      sk = self.h.PRF(pk_seed, sk_seed, sk_addr)
      addr.set_chain_address(i)
      sig[i] = self.chain(sk, 0, msg[i], pk_seed, addr)
    return sig

  def pk_from_sig(self, sig: list[bytes], raw_msg: bytes, pk_seed: bytes, addr: Address):
    """
    Construct WOTS public key from a signature

    Args:
      sig (bytes[]): The signature
      raw_msg (bytes): The message to sign
      pk_seed (bytes): The public key seed
      addr (Address): Current node address

    Returns:
      A WOTS+ signature
    """
    csum = 0
    msg = base_2b(raw_msg, self.lgw, self.ln1)
    for i in range(self.ln1):
      csum += self.w - 1 - msg[i]
    csum <<= self.shift_amount
    msg += base_2b(csum.to_bytes(ceil_div(self.ln2 * self.lgw, 8)), self.lgw, self.ln2)
    tmp_chains = [b'' for _ in range(self.ln)]
    for i in range(self.ln):
      addr.set_chain_address(i)
      tmp_chains[i] = self.chain(sig[i], msg[i], self.w - 1 - msg[i], pk_seed, addr)
    wots_pk_addr = addr.copy()
    wots_pk_addr.set_type_and_clear(AddressType.WOTS_PK)
    wots_pk_addr.set_keypair_address(addr.get_keypair_address())
    pk = self.h.Tl(pk_seed, wots_pk_addr, b''.join(tmp_chains))
    return pk
