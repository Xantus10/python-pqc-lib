from .address import Address, AddressType
from .slh_hashes import SLH_Hashes
from .wots import WOTS


class XMSS:
  """Class for XMSS methods"""
  def __init__(self, lgw: int, n: int, h_sec: int, h: SLH_Hashes):
    """
    Class for XMSS methods

    Note: This class does not preserve state of keys, it only serves for storing runtime constants

    Args:
      lgw (int): The lgw parameter
      n (int): The n parameter (security bytes)
      h_sec (int): The h' parameter (XMSS tree depth)
      h (SLH_Hashes): The hashes object
    """
    self.h = h
    self.n = n
    self.h_sec = h_sec
    self.wots = WOTS(lgw, n, h)

  def node(self, sk_seed: bytes, i: int, z: int, pk_seed: bytes, addr: Address) -> bytes:
    """
    Compute value at the specified node of the XMSS tree

    Args:
      sk_seed (bytes): Secret seed
      i (int): Index of the node
      z (int): Height of the subtree
      pk_seed (bytes): Public seed
      addr (Address): Address of the node

    Returns:
      The value at the node
    """
    if z == 0:
      addr.set_type_and_clear(AddressType.WOTS_HASH)
      addr.set_keypair_address(i)
      return self.wots.pk_gen(sk_seed, pk_seed, addr)
    else:
      lnode = self.node(sk_seed, 2 * i, z - 1, pk_seed, addr)
      rnode = self.node(sk_seed, 2 * i + 1, z - 1, pk_seed, addr)
      addr.set_type_and_clear(AddressType.TREE)
      addr.set_tree_height(z)
      addr.set_tree_index(i)
      return self.h.H(pk_seed, addr, lnode + rnode)

  def sign(self, msg: bytes, sk_seed: bytes, ix: int, pk_seed: bytes, addr: Address) -> bytes:
    """
    Sign a message using XMSS tree

    Args:
      msg (bytes): The n-byte message
      sk_seed (bytes): Secret seed
      ix (int): Index of the node
      pk_seed (bytes): Public seed
      addr (Address): Address of the node

    Returns:
      The byte XMSS signature
    """
    auth_path = [b'' for _ in range(self.h_sec)]
    for i in range(self.h_sec):
      k = (ix // (2**i)) ^ 1
      auth_path[i] = self.node(sk_seed, k, i, pk_seed, addr)
    addr.set_type_and_clear(AddressType.WOTS_HASH)
    addr.set_keypair_address(ix)
    sig = self.wots.sign(msg, sk_seed, pk_seed, addr)
    return b''.join(sig) + b''.join(auth_path)

  def pk_from_sig(self, ix: int, sig: bytes, msg: bytes, pk_seed: bytes, addr: Address) -> bytes:
    """
    Calculate the root XMSS node (XMSS public key) from sig

    Args:
      ix (int): Index of the node
      sig (bytes): The XMSS signature
      msg (bytes): The n-byte message
      pk_seed (bytes): Public seed
      addr (Address): Address of the node

    Returns:
      The presumed XMSS public key
    """
    addr.set_type_and_clear(AddressType.WOTS_HASH)
    addr.set_keypair_address(ix)
    sig_split_ix = self.wots.ln * self.n
    wots_sig = [sig[i:i+self.n] for i in range(0, sig_split_ix, self.n)]
    auth_path = [sig[i:i+self.n] for i in range(sig_split_ix, len(sig), self.n)]
    ret = self.wots.pk_from_sig(wots_sig, msg, pk_seed, addr)
    addr.set_type_and_clear(AddressType.TREE)
    addr.set_tree_index(ix)
    for k in range(self.h_sec):
      addr.set_tree_height(k + 1)
      if (ix // (2**k)) % 2 == 0:
        addr.set_tree_index(addr.get_tree_index() // 2)
        ret = self.h.H(pk_seed, addr, ret + auth_path[k])
      else:
        addr.set_tree_index((addr.get_tree_index() - 1) // 2)
        ret = self.h.H(pk_seed, addr, auth_path[k] + ret)
    return ret
