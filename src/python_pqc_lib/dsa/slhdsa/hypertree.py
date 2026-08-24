from .address import Address, AddressType
from .slh_hashes import SLH_Hashes
from .xmss import XMSS


class HyperTree:
  """Class for HyperTree methods"""
  def __init__(self, d: int, lgw: int, n: int, h_sec: int, h: SLH_Hashes):
    """
    Class for HyperTree methods

    Note: This class does not preserve state of keys, it only serves for storing runtime constants

    Args:
      d (int): The depth of the hypertree
      lgw (int): The lgw parameter
      n (int): The n parameter (security bytes)
      h_sec (int): The h' parameter (XMSS tree depth)
      h (SLH_Hashes): The hashes object
    """
    self.h = h
    self.n = n
    self.h_sec = h_sec
    self.d = d
    self.xmss = XMSS(lgw, n, h_sec, h)

  def sign(self, msg: bytes, sk_seed: bytes, pk_seed: bytes, tree_ix: int, leaf_ix: int) -> bytes:
    """
    Sign a message using HyperTree

    Args:
      msg (bytes): The n-byte message
      sk_seed (bytes): Secret seed
      pk_seed (bytes): Public seed
      tree_ix (int): Index of the XMSS tree to use
      leaf_ix (int): Index of the FORS+ leaf to use

    Returns:
      The byte HyperTree signature
    """
    addr = Address()
    addr.set_tree_address(tree_ix)
    tmp_sig = self.xmss.sign(msg, sk_seed, leaf_ix, pk_seed, addr)
    sig = tmp_sig
    xmss_root = self.xmss.pk_from_sig(leaf_ix, tmp_sig, msg, pk_seed, addr)
    for i in range(1, self.d):
      leaf_ix = tree_ix % (2 ** self.h_sec)
      tree_ix >>= self.h_sec
      addr.set_layer_address(i)
      addr.set_tree_address(tree_ix)
      tmp_sig = self.xmss.sign(xmss_root, sk_seed, leaf_ix, pk_seed, addr)
      sig += tmp_sig
      if i < self.d-1:
        xmss_root = self.xmss.pk_from_sig(leaf_ix, tmp_sig, xmss_root, pk_seed, addr)
    return sig

  def get_XMSS_sig_from_HT_sig(self, ht_sig: bytes, ix: int):
    """
    Helper method for getting the specific XMSS signature from HT signature

    Args:
      ht_sig (bytes): The hypertree signature
      ix (int): The index of the XMSS signature

    Returns:
      The XMSS signature
    """
    return ht_sig[ix * (self.h_sec + self.xmss.wots.ln) * self.n : (ix + 1) * (self.h_sec + self.xmss.wots.ln) * self.n]

  def verify(self, msg: bytes, sig: bytes, pk_seed: bytes, tree_ix: int, leaf_ix: int, pk_root: bytes) -> bool:
    """
    Verify if the HT root matches the expected value

    Args:
      msg (bytes): The n-byte message
      sig (bytes): The HyperTree signature
      pk_seed (bytes): Public seed
      tree_ix (int): Index of the XMSS tree
      leaf_ix (int): Index of the FORS+ node
      pk_root (int): The absolute root of the hypertree (HT public key)

    Returns:
      True if the signature is valid
    """
    addr = Address()
    addr.set_tree_address(tree_ix)
    tmp_sig = self.get_XMSS_sig_from_HT_sig(sig, 0)
    node = self.xmss.pk_from_sig(leaf_ix, tmp_sig, msg, pk_seed, addr)
    for i in range(1, self.d):
      leaf_ix = tree_ix % (2 ** self.h_sec)
      tree_ix >>= self.h_sec
      addr.set_layer_address(i)
      addr.set_tree_address(tree_ix)
      tmp_sig = self.get_XMSS_sig_from_HT_sig(sig, i)
      node = self.xmss.pk_from_sig(leaf_ix, tmp_sig, node, pk_seed, addr)
    return node == pk_root
