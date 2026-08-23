"""
Main SLH DSA class
"""

from secrets import token_bytes

from .constants import SLHDSA_Parameters
from .address import Address, AddressType
from .helper import ceil_div
from .hypertree import HyperTree
from .fors import FORS
from .slh_hashes import SLH_Hashes_Factory, SLH_Hashes

class SLHDSA:
  """Class representing an SLH DSA state"""
  def __init__(self, parameters: SLHDSA_Parameters):
    """
    Class representing an SLH DSA state

    Args:
      parameters (SLHDSA_Parameters): Special list of parameters for SLH DSA
    """
    # Parameters
    self.n = parameters[0][0]
    self.h = parameters[0][1]
    self.d = parameters[0][2]
    self.h_sec = parameters[0][3]
    self.a = parameters[0][4]
    self.k = parameters[0][5]
    self.lgw = parameters[0][6]
    self.m = parameters[0][7]
    # Hashes
    self.slh_hashes: SLH_Hashes = SLH_Hashes_Factory(parameters[0])
    self._parameter_version = 'Generic SLH DSA'
    # SLH objects
    self.ht = HyperTree(self.d, self.lgw, self.n, self.h_sec, self.slh_hashes)
    self.fors = FORS(self.k, self.a, self.n, self.slh_hashes)
    # Byte keys
    self.public_key = None
    self._secret_key = None

  def __innerKeyGen(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> tuple[bytes, bytes]:
    """
    Inner key generation for SLH DSA

    Args:
      sk_seed (bytes): Secret seed
      sk_prf (bytes): Secret PRF key
      pk_seed (bytes): Public seed

    Returns:
      A tuple of secret_key, public_key
    """
    addr = Address()
    addr.set_layer_address(self.d - 1)
    pk_root = self.ht.xmss.node(sk_seed, 0, self.h_sec, pk_seed, addr)
    return (
      sk_seed + sk_prf + pk_seed + pk_root,
      pk_seed + pk_root
    )

  def __innerSign(self, msg: bytes, secret_key: bytes, additional_randomness: bytes = None):
    """
    Inner SLH DSA Sign algorithm

    Args:
      msg (bytes): The message to sign
      secret_key (bytes): The byte secret key
      additional_randomness (bytes): Optional additional randomness (if None, pk_seed is used)

    Returns:
      The byte signature
    """
    sk_seed, sk_prf, pk_seed, pk_root = [secret_key[i:i+self.n] for i in range(0, len(secret_key), self.n)]
    opt_rand = additional_randomness if not additional_randomness is None else pk_seed
    random_r = self.slh_hashes.PRFmsg(sk_prf, opt_rand, msg)
    sig = random_r
    raw_digest = self.slh_hashes.Hmsg(random_r, pk_seed, pk_root, msg)
    split_md = ceil_div(self.k * self.a, 8)
    split_tree_ix = split_md + ceil_div(self.h - self.h // self.d, 8)
    split_leaf_ix = split_tree_ix + ceil_div(self.h, 8 * self.d)
    md = raw_digest[0:split_md]
    tree_ix = int.from_bytes(raw_digest[split_md:split_tree_ix]) % 2**(self.h - self.h // self.d)
    leaf_ix = int.from_bytes(raw_digest[split_tree_ix:split_leaf_ix]) % 2**(self.h // self.d)
    addr = Address()
    addr.set_tree_address(tree_ix)
    addr.set_type_and_clear(AddressType.FORS_TREE)
    addr.set_keypair_address(leaf_ix)
    fors_sig = self.fors.sign(md, sk_seed, pk_seed, addr)
    sig += fors_sig
    fors_pk = self.fors.pk_from_sig(fors_sig, md, pk_seed, addr)
    ht_sig = self.ht.sign(fors_pk, sk_seed, pk_seed, tree_ix, leaf_ix)
    sig += ht_sig
    return sig

  def __innerVerify(self, msg: bytes, sig: bytes, public_key: bytes):
    """
    Inner SLH DSA Sign algorithm

    Args:
      msg (bytes): The signed message
      sig (bytes): The signature
      public_key (bytes): The byte public key

    Returns:
      True if the signature is valid
    """
    if len(sig) != (1 + self.k * (1 + self.a) + self.h + self.d * self.ht.xmss.wots.ln) * self.n: return False
    pk_seed, pk_root = public_key[0:self.n], public_key[self.n:]
    addr = Address()
    fors_sig_boundary = (1 + self.k * (1 + self.a)) * self.n
    random_r = sig[0:self.n]
    fors_sig = sig[self.n:fors_sig_boundary]
    ht_sig = sig[fors_sig_boundary:]
    raw_digest = self.slh_hashes.Hmsg(random_r, pk_seed, pk_root, msg)
    split_md = ceil_div(self.k * self.a, 8)
    split_tree_ix = split_md + ceil_div(self.h - self.h // self.d, 8)
    split_leaf_ix = split_tree_ix + ceil_div(self.h, 8 * self.d)
    md = raw_digest[0:split_md]
    tree_ix = int.from_bytes(raw_digest[split_md:split_tree_ix]) % 2**(self.h - self.h // self.d)
    leaf_ix = int.from_bytes(raw_digest[split_tree_ix:split_leaf_ix]) % 2**(self.h // self.d)
    addr = Address()
    addr.set_tree_address(tree_ix)
    addr.set_type_and_clear(AddressType.FORS_TREE)
    addr.set_keypair_address(leaf_ix)
    fors_pk = self.fors.pk_from_sig(fors_sig, md, pk_seed, addr)
    return self.ht.verify(fors_pk, ht_sig, pk_seed, tree_ix, leaf_ix, pk_root)
