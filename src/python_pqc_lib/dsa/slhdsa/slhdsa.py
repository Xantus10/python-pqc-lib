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

from ...util.prehash import handle_prehash, PreHash_Alg, HASH_BIT_STRENGTHS

class SLHDSA:
  """Class representing an SLH DSA state"""
  def __init__(self, parameters: SLHDSA_Parameters):
    """
    Class representing an SLH DSA state

    Args:
      parameters (SLHDSA_Parameters): Special list of parameters for SLH DSA
    """
    # Parameters
    self.n = parameters[1][0]
    self.h = parameters[1][1]
    self.d = parameters[1][2]
    self.h_sec = parameters[1][3]
    self.a = parameters[1][4]
    self.k = parameters[1][5]
    self.lgw = parameters[1][6]
    self.m = parameters[1][7]
    # Hashes
    self.slh_hashes: SLH_Hashes = SLH_Hashes_Factory(parameters[0], self.m, self.n)
    self._parameter_version = parameters[2]
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

  def _deterministicKeyGen(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> tuple[bytes, bytes]:
    """
    Deterministic key generation for SLH DSA (Test function)

    Args:
      sk_seed (bytes): Secret seed
      sk_prf (bytes): Secret PRF key
      pk_seed (bytes): Public seed

    Returns:
      A tuple of secret_key, public_key
    """
    return self.__innerKeyGen(sk_seed, sk_prf, pk_seed)

  def KeyGen(self):
    """
    Generate keys for SLH DSA

    Keys are stored internally
    """
    sk_seed = token_bytes(self.n)
    sk_prf = token_bytes(self.n)
    pk_seed = token_bytes(self.n)
    self._secret_key, self.public_key = self._deterministicKeyGen(sk_seed, sk_prf, pk_seed)

  def _deterministicSign(self, msg: bytes, ctx: bytes = b'', addrand: bytes = None):
    """
    Deterministic SLH DSA signature generation

    Args:
      msg (bytes): The message to be signed
      ctx (bytes): The context string
      addrand (bytes): Additional randomness (or None)

    Returns:
      The SLH DSA signature

    Raises:
      ValueError: The context string is too long
    """
    if len(ctx) > 255: raise ValueError('Context is too long')
    updated_message = b'\x00' + len(ctx).to_bytes() + ctx + msg
    return self.__innerSign(updated_message, self._secret_key, addrand)

  def Sign(self, msg: bytes, ctx: bytes = b''):
    """
    Sign a message using SLH DSA

    Args:
      msg (bytes): The message to be signed
      ctx (bytes): The context string

    Returns:
      The SLH DSA signature

    Raises:
      ValueError: The context string is too long
    """
    addrand = token_bytes(self.n)
    return self._deterministicSign(msg, ctx, addrand)

  def _deterministicHashSign(self, msg: bytes, hash_alg: PreHash_Alg, ctx: bytes = b'', addrand: bytes = None):
    """
    Deterministic pre-hash SLH DSA signature generation

    Args:
      msg (bytes): The message to be signed
      ctx (bytes): The context string
      hash_alg (PreHash_Alg): The hash algorithm to use for pre-hash
      addrand (bytes): Additional randomness (or None)

    Returns:
      The SLH DSA signature

    Raises:
      ValueError: The context string is too long
    """
    if len(ctx) > 255: raise ValueError('Context is too long')
    oid, message_hash = handle_prehash(msg, hash_alg)
    updated_message = b'\x01' + len(ctx).to_bytes() + ctx + oid + message_hash
    return self.__innerSign(updated_message, self._secret_key, addrand)

  def HashSign(self, msg: bytes, hash_alg: PreHash_Alg, ctx: bytes = b''):
    """
    Sign a message using SLH DSA pre-hash variant

    Args:
      msg (bytes): The message to be signed
      hash_alg (PreHash_Alg): The hash algorithm to use for pre-hash
      ctx (bytes): The context string

    Returns:
      The SLH DSA signature

    Raises:
      ValueError: The context string is too long or Invalid hash alg was provided
    """
    addrand = token_bytes(self.n)
    bit_strength = HASH_BIT_STRENGTHS.get(hash_alg)
    if not bit_strength is None and bit_strength < (self.n * 8): raise UserWarning(f'Requested hash ({hash_alg}) has bit strength of {bit_strength} bits, but at least {self.n * 8} bits is required for {self._parameter_version}')
    return self._deterministicHashSign(msg, hash_alg, ctx, addrand)

  def Verify(self, msg: bytes, sig: bytes, public_key: bytes, ctx: bytes = b''):
    """
    Verify an SLH DSA signature

    Args:
      msg (bytes): The signed message
      sig (bytes): The signature
      public_key (bytes): The public key to use
      ctx (bytes): The context string

    Raises:
      ValueError: The context string is too long
    """
    if len(ctx) > 255: raise ValueError('Context is too long')
    updated_message = b'\x00' + len(ctx).to_bytes() + ctx + msg
    return self.__innerVerify(updated_message, sig, public_key)

  def HashVerify(self, msg: bytes, sig: bytes, public_key: bytes, hash_alg: PreHash_Alg, ctx: bytes = b''):
    """
    Verify a pre-hash SLH DSA signature

    Args:
      msg (bytes): The signed message
      sig (bytes): The signature
      public_key (bytes): The public key to use
      hash_alg (PreHash_Alg): The hash algorithm to use for pre-hash
      ctx (bytes): The context string

    Raises:
      ValueError: The context string is too long or Invalid hash alg was provided
    """
    if len(ctx) > 255: raise ValueError('Context is too long')
    oid, message_hash = handle_prehash(msg, hash_alg)
    updated_message = b'\x01' + len(ctx).to_bytes() + ctx + oid + message_hash
    return self.__innerVerify(updated_message, sig, public_key)

  def _testSetSecretKey(self, sk: bytes):
    """Test function for explicitly setting secret key"""
    self._secret_key = sk
