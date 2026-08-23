from .address import Address, AddressType
from .helper import base_2b
from .slh_hashes import SLH_Hashes


class FORS:
  """Class for FORS methods"""
  def __init__(self, k: int, a: int, n: int, h: SLH_Hashes):
    """
    Class for FORS methods

    Note: This class does not preserve state of keys, it only serves for storing runtime constants

    Args:
      k (int): How many trees
      a (int): How deep are the trees
      n (int): The security parameter
      h (SLH_Hashes): The hashes object
    """
    self.h = h
    self.k = k
    self.n = n
    self.a = a

  def sk_gen(self, sk_seed: bytes, pk_seed: bytes, addr: Address, ix: int) -> bytes:
    """
    Compute the secret value at the bottom layer of FORS tree

    Args:
      sk_seed (bytes): Secret seed
      pk_seed (bytes): Public seed
      addr (int): Address of the node
      ix (int): Index of the tree

    Returns:
      The value of the node
    """
    sk_addr = addr.copy()
    sk_addr.set_type_and_clear(AddressType.FORS_PRF)
    sk_addr.set_keypair_address(addr.get_keypair_address())
    sk_addr.set_tree_index(ix)
    return self.h.PRF(pk_seed, sk_seed, sk_addr)

  def node(self, sk_seed: bytes, i: int, z: int, pk_seed: bytes, addr: Address) -> bytes:
    """
    Compute value at the specified node of the FORS tree

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
      node_sk = self.sk_gen(sk_seed, pk_seed, addr, i)
      addr.set_tree_height(0)
      addr.set_tree_index(i)
      return self.h.F(pk_seed, addr, node_sk)
    else:
      lnode = self.node(sk_seed, 2 * i, z - 1, pk_seed, addr)
      rnode = self.node(sk_seed, 2 * i + 1, z - 1, pk_seed, addr)
      addr.set_tree_height(z)
      addr.set_tree_index(i)
      return self.h.H(pk_seed, addr, lnode + rnode)

  def sign(self, md: bytes, sk_seed: bytes, pk_seed: bytes, addr: Address) -> bytes:
    """
    Sign a message using FORS

    Args:
      md (bytes): The message digest (a * k bits)
      sk_seed (bytes): Secret seed
      pk_seed (bytes): Public seed
      addr (Address): Address of the node

    Returns:
      The byte FORS signature
    """
    sig = b''
    indicies = base_2b(md, self.a, self.k)
    auth_path = [b'' for _ in range(self.a)]
    for i in range(self.k):
      sig += self.sk_gen(sk_seed, pk_seed, addr, i * (2**self.a) + indicies[i])
      for j in range(self.a):
        s = (indicies[i] // (2**j)) ^ 1
        auth_path[j] = self.node(sk_seed, i * (2**(self.a-j)) + s, j, pk_seed, addr)
      sig += b''.join(auth_path)
    return sig

  def pk_from_sig(self, sig: bytes, md: bytes, pk_seed: bytes, addr: Address) -> bytes:
    """
    Calculate the FORS master public key from sig

    Args:
      sig (bytes): The FORS signature
      md (bytes): The message digest
      pk_seed (bytes): Public seed
      addr (Address): Address of the node

    Returns:
      The presumed FORS public key
    """
    indicies = base_2b(md, self.a, self.k)
    roots = [b'' for _ in range(self.k)]
    for i in range(self.k):
      sk = sig[
        i * (self.a + 1) * self.n :
        (i * (self.a + 1) + 1) * self.n
      ]
      addr.set_tree_height(0)
      addr.set_tree_index(i * (2**self.a) + indicies[i])
      node_val = self.h.F(pk_seed, addr, sk)
      auth_path = [sig[auth_i:auth_i + self.n] for auth_i in range(
        (i * (self.a + 1) + 1) * self.n,
        (i + 1) * (self.a + 1) * self.n,
        self.n
      )]
      for j in range(self.a):
        addr.set_tree_height(j + 1)
        if (indicies[i] // (2**j)) % 2 == 0:
          addr.set_tree_index(addr.get_tree_index() // 2)
          node_val = self.h.H(pk_seed, addr, node_val + auth_path[j])
        else:
          addr.set_tree_index((addr.get_tree_index() - 1) // 2)
          node_val = self.h.H(pk_seed, addr, auth_path[j] + node_val)
      roots[i] = node_val
    fors_pk_addr = addr.copy()
    fors_pk_addr.set_type_and_clear(AddressType.FORS_ROOTS)
    fors_pk_addr.set_keypair_address(addr.get_keypair_address())
    pk = self.h.Tl(pk_seed, fors_pk_addr, b''.join(roots))
    return pk

