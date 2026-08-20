from __future__ import annotations

from enum import IntEnum

class AddressType(IntEnum):
  WOTS_HASH = 0
  WOTS_PK = 1
  TREE = 2
  FORS_TREE = 3
  FORS_ROOTS = 4
  WOTS_PRF = 5
  FORS_PRF = 6

class Address:
  """The address of a tree node"""
  def __init__(self, initial_value: bytes = b'\x00'*32):
    """The address of a tree node"""
    self.addr = initial_value

  def get_layer_address(self) -> int:
    """
    Getter for layer address
    """
    return int.from_bytes(self.addr[0:4])

  def get_tree_address(self) -> int:
    """
    Getter for tree address
    """
    return int.from_bytes(self.addr[4:16])

  def get_type(self) -> int:
    """
    Getter for type
    """
    return int.from_bytes(self.addr[16:20])

  def get_keypair_address(self) -> int:
    """
    Getter for keypair address
    """
    return int.from_bytes(self.addr[20:24])

  def get_chain_address(self) -> int:
    """
    Getter for chain address
    """
    return int.from_bytes(self.addr[24:28])

  def get_hash_address(self) -> int:
    """
    Getter for hash address
    """
    return int.from_bytes(self.addr[28:32])

  def get_tree_height(self) -> int:
    """
    Getter for tree height
    """
    return int.from_bytes(self.addr[24:28])

  def get_tree_index(self) -> int:
    """
    Getter for tree index
    """
    return int.from_bytes(self.addr[28:32])

  def set_layer_address(self, layer_addr: int):
    """
    Setter for layer address

    Args:
      layer_addr (int): The new layer address
    """
    self.addr = layer_addr.to_bytes(4) + self.addr[4:]

  def set_tree_address(self, tree_addr: int):
    """
    Setter for tree address

    Args:
      tree_addr (int): The new tree address
    """
    self.addr = self.addr[0:4] + tree_addr.to_bytes(12) + self.addr[16:]

  def set_type_and_clear(self, addr_type: AddressType):
    """
    Setter for address type, also clears type dependent metadata

    Args:
      addr_type (AddressType): The new type
    """
    self.addr = self.addr[0:16] + addr_type.to_bytes(4) + b'\x00'*12

  def set_keypair_address(self, keypair_addr: int):
    """
    Setter for keypair address

    Args:
      keypair_addr (int): The new keypair address
    """
    self.addr = self.addr[0:20] + keypair_addr.to_bytes(4) + self.addr[24:]

  def set_chain_address(self, chain_addr: int):
    """
    Setter for chain address

    Args:
      chain_addr (int): The new chain address
    """
    self.addr = self.addr[0:24] + chain_addr.to_bytes(4) + self.addr[28:]

  def set_hash_address(self, hash_addr: int):
    """
    Setter for hash address

    Args:
      hash_addr (int): The new hash address
    """
    self.addr = self.addr[0:28] + hash_addr.to_bytes(4)

  def set_tree_height(self, tree_height: int):
    """
    Setter for tree_height

    Args:
      tree_height (int): The new tree height
    """
    self.addr = self.addr[0:24] + tree_height.to_bytes(4) + self.addr[28:]

  def set_tree_index(self, tree_index: int):
    """
    Setter for tree index

    Args:
      tree_index (int): The new tree index
    """
    self.addr = self.addr[0:28] + tree_index.to_bytes(4)

  def compressed(self) -> bytes:
    """
    Create a compressed version of the Address

    Returns:
      The bytes representing the compressed address
    """
    return self.addr[3] + self.addr[8:16] + self.addr[19:]

  def copy(self) -> Address:
    return Address(self.addr)
