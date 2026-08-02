"""
Various encoding and compression mechanisms used by ML KEM
"""

def bytes_to_bits(data: bytes) -> list[int]:
  """
  Return a bit string of the data bytes

  Args:
    data (bytes): The data

  Returns:
    An array of 0/1 integers based on the bits
  """
  bits = []
  for byte in data:
    for i in range(8):
      bits.append((byte >> i) & 1)
  return bits
