"""Various help functions"""

def base_2b(inp: bytes, base: int, out_len: int):
  """
  Convert the bytes into an array of base[2**base] integers of length out_len

  Args:
    inp (bytes): The input to convert
    base (int): The base to which convert (2**base)
    out_len (int): The length of the output array

  Returns:
    An array of converted integers
  """
  i = 0
  bits = 0
  total = 0
  mod = 2 ** base
  ret = [0 for _ in range(out_len)]
  for out_ix in range(out_len):
    while bits < base:
      total = (total << 8) + inp[i]
      i += 1
      bits += 8
    bits -= base
    ret[out_ix] = (total >> bits) % mod
  return ret


def log2(x: int) -> int:
  """
  Helper function for calculating int-based log2

  Args:
    x (int): Number to compute log of

  Returns:
    The exponent
  """
  return x.bit_length() - 1


def ceil_div(numerator: int, denominator: int):
  """
  Perform Upper rounded division

  Args:
    numerator (int): The number to be divided
    denominator (int): The divisor

  Returns:
    The result
  """
  return (numerator + denominator - 1) // denominator
