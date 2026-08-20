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
