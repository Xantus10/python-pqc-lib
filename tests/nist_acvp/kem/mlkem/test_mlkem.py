import pytest
import json
from pathlib import Path

from python_pqc_lib.kem import *

pytestmark = [pytest.mark.nist, pytest.mark.kem, pytest.mark.mlkem]

cur_dir = Path(__file__).parent

def load_keygen_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (bytes.fromhex(v['z']), bytes.fromhex(v['d']), bytes.fromhex(v['ek']), bytes.fromhex(v['dk'])) for v in content
  ]

# NIST ACVP
data_512_kg = load_keygen_json(cur_dir / 'nist_test_keygen_512.json')

@pytest.fixture
def mlkem_512_inst():
  return MLKEM(MLKEM_512)

@pytest.mark.parametrize(['z', 'd', 'ek', 'dk'], data_512_kg)
def test_mlkem_512_keygen(mlkem_512_inst, z, d, ek, dk):
  kg_ek, kg_dk = mlkem_512_inst._deterministicKeyGen(d, z)
  assert kg_ek == ek
  assert kg_dk == dk


# NIST ACVP
data_768_kg = load_keygen_json(cur_dir / 'nist_test_keygen_768.json')

@pytest.fixture
def mlkem_768_inst():
  return MLKEM(MLKEM_768)

@pytest.mark.parametrize(['z', 'd', 'ek', 'dk'], data_768_kg)
def test_mlkem_768_keygen(mlkem_768_inst, z, d, ek, dk):
  kg_ek, kg_dk = mlkem_768_inst._deterministicKeyGen(d, z)
  assert kg_ek == ek
  assert kg_dk == dk


# NIST ACVP
data_1024_kg = load_keygen_json(cur_dir / 'nist_test_keygen_1024.json')

@pytest.fixture
def mlkem_1024_inst():
  return MLKEM(MLKEM_1024)

@pytest.mark.parametrize(['z', 'd', 'ek', 'dk'], data_1024_kg)
def test_mlkem_1024_keygen(mlkem_1024_inst, z, d, ek, dk):
  kg_ek, kg_dk = mlkem_1024_inst._deterministicKeyGen(d, z)
  assert kg_ek == ek
  assert kg_dk == dk



def load_encaps_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (bytes.fromhex(v['ek']), bytes.fromhex(v['m']), bytes.fromhex(v['k']), bytes.fromhex(v['c'])) for v in content
  ]

# NIST ACVP
data_512_en = load_encaps_json(cur_dir / 'nist_test_encaps_512.json')

@pytest.mark.parametrize(['ek', 'm', 'k', 'c'], data_512_en)
def test_mlkem_512_encaps(mlkem_512_inst, ek, m, k, c):
  k_gen, c_gen = mlkem_512_inst._deterministicEncapsulate(ek, m)
  assert k_gen == k
  assert c_gen == c

# NIST ACVP
data_768_en = load_encaps_json(cur_dir / 'nist_test_encaps_768.json')

@pytest.mark.parametrize(['ek', 'm', 'k', 'c'], data_768_en)
def test_mlkem_768_encaps(mlkem_768_inst, ek, m, k, c):
  k_gen, c_gen = mlkem_768_inst._deterministicEncapsulate(ek, m)
  assert k_gen == k
  assert c_gen == c

# NIST ACVP
data_1024_en = load_encaps_json(cur_dir / 'nist_test_encaps_1024.json')

@pytest.mark.parametrize(['ek', 'm', 'k', 'c'], data_1024_en)
def test_mlkem_1024_encaps(mlkem_1024_inst, ek, m, k, c):
  k_gen, c_gen = mlkem_1024_inst._deterministicEncapsulate(ek, m)
  assert k_gen == k
  assert c_gen == c



def load_decaps_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (bytes.fromhex(v['z']), bytes.fromhex(v['d']), bytes.fromhex(v['c']), bytes.fromhex(v['k'])) for v in content['seed']
  ] + [
    (None, bytes.fromhex(v['dk']), bytes.fromhex(v['c']), bytes.fromhex(v['k'])) for v in content['key']
  ]

# NIST ACVP
data_512_de = load_decaps_json(cur_dir / 'nist_test_decaps_512.json')

@pytest.mark.parametrize(['z', 'd', 'c', 'k'], data_512_de)
def test_mlkem_512_decaps(mlkem_512_inst, z, d, c, k):
  if z is None:
    mlkem_512_inst._testSetDecapsKey(d)
  else:
    _, dk = mlkem_512_inst._deterministicKeyGen(d, z)
    mlkem_512_inst._testSetDecapsKey(dk)
  k_gen = mlkem_512_inst.Decapsulate(c)
  assert k_gen == k

# NIST ACVP
data_768_de = load_decaps_json(cur_dir / 'nist_test_decaps_768.json')

@pytest.mark.parametrize(['z', 'd', 'c', 'k'], data_768_de)
def test_mlkem_768_decaps(mlkem_768_inst, z, d, c, k):
  if z is None:
    mlkem_768_inst._testSetDecapsKey(d)
  else:
    _, dk = mlkem_768_inst._deterministicKeyGen(d, z)
    mlkem_768_inst._testSetDecapsKey(dk)
  k_gen = mlkem_768_inst.Decapsulate(c)
  assert k_gen == k

# NIST ACVP
data_1024_de = load_decaps_json(cur_dir / 'nist_test_decaps_1024.json')

@pytest.mark.parametrize(['z', 'd', 'c', 'k'], data_1024_de)
def test_mlkem_1024_decaps(mlkem_1024_inst, z, d, c, k):
  if z is None:
    mlkem_1024_inst._testSetDecapsKey(d)
  else:
    _, dk = mlkem_1024_inst._deterministicKeyGen(d, z)
    mlkem_1024_inst._testSetDecapsKey(dk)
  k_gen = mlkem_1024_inst.Decapsulate(c)
  assert k_gen == k


