import pytest
import json
from pathlib import Path

from python_pqc_lib.kem import *

cur_dir = Path(__file__).parent

def load_keygen_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (bytes.fromhex(v['z']), bytes.fromhex(v['d']), bytes.fromhex(v['ek']), bytes.fromhex(v['dk'])) for v in content
  ]

# NIST ACVP
data_512 = load_keygen_json(cur_dir / 'nist_test_keygen_512.json')

@pytest.fixture
def mlkem_512_inst():
  return MLKEM(MLKEM_512)

@pytest.mark.parametrize(['z', 'd', 'ek', 'dk'], data_512)
def test_mlkem_512_keygen(mlkem_512_inst, z, d, ek, dk):
  kg_ek, kg_dk = mlkem_512_inst._deterministicKeyGen(d, z)
  assert kg_ek == ek
  assert kg_dk == dk


# NIST ACVP
data_768 = load_keygen_json(cur_dir / 'nist_test_keygen_768.json')

@pytest.fixture
def mlkem_768_inst():
  return MLKEM(MLKEM_768)

@pytest.mark.parametrize(['z', 'd', 'ek', 'dk'], data_768)
def test_mlkem_768_keygen(mlkem_768_inst, z, d, ek, dk):
  kg_ek, kg_dk = mlkem_768_inst._deterministicKeyGen(d, z)
  assert kg_ek == ek
  assert kg_dk == dk


# NIST ACVP
data_1024 = load_keygen_json(cur_dir / 'nist_test_keygen_1024.json')

@pytest.fixture
def mlkem_1024_inst():
  return MLKEM(MLKEM_1024)

@pytest.mark.parametrize(['z', 'd', 'ek', 'dk'], data_1024)
def test_mlkem_1024_keygen(mlkem_1024_inst, z, d, ek, dk):
  kg_ek, kg_dk = mlkem_1024_inst._deterministicKeyGen(d, z)
  assert kg_ek == ek
  assert kg_dk == dk
