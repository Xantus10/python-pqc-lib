import pytest
import json
from pathlib import Path

from python_pqc_lib.dsa import *

pytestmark = [pytest.mark.nist, pytest.mark.dsa, pytest.mark.mldsa]

cur_dir = Path(__file__).parent

def load_keygen_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (bytes.fromhex(v['seed']), bytes.fromhex(v['pk']), bytes.fromhex(v['sk'])) for v in content
  ]

# NIST ACVP
data_44_kg = load_keygen_json(cur_dir / 'nist_test_keygen_44.json')

@pytest.fixture
def mldsa_44_inst():
  return MLDSA(MLDSA_44)

@pytest.mark.parametrize(['seed', 'pk', 'sk'], data_44_kg)
def test_mldsa_44_keygen(mldsa_44_inst, seed, pk, sk):
  kg_pk, kg_sk = mldsa_44_inst._deterministicKeyGen(seed)
  assert kg_pk == pk
  assert kg_sk == sk
