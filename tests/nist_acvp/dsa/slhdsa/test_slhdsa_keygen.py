import pytest
import json
from pathlib import Path
from typing import TypedDict

from python_pqc_lib.dsa import *

pytestmark = [pytest.mark.nist, pytest.mark.dsa, pytest.mark.slhdsa]

cur_dir = Path(__file__).parent

def load_keygen_json(fn: str) -> list[str | bytes]:
  with open(fn, 'r') as f:
    content = json.load(f)
  tests = []
  for tg in content:
    parameter_set = tg['parameterSet']
    for test in tg['tests']:
      tests.append((
        bytes.fromhex(test['skSeed']),
        bytes.fromhex(test['skPrf']),
        bytes.fromhex(test['pkSeed']),
        bytes.fromhex(test['sk']),
        bytes.fromhex(test['pk']),
        parameter_set
      ))
  return tests

# NIST ACVP
data_kg = load_keygen_json(cur_dir / 'nist_test_keygen.json')

@pytest.mark.parametrize(['skSeed', 'skPrf', 'pkSeed', 'sk', 'pk', 'parameterSet'], data_kg)
def test_slhdsa_keygen(crypto_instance, skSeed, skPrf, pkSeed, sk, pk, parameterSet):
  inst: SLHDSA = crypto_instance(parameterSet)
  kg_sk, kg_pk = inst._deterministicKeyGen(skSeed, skPrf, pkSeed)
  assert kg_sk == sk
  assert kg_pk == pk
