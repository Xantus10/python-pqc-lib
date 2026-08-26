import pytest
import json
from pathlib import Path
from typing import TypedDict

from python_pqc_lib.dsa import *

pytestmark = [pytest.mark.nist, pytest.mark.dsa, pytest.mark.slhdsa, pytest.mark.slow]

cur_dir = Path(__file__).parent

def load_keygen_json(fn: str) -> tuple[list[str | bytes], list[str]]:
  with open(fn, 'r') as f:
    content = json.load(f)
  tests = []
  ids = []
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
      ids.append(f'{parameter_set}--{test['sk'][0:16]}-{test['sk'][-16:]}')
  return tests, ids

# NIST ACVP
data_kg, ids = load_keygen_json(cur_dir / 'nist_test_keygen.json')

@pytest.mark.parametrize(['skSeed', 'skPrf', 'pkSeed', 'sk', 'pk', 'parameterSet'], data_kg, ids=ids)
def test_slhdsa_keygen(crypto_instance, skSeed, skPrf, pkSeed, sk, pk, parameterSet):
  inst: SLHDSA = crypto_instance(parameterSet)
  kg_sk, kg_pk = inst._deterministicKeyGen(skSeed, skPrf, pkSeed)
  assert kg_sk == sk
  assert kg_pk == pk
