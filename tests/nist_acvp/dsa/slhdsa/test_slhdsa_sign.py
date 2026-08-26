import pytest
import json
from pathlib import Path

from python_pqc_lib.dsa import *

pytestmark = [pytest.mark.nist, pytest.mark.dsa, pytest.mark.slhdsa, pytest.mark.slow] # When doing JSON revision maybe split the test sets based on parameter set F/S

cur_dir = Path(__file__).parent

def load_sign_json(fn: str) -> list[str | bytes]:
  with open(fn, 'r') as f:
    content = json.load(f)
  tests = []
  ids = []
  for tg in content:
    parameter_set = tg['parameterSet']
    deterministic = tg['deterministic']
    prehash = True if tg.get('preHash') == 'preHash' else False
    for test in tg['tests']:
      tests.append((
        bytes.fromhex(test['sk']),
        bytes.fromhex(test['message']),
        bytes.fromhex(test['context']),
        bytes.fromhex(test['signature']),
        parameter_set,
        bytes.fromhex(test['additionalRandomness']) if not deterministic else None,
        test['hashAlg'] if prehash else None
      ))
      ids.append(f'{parameter_set}--D:{"T" if deterministic else "F"}-PH:{"T" if prehash else "F"}-{test['sk'][0:16]}-{test['sk'][-16:]}')
  return tests, ids

# NIST ACVP
data_sign, ids = load_sign_json(cur_dir / 'nist_test_sign.json')

@pytest.mark.parametrize(['sk', 'msg', 'ctx', 'sig', 'parameterSet', 'addRand', 'hashAlg'], data_sign, ids=ids)
def test_slhdsa_sign(crypto_instance, sk, msg, ctx, sig, parameterSet, addRand, hashAlg):
  inst: SLHDSA = crypto_instance(parameterSet)
  inst._testSetSecretKey(sk)
  if hashAlg is None:
    test_sig = inst._deterministicSign(msg, ctx, addRand)
  else:
    if not hashAlg in SUPPORTED_HASH_ALGS: pytest.skip(f'Unsupported hash {hashAlg}')
    test_sig = inst._deterministicHashSign(msg, hashAlg, ctx, addRand)
  assert test_sig == sig  
