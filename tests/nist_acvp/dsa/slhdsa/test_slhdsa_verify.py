import pytest
import json
from pathlib import Path

from python_pqc_lib.dsa import *

pytestmark = [pytest.mark.nist, pytest.mark.dsa, pytest.mark.slhdsa]

cur_dir = Path(__file__).parent

def load_verify_json(fn: str) -> list[str | bytes]:
  with open(fn, 'r') as f:
    content = json.load(f)
  tests = []
  ids = []
  for tg in content:
    parameter_set = tg['parameterSet']
    prehash = True if tg.get('preHash') == 'preHash' else False
    for test in tg['tests']:
      tests.append((
        bytes.fromhex(test['pk']),
        bytes.fromhex(test['message']),
        bytes.fromhex(test['context']),
        bytes.fromhex(test['signature']),
        test['testPassed'],
        parameter_set,
        test['hashAlg'] if prehash else None
      ))
      ids.append(f'{parameter_set}--{test["tcId"]}-PH:{"T" if prehash else "F"}-{test['sk'][0:16]}-{test['sk'][-16:]}')
  return tests, ids

# NIST ACVP
data_verify, ids = load_verify_json(cur_dir / 'nist_test_verify.json')

@pytest.mark.parametrize(['pk', 'msg', 'ctx', 'sig', 'passed', 'parameterSet', 'hashAlg'], data_verify, ids=ids)
def test_slhdsa_verify(crypto_instance, pk, msg, ctx, sig, passed, parameterSet, hashAlg):
  inst: SLHDSA = crypto_instance(parameterSet)
  if hashAlg is None:
    res = inst.Verify(msg, sig, pk, ctx)
  else:
    if not hashAlg in SUPPORTED_HASH_ALGS: pytest.skip(f'Unsupported hash {hashAlg}')
    res = inst.HashVerify(msg, sig, pk, hashAlg, ctx)
  assert res == passed
