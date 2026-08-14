import pytest
import json
from pathlib import Path

from python_pqc_lib.dsa import *

pytestmark = [pytest.mark.nist, pytest.mark.dsa, pytest.mark.mldsa]

cur_dir = Path(__file__).parent


@pytest.fixture
def mldsa_44_inst():
  return MLDSA(MLDSA_44)

@pytest.fixture
def mldsa_65_inst():
  return MLDSA(MLDSA_65)

@pytest.fixture
def mldsa_87_inst():
  return MLDSA(MLDSA_87)

def load_sign_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (True, bytes.fromhex(v['seed']), bytes.fromhex(v['message']), bytes.fromhex(v['context']), bytes.fromhex(v['signature']), v['hashAlg']) for v in content['seed']
  ] + [
    (False, bytes.fromhex(v['sk']), bytes.fromhex(v['message']), bytes.fromhex(v['context']), bytes.fromhex(v['signature']), v['hashAlg']) for v in content['key']
  ]

def long_id_func(val):
  return val[0:64] if isinstance(val, bytes) else str(val)

data_44_sig = load_sign_json(cur_dir / 'nist_test_hash_sign_44.json')

@pytest.mark.parametrize(['isKeyGen', 'secret', 'msg', 'ctx', 'sig', 'hashAlg'], data_44_sig, ids=long_id_func)
def test_mldsa_44_hashsign(mldsa_44_inst, isKeyGen, secret, msg, ctx, sig, hashAlg):
  if not hashAlg in mldsa_44_inst.SUPPORTED_HASH_ALGS: pytest.skip(f'Unsupported hash {hashAlg}')
  if isKeyGen:
    _, sk = mldsa_44_inst._deterministicKeyGen(secret)
    mldsa_44_inst._testSetSecretKey(sk)
  else:
    mldsa_44_inst._testSetSecretKey(secret)
  gen_sig = mldsa_44_inst._deterministicHashSign(msg, ctx, hashAlg, b'\x00'*32)
  assert gen_sig == sig

data_65_sig = load_sign_json(cur_dir / 'nist_test_hash_sign_65.json')

@pytest.mark.parametrize(['isKeyGen', 'secret', 'msg', 'ctx', 'sig', 'hashAlg'], data_65_sig, ids=long_id_func)
def test_mldsa_65_hashsign(mldsa_65_inst, isKeyGen, secret, msg, ctx, sig, hashAlg):
  if not hashAlg in mldsa_65_inst.SUPPORTED_HASH_ALGS: pytest.skip(f'Unsupported hash {hashAlg}')
  if isKeyGen:
    _, sk = mldsa_65_inst._deterministicKeyGen(secret)
    mldsa_65_inst._testSetSecretKey(sk)
  else:
    mldsa_65_inst._testSetSecretKey(secret)
  gen_sig = mldsa_65_inst._deterministicHashSign(msg, ctx, hashAlg, b'\x00'*32)
  assert gen_sig == sig


data_87_sig = load_sign_json(cur_dir / 'nist_test_hash_sign_87.json')

@pytest.mark.parametrize(['isKeyGen', 'secret', 'msg', 'ctx', 'sig', 'hashAlg'], data_87_sig, ids=long_id_func)
def test_mldsa_87_hashsign(mldsa_87_inst, isKeyGen, secret, msg, ctx, sig, hashAlg):
  if not hashAlg in mldsa_87_inst.SUPPORTED_HASH_ALGS: pytest.skip(f'Unsupported hash {hashAlg}')
  if isKeyGen:
    _, sk = mldsa_87_inst._deterministicKeyGen(secret)
    mldsa_87_inst._testSetSecretKey(sk)
  else:
    mldsa_87_inst._testSetSecretKey(secret)
  gen_sig = mldsa_87_inst._deterministicHashSign(msg, ctx, hashAlg, b'\x00'*32)
  assert gen_sig == sig

