import pytest
import json
from pathlib import Path
from hashlib import sha256

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


# NIST ACVP
data_65_kg = load_keygen_json(cur_dir / 'nist_test_keygen_65.json')

@pytest.fixture
def mldsa_65_inst():
  return MLDSA(MLDSA_65)

@pytest.mark.parametrize(['seed', 'pk', 'sk'], data_65_kg)
def test_mldsa_65_keygen(mldsa_65_inst, seed, pk, sk):
  kg_pk, kg_sk = mldsa_65_inst._deterministicKeyGen(seed)
  assert kg_pk == pk
  assert kg_sk == sk


# NIST ACVP
data_87_kg = load_keygen_json(cur_dir / 'nist_test_keygen_87.json')

@pytest.fixture
def mldsa_87_inst():
  return MLDSA(MLDSA_87)

@pytest.mark.parametrize(['seed', 'pk', 'sk'], data_87_kg)
def test_mldsa_87_keygen(mldsa_87_inst, seed, pk, sk):
  kg_pk, kg_sk = mldsa_87_inst._deterministicKeyGen(seed)
  assert kg_pk == pk
  assert kg_sk == sk


def load_sign_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (True, bytes.fromhex(v['seed']), bytes.fromhex(v['message']), bytes.fromhex(v['context']), bytes.fromhex(v['signature'])) for v in content['seed']
  ] + [
    (False, bytes.fromhex(v['sk']), bytes.fromhex(v['message']), bytes.fromhex(v['context']), bytes.fromhex(v['signature'])) for v in content['key']
  ]

def long_id_func(val):
  return val[0:64] if isinstance(val, bytes) else str(val)

data_44_sig = load_sign_json(cur_dir / 'nist_test_sign_44.json')

@pytest.mark.parametrize(['isKeyGen', 'secret', 'msg', 'ctx', 'sig'], data_44_sig, ids=long_id_func)
def test_mldsa_44_sign(mldsa_44_inst, isKeyGen, secret, msg, ctx, sig):
  if isKeyGen:
    _, sk = mldsa_44_inst._deterministicKeyGen(secret)
    mldsa_44_inst._testSetSecretKey(sk)
  else:
    mldsa_44_inst._testSetSecretKey(secret)
  gen_sig = mldsa_44_inst._deterministicSign(msg, ctx, b'\x00'*32)
  assert gen_sig == sig

data_65_sig = load_sign_json(cur_dir / 'nist_test_sign_65.json')

@pytest.mark.parametrize(['isKeyGen', 'secret', 'msg', 'ctx', 'sig'], data_65_sig, ids=long_id_func)
def test_mldsa_65_sign(mldsa_65_inst, isKeyGen, secret, msg, ctx, sig):
  if isKeyGen:
    _, sk = mldsa_65_inst._deterministicKeyGen(secret)
    mldsa_65_inst._testSetSecretKey(sk)
  else:
    mldsa_65_inst._testSetSecretKey(secret)
  gen_sig = mldsa_65_inst._deterministicSign(msg, ctx, b'\x00'*32)
  assert gen_sig == sig


data_87_sig = load_sign_json(cur_dir / 'nist_test_sign_87.json')

@pytest.mark.parametrize(['isKeyGen', 'secret', 'msg', 'ctx', 'sig'], data_87_sig, ids=long_id_func)
def test_mldsa_87_sign(mldsa_87_inst, isKeyGen, secret, msg, ctx, sig):
  if isKeyGen:
    _, sk = mldsa_87_inst._deterministicKeyGen(secret)
    mldsa_87_inst._testSetSecretKey(sk)
  else:
    mldsa_87_inst._testSetSecretKey(secret)
  gen_sig = mldsa_87_inst._deterministicSign(msg, ctx, b'\x00'*32)
  assert gen_sig == sig


def load_verify_json(fn: str):
  with open(fn, 'r') as f:
    content = json.load(f)
  return [
    (bytes.fromhex(v['pk']), bytes.fromhex(v['message']), bytes.fromhex(v['context']), bytes.fromhex(v['signature']), v['testPassed']) for v in content
  ]

data_44_vrfy = load_verify_json(cur_dir / 'nist_test_verify_44.json')

@pytest.mark.parametrize(['pk', 'msg', 'ctx', 'sig', 'passed'], data_44_vrfy, ids=long_id_func)
def test_mldsa_44_verify(mldsa_44_inst, pk, msg, ctx, sig, passed):
  res = mldsa_44_inst.Verify(pk, msg, sig, ctx)
  assert res == passed

data_65_vrfy = load_verify_json(cur_dir / 'nist_test_verify_65.json')

@pytest.mark.parametrize(['pk', 'msg', 'ctx', 'sig', 'passed'], data_65_vrfy, ids=long_id_func)
def test_mldsa_65_verify(mldsa_65_inst, pk, msg, ctx, sig, passed):
  res = mldsa_65_inst.Verify(pk, msg, sig, ctx)
  assert res == passed

data_87_vrfy = load_verify_json(cur_dir / 'nist_test_verify_87.json')

@pytest.mark.parametrize(['pk', 'msg', 'ctx', 'sig', 'passed'], data_87_vrfy, ids=long_id_func)
def test_mldsa_87_verify(mldsa_87_inst, pk, msg, ctx, sig, passed):
  res = mldsa_87_inst.Verify(pk, msg, sig, ctx)
  assert res == passed
