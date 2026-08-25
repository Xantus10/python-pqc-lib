import pytest

from python_pqc_lib.dsa import *

@pytest.fixture
def slh_dsa_sha2_128f_inst():
  return SLHDSA(SLHDSA_SHA2_128_FAST)

@pytest.fixture
def slh_dsa_sha2_128s_inst():
  return SLHDSA(SLHDSA_SHA2_128_SMALL)

@pytest.fixture
def slh_dsa_sha2_192f_inst():
  return SLHDSA(SLHDSA_SHA2_192_FAST)

@pytest.fixture
def slh_dsa_sha2_192s_inst():
  return SLHDSA(SLHDSA_SHA2_192_SMALL)

@pytest.fixture
def slh_dsa_sha2_256f_inst():
  return SLHDSA(SLHDSA_SHA2_256_FAST)

@pytest.fixture
def slh_dsa_sha2_256s_inst():
  return SLHDSA(SLHDSA_SHA2_256_SMALL)

@pytest.fixture
def slh_dsa_shake_128f_inst():
  return SLHDSA(SLHDSA_SHAKE_128_FAST)

@pytest.fixture
def slh_dsa_shake_128s_inst():
  return SLHDSA(SLHDSA_SHAKE_128_SMALL)

@pytest.fixture
def slh_dsa_shake_192f_inst():
  return SLHDSA(SLHDSA_SHAKE_192_FAST)

@pytest.fixture
def slh_dsa_shake_192s_inst():
  return SLHDSA(SLHDSA_SHAKE_192_SMALL)

@pytest.fixture
def slh_dsa_shake_256f_inst():
  return SLHDSA(SLHDSA_SHAKE_256_FAST)

@pytest.fixture
def slh_dsa_shake_256s_inst():
  return SLHDSA(SLHDSA_SHAKE_256_SMALL)

@pytest.fixture
def crypto_instance(request):
  """
  Maps a string parameterSet name to the corresponding fixture
  """
  def _inner(parameter_set_name: str):
    return request.getfixturevalue(f'{parameter_set_name.lower().replace("-", "_")}_inst')
  return _inner
