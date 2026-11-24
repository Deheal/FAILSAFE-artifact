from __future__ import annotations

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from failsafe.policies.profiles import POLICY_PROFILES
from failsafe.simulator.inference import FailsafeInference


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(20261111)


@pytest.fixture
def keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


@pytest.fixture
def failsafe() -> FailsafeInference:
    return FailsafeInference(prior_normal=0.85)


@pytest.fixture(params=list(POLICY_PROFILES.keys()))
def any_policy(request):
    return POLICY_PROFILES[request.param]


@pytest.fixture
def lenient_policy():
    return POLICY_PROFILES["P1_lenient"]


@pytest.fixture
def normal_counted_policy():
    return POLICY_PROFILES["P2_normal_counted"]


@pytest.fixture
def strict_policy():
    return POLICY_PROFILES["P3_strict"]


@pytest.fixture
def aggressive_policy():
    return POLICY_PROFILES["P4_aggressive"]