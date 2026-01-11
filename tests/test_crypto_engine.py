import os
import pytest
from core.crypto.engine import CryptoEngine


def test_wrap_unwrap_master_key():
    ce = CryptoEngine()
    mk = ce.generate_master_key()
    wrapped = ce.wrap_master_key(mk, "password123")
    unwrapped = ce.unwrap_master_key(wrapped, "password123")
    assert unwrapped == mk


def test_unwrap_wrong_password_raises():
    ce = CryptoEngine()
    mk = ce.generate_master_key()
    wrapped = ce.wrap_master_key(mk, "password123")
    with pytest.raises(ValueError):
        ce.unwrap_master_key(wrapped, "badpass")
