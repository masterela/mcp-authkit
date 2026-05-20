"""
Shared fixtures for the mcpauthkit test suite.
"""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet


@pytest.fixture()
def fernet_key() -> str:
    """Return a freshly generated Fernet key (base64 string)."""
    return Fernet.generate_key().decode()


@pytest.fixture(autouse=True)
def reset_fernet_singleton(monkeypatch):
    """
    Reset the module-level _fernet singleton before every test so that key
    resolution is exercised fresh and tests cannot leak encryption state.
    """
    import mcpauthkit.store.encryption as enc_mod
    monkeypatch.setattr(enc_mod, "_fernet", None)
