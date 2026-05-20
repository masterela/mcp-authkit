"""
Tests for mcpauthkit.store.encryption — Fernet key resolution and round-trip.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

import mcpauthkit.store.encryption as enc_mod
from mcpauthkit.store.encryption import decrypt, encrypt, get_fernet

# ── Key resolution ────────────────────────────────────────────────────────────


def test_key_from_env_var(monkeypatch, fernet_key):
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", fernet_key)
    f = get_fernet()
    assert f is not None


def test_key_from_file(monkeypatch, tmp_path, fernet_key):
    key_file = tmp_path / "enc.key"
    key_file.write_bytes(fernet_key.encode())
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY_PATH", str(key_file))
    f = get_fernet()
    assert f is not None


def test_ephemeral_key_generated_when_no_config(monkeypatch):
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY_PATH", raising=False)
    # Should not raise — falls back to ephemeral key with a warning
    f = get_fernet()
    assert f is not None


def test_singleton_reused(monkeypatch, fernet_key):
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", fernet_key)
    f1 = get_fernet()
    f2 = get_fernet()
    assert f1 is f2


# ── Encrypt / decrypt ─────────────────────────────────────────────────────────


def test_round_trip(monkeypatch, fernet_key):
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", fernet_key)
    data = {"access_token": "tok-abc", "sub": "alice", "count": 42}
    assert decrypt(encrypt(data)) == data


def test_nested_dict_round_trip(monkeypatch, fernet_key):
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", fernet_key)
    data = {"user": {"sub": "u1", "roles": ["admin", "user"]}, "exp": 9999}
    assert decrypt(encrypt(data)) == data


def test_wrong_key_raises(monkeypatch):
    key_a = Fernet.generate_key().decode()
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", key_a)
    blob = encrypt({"secret": "value"})

    # Switch to a different key
    monkeypatch.setattr(enc_mod, "_fernet", None)
    key_b = Fernet.generate_key().decode()
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", key_b)

    with pytest.raises((InvalidToken, ValueError)):
        decrypt(blob)
