"""
Tests for the store factory — backend selection and namespace wiring.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from mcpauthkit.store.factory import create_stores
from mcpauthkit.store.file_store import FileTokenStore
from mcpauthkit.store.memory import MemoryPendingStore, MemoryTokenStore


@pytest.fixture()
def enc_key(monkeypatch) -> str:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", key)
    return key


# ── Mode selection ────────────────────────────────────────────────────────────


def test_default_mode_is_memory(monkeypatch):
    monkeypatch.delenv("TOKEN_STORAGE_MODE", raising=False)
    ts, ps = create_stores()
    assert isinstance(ts, MemoryTokenStore)
    assert isinstance(ps, MemoryPendingStore)


def test_explicit_memory_mode():
    ts, ps = create_stores(mode="memory")
    assert isinstance(ts, MemoryTokenStore)
    assert isinstance(ps, MemoryPendingStore)


def test_file_mode(enc_key, tmp_path):
    ts, _ = create_stores(mode="file", file_path=str(tmp_path))
    assert isinstance(ts, FileTokenStore)


def test_file_mode_env_var(monkeypatch, enc_key, tmp_path):
    monkeypatch.setenv("TOKEN_STORAGE_MODE", "file")
    monkeypatch.setenv("FILE_STORAGE_PATH", str(tmp_path))
    ts, _ = create_stores()
    assert isinstance(ts, FileTokenStore)


# ── Encryption key validation ─────────────────────────────────────────────────


def test_file_mode_raises_without_key(monkeypatch, tmp_path):
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY_PATH", raising=False)
    with pytest.raises(RuntimeError, match="encryption key"):
        create_stores(mode="file", file_path=str(tmp_path))


def test_redis_mode_raises_without_key(monkeypatch):
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("STORAGE_ENCRYPTION_KEY_PATH", raising=False)
    with pytest.raises(RuntimeError, match="encryption key"):
        create_stores(mode="redis")


# ── Namespace wiring ──────────────────────────────────────────────────────────


def test_file_namespace_creates_subdirectory(enc_key, tmp_path):
    ts, _ = create_stores(mode="file", file_path=str(tmp_path), namespace="github")
    assert isinstance(ts, FileTokenStore)
    assert "github" in str(ts._dir)


def test_no_namespace_uses_tokens_root(enc_key, tmp_path):
    ts, _ = create_stores(mode="file", file_path=str(tmp_path))
    assert isinstance(ts, FileTokenStore)
    assert "github" not in str(ts._dir)


# ── Redis mode ────────────────────────────────────────────────────────────────


def test_redis_mode_returns_redis_stores(enc_key):
    from unittest.mock import patch

    import fakeredis

    from mcpauthkit.store.redis_store import RedisPendingStore, RedisTokenStore

    fake_redis = fakeredis.FakeAsyncRedis()
    with patch("redis.asyncio.from_url", return_value=fake_redis):
        ts, ps = create_stores(mode="redis", redis_url="redis://localhost/0")

    assert isinstance(ts, RedisTokenStore)
    assert isinstance(ps, RedisPendingStore)


def test_redis_namespace_applied_to_prefix(enc_key):
    from unittest.mock import patch

    import fakeredis

    from mcpauthkit.store.redis_store import RedisTokenStore

    fake_redis = fakeredis.FakeAsyncRedis()
    with patch("redis.asyncio.from_url", return_value=fake_redis):
        ts, _ = create_stores(mode="redis", redis_url="redis://localhost/0", namespace="github")

    assert isinstance(ts, RedisTokenStore)
    assert "github" in ts._prefix
