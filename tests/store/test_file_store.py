"""
Tests for FileTokenStore and FilePendingStore.
"""

from __future__ import annotations

import asyncio
import hashlib

import pytest
from cryptography.fernet import Fernet

from mcpauthkit.store.file_store import FilePendingStore, FileTokenStore


@pytest.fixture(autouse=True)
def set_encryption_key(monkeypatch):
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", Fernet.generate_key().decode())


# ── FileTokenStore ────────────────────────────────────────────────────────────


async def test_token_round_trip(tmp_path):
    store = FileTokenStore(str(tmp_path))
    await store.set("alice", {"token": "abc123", "exp": 9999})
    assert await store.get("alice") == {"token": "abc123", "exp": 9999}


async def test_token_miss(tmp_path):
    store = FileTokenStore(str(tmp_path))
    assert await store.get("alice") is None


async def test_token_overwrite(tmp_path):
    store = FileTokenStore(str(tmp_path))
    await store.set("alice", {"token": "v1"})
    await store.set("alice", {"token": "v2"})
    assert await store.get("alice") == {"token": "v2"}


async def test_token_delete(tmp_path):
    store = FileTokenStore(str(tmp_path))
    await store.set("alice", {"token": "abc"})
    await store.delete("alice")
    assert await store.get("alice") is None


async def test_token_delete_missing_is_noop(tmp_path):
    store = FileTokenStore(str(tmp_path))
    await store.delete("nobody")  # must not raise


async def test_namespace_isolates_users(tmp_path):
    gh = FileTokenStore(str(tmp_path), namespace="github")
    cf = FileTokenStore(str(tmp_path), namespace="confluence")
    await gh.set("alice", {"provider": "github"})
    await cf.set("alice", {"provider": "confluence"})
    assert (await gh.get("alice")) == {"provider": "github"}
    assert (await cf.get("alice")) == {"provider": "confluence"}


async def test_namespace_creates_subdirectory(tmp_path):
    store = FileTokenStore(str(tmp_path), namespace="github")
    assert store._dir == tmp_path / "tokens" / "github"


async def test_no_namespace_uses_tokens_dir(tmp_path):
    store = FileTokenStore(str(tmp_path))
    assert store._dir == tmp_path / "tokens"


async def test_file_named_by_sha256(tmp_path):
    store = FileTokenStore(str(tmp_path))
    await store.set("alice", {"x": 1})
    expected_name = hashlib.sha256(b"alice").hexdigest() + ".enc"
    assert (store._dir / expected_name).exists()


async def test_corrupt_file_returns_none(tmp_path):
    store = FileTokenStore(str(tmp_path))
    bad_name = hashlib.sha256(b"alice").hexdigest() + ".enc"
    store._dir.mkdir(parents=True, exist_ok=True)
    (store._dir / bad_name).write_bytes(b"not-valid-fernet-ciphertext")
    assert await store.get("alice") is None


# ── FilePendingStore ──────────────────────────────────────────────────────────


async def test_pending_round_trip(tmp_path):
    store = FilePendingStore(str(tmp_path))
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    result = await store.get("state-1")
    assert result == {"sub": "alice"}


async def test_pending_get_miss(tmp_path):
    store = FilePendingStore(str(tmp_path))
    assert await store.get("nonexistent") is None


async def test_pending_pop_removes(tmp_path):
    store = FilePendingStore(str(tmp_path))
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    popped = await store.pop("state-1")
    assert popped == {"sub": "alice"}
    assert await store.get("state-1") is None


async def test_pending_expired(tmp_path):
    store = FilePendingStore(str(tmp_path))
    await store.create("state-1", {"sub": "alice"}, ttl=0)
    await asyncio.sleep(0.01)
    assert await store.get("state-1") is None


async def test_pending_wait_for_result(tmp_path):
    store = FilePendingStore(str(tmp_path))
    await store.create("state-1", {"sub": "alice"}, ttl=60)

    async def signal():
        await asyncio.sleep(0.1)
        await store.set_result("state-1", {"access_token": "tok"}, ttl=60)

    task = asyncio.create_task(signal())
    result = await store.wait_for_result("state-1", timeout=3.0)
    assert result == {"access_token": "tok"}
    await task


async def test_pending_wait_timeout(tmp_path):
    store = FilePendingStore(str(tmp_path))
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    # poll interval is 0.5s, timeout < that → times out immediately
    result = await store.wait_for_result("state-1", timeout=0.1)
    assert result is None


async def test_pending_pop_miss(tmp_path):
    store = FilePendingStore(str(tmp_path))
    assert await store.pop("nonexistent") is None


async def test_pending_corrupt_file_on_get(tmp_path):
    """Corrupt .enc file → get() returns None without raising."""
    store = FilePendingStore(str(tmp_path))
    bad_path = store._meta_path("state-1")
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_bytes(b"not-valid-fernet-ciphertext")
    assert await store.get("state-1") is None


async def test_pending_corrupt_file_on_pop(tmp_path):
    """Corrupt .enc file → pop() returns None without raising."""
    store = FilePendingStore(str(tmp_path))
    bad_path = store._meta_path("state-1")
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_bytes(b"not-valid-fernet-ciphertext")
    assert await store.pop("state-1") is None


async def test_pending_corrupt_done_on_wait_for_result(tmp_path):
    """Corrupt .done.enc file → wait_for_result() returns None without raising."""
    store = FilePendingStore(str(tmp_path))
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    store._done_path("state-1").write_bytes(b"not-valid-fernet-ciphertext")
    result = await store.wait_for_result("state-1", timeout=1.0)
    assert result is None
