"""
Tests for RedisTokenStore and RedisPendingStore using fakeredis.

No real Redis server required — fakeredis provides a full in-process
async Redis implementation.
"""

from __future__ import annotations

import asyncio

import fakeredis
import pytest
from cryptography.fernet import Fernet

from mcpauthkit.store.redis_store import RedisPendingStore, RedisTokenStore


@pytest.fixture(autouse=True)
def set_encryption_key(monkeypatch):
    monkeypatch.setenv("STORAGE_ENCRYPTION_KEY", Fernet.generate_key().decode())


@pytest.fixture()
def redis_client():
    return fakeredis.FakeAsyncRedis(decode_responses=False)


# ── RedisTokenStore ───────────────────────────────────────────────────────────


async def test_token_round_trip(redis_client):
    store = RedisTokenStore(redis_client)
    await store.set("alice", {"token": "abc123", "exp": 9999})
    assert await store.get("alice") == {"token": "abc123", "exp": 9999}


async def test_token_miss(redis_client):
    store = RedisTokenStore(redis_client)
    assert await store.get("alice") is None


async def test_token_overwrite(redis_client):
    store = RedisTokenStore(redis_client)
    await store.set("alice", {"token": "v1"})
    await store.set("alice", {"token": "v2"})
    assert await store.get("alice") == {"token": "v2"}


async def test_token_delete(redis_client):
    store = RedisTokenStore(redis_client)
    await store.set("alice", {"token": "abc"})
    await store.delete("alice")
    assert await store.get("alice") is None


async def test_token_delete_missing_is_noop(redis_client):
    store = RedisTokenStore(redis_client)
    await store.delete("nobody")  # must not raise


async def test_token_users_are_isolated(redis_client):
    store = RedisTokenStore(redis_client)
    await store.set("alice", {"token": "alice-tok"})
    await store.set("bob", {"token": "bob-tok"})
    assert (await store.get("alice")) == {"token": "alice-tok"}
    assert (await store.get("bob")) == {"token": "bob-tok"}


async def test_token_custom_prefix(redis_client):
    store = RedisTokenStore(redis_client, prefix="myapp:auth:")
    await store.set("alice", {"x": 1})
    assert await store.get("alice") == {"x": 1}
    # Confirm key is stored under the custom prefix
    pattern = b"myapp:auth:token:*"
    keys = await redis_client.keys(pattern)
    assert len(keys) == 1


async def test_token_decrypt_error_returns_none(redis_client):
    store = RedisTokenStore(redis_client)
    # Write corrupt bytes directly under the token key
    await redis_client.set(store._key("alice"), b"not-valid-fernet-ciphertext")
    assert await store.get("alice") is None


# ── RedisPendingStore ─────────────────────────────────────────────────────────


async def test_pending_round_trip(redis_client):
    store = RedisPendingStore(redis_client)
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    result = await store.get("state-1")
    assert result == {"sub": "alice"}


async def test_pending_get_miss(redis_client):
    store = RedisPendingStore(redis_client)
    assert await store.get("nonexistent") is None


async def test_pending_get_expired(redis_client):
    store = RedisPendingStore(redis_client)
    await store.create("state-1", {"sub": "alice"}, ttl=1)
    # Expire the key in fakeredis by setting its TTL to 0 directly
    await redis_client.expire(store._pending_key("state-1"), 0)
    assert await store.get("state-1") is None


async def test_pending_pop_removes(redis_client):
    store = RedisPendingStore(redis_client)
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    popped = await store.pop("state-1")
    assert popped == {"sub": "alice"}
    assert await store.get("state-1") is None


async def test_pending_pop_miss(redis_client):
    store = RedisPendingStore(redis_client)
    assert await store.pop("nonexistent") is None


async def test_pending_set_result_and_get(redis_client):
    store = RedisPendingStore(redis_client)
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    await store.set_result("state-1", {"access_token": "tok"}, ttl=60)
    # done key is separate from pending key
    assert await store.get("state-1") == {"sub": "alice"}


async def test_pending_wait_for_result(redis_client):
    store = RedisPendingStore(redis_client)
    await store.create("state-1", {"sub": "alice"}, ttl=60)

    async def signal():
        await asyncio.sleep(0.1)
        await store.set_result("state-1", {"access_token": "tok"}, ttl=60)

    task = asyncio.create_task(signal())
    result = await store.wait_for_result("state-1", timeout=3.0)
    assert result == {"access_token": "tok"}
    await task


async def test_pending_wait_timeout(redis_client):
    store = RedisPendingStore(redis_client)
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    result = await store.wait_for_result("state-1", timeout=0.1)
    assert result is None


async def test_pending_decrypt_error_on_get(redis_client):
    store = RedisPendingStore(redis_client)
    await redis_client.set(store._pending_key("bad-state"), b"not-valid-fernet-ciphertext")
    assert await store.get("bad-state") is None


async def test_pending_decrypt_error_on_pop(redis_client):
    store = RedisPendingStore(redis_client)
    await redis_client.set(store._pending_key("bad-state"), b"not-valid-fernet-ciphertext")
    assert await store.pop("bad-state") is None


async def test_pending_custom_prefix_isolation(redis_client):
    a = RedisPendingStore(redis_client, prefix="app1:")
    b = RedisPendingStore(redis_client, prefix="app2:")
    await a.create("state", {"sub": "alice"}, ttl=60)
    await b.create("state", {"sub": "bob"}, ttl=60)
    assert (await a.get("state")) == {"sub": "alice"}
    assert (await b.get("state")) == {"sub": "bob"}
