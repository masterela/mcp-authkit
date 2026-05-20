"""
Tests for MemoryTokenStore and MemoryPendingStore.
"""

from __future__ import annotations

import asyncio

from mcpauthkit.store.memory import MemoryPendingStore, MemoryTokenStore

# ── MemoryTokenStore ──────────────────────────────────────────────────────────


async def test_get_miss():
    store = MemoryTokenStore()
    assert await store.get("alice") is None


async def test_set_then_get():
    store = MemoryTokenStore()
    await store.set("alice", {"token": "abc123"})
    assert await store.get("alice") == {"token": "abc123"}


async def test_overwrite():
    store = MemoryTokenStore()
    await store.set("alice", {"token": "v1"})
    await store.set("alice", {"token": "v2"})
    assert await store.get("alice") == {"token": "v2"}


async def test_delete_removes_entry():
    store = MemoryTokenStore()
    await store.set("alice", {"token": "abc123"})
    await store.delete("alice")
    assert await store.get("alice") is None


async def test_delete_missing_is_noop():
    store = MemoryTokenStore()
    await store.delete("nobody")  # must not raise


async def test_users_are_isolated():
    store = MemoryTokenStore()
    await store.set("alice", {"token": "alice-tok"})
    await store.set("bob", {"token": "bob-tok"})
    assert (await store.get("alice")) == {"token": "alice-tok"}
    assert (await store.get("bob")) == {"token": "bob-tok"}


# ── MemoryPendingStore ────────────────────────────────────────────────────────


async def test_pending_create_then_get():
    store = MemoryPendingStore()
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    result = await store.get("state-1")
    assert result == {"sub": "alice"}


async def test_pending_get_miss():
    store = MemoryPendingStore()
    assert await store.get("nonexistent") is None


async def test_pending_get_strips_private_keys():
    store = MemoryPendingStore()
    await store.create("state-1", {"sub": "alice", "redirect": "http://x"}, ttl=60)
    result = await store.get("state-1")
    assert "_expires" not in result
    assert result["sub"] == "alice"


async def test_pending_pop_returns_and_removes():
    store = MemoryPendingStore()
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    popped = await store.pop("state-1")
    assert popped == {"sub": "alice"}
    assert await store.get("state-1") is None


async def test_pending_pop_miss():
    store = MemoryPendingStore()
    assert await store.pop("nonexistent") is None


async def test_pending_expired_entry_returns_none():
    store = MemoryPendingStore()
    await store.create("state-1", {"sub": "alice"}, ttl=0)
    await asyncio.sleep(0.01)
    assert await store.get("state-1") is None


async def test_wait_for_result_receives_signal():
    store = MemoryPendingStore()
    await store.create("state-1", {"sub": "alice"}, ttl=60)

    async def signal():
        await asyncio.sleep(0.05)
        await store.set_result("state-1", {"access_token": "tok"})

    task = asyncio.create_task(signal())
    result = await store.wait_for_result("state-1", timeout=2.0)
    assert result == {"access_token": "tok"}
    await task


async def test_wait_for_result_timeout():
    store = MemoryPendingStore()
    await store.create("state-1", {"sub": "alice"}, ttl=60)
    result = await store.wait_for_result("state-1", timeout=0.05)
    assert result is None


async def test_wait_for_result_no_entry():
    store = MemoryPendingStore()
    result = await store.wait_for_result("unknown", timeout=0.05)
    assert result is None
