"""
Encrypted Redis-based store implementations.

Suitable for distributed / cloud deployments (multiple hosts or containers).
All values are Fernet-encrypted before being written to Redis, so the
Redis server never sees plaintext tokens or credentials.

Requires ``redis[asyncio] >= 5``::

    pip install "redis[asyncio]>=5"

Key layout (``{prefix}`` defaults to ``mcp:auth:``)::

    {prefix}token:{sha256(sub)}    ← encrypted token / credential data
    {prefix}pending:{sha256(key)}  ← encrypted pending-flow metadata (TTL set)
    {prefix}done:{sha256(key)}     ← encrypted completion result (short TTL)

Poll interval for ``wait_for_result``: 0.5 s.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Optional

from .base import PendingStore, TokenStore
from .encryption import decrypt, encrypt

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 0.5  # seconds between Redis GET polls


class RedisTokenStore(TokenStore):
    """
    Encrypted Redis token / credential store.

    Token expiry is managed lazily by the provider (same behaviour as
    ``MemoryTokenStore``) — no Redis TTL is set on token keys.
    """

    def __init__(self, redis_client, prefix: str = "mcp:auth:") -> None:
        self._r = redis_client
        self._prefix = prefix

    def _key(self, sub: str) -> str:
        return f"{self._prefix}token:{hashlib.sha256(sub.encode()).hexdigest()}"

    async def get(self, sub: str) -> Optional[dict]:
        k = self._key(sub)
        logger.debug("RedisTokenStore.get sub=%r redis_key=%s", sub, k)
        raw = await self._r.get(k)
        if raw is None:
            logger.debug("RedisTokenStore.get sub=%r → miss", sub)
            return None
        try:
            result = decrypt(raw)
            logger.debug("RedisTokenStore.get sub=%r → hit", sub)
            return result
        except Exception as exc:
            logger.warning("RedisTokenStore: decrypt failed for sub=%r: %s", sub[:8], exc)
            return None

    async def set(self, sub: str, value: dict) -> None:
        k = self._key(sub)
        logger.debug("RedisTokenStore.set sub=%r redis_key=%s", sub, k)
        await self._r.set(k, encrypt(value))

    async def delete(self, sub: str) -> None:
        k = self._key(sub)
        logger.debug("RedisTokenStore.delete sub=%r redis_key=%s", sub, k)
        await self._r.delete(k)


class RedisPendingStore(PendingStore):
    """
    Encrypted Redis pending store with polling-based ``wait_for_result``.

    Completion results live under a separate ``done:`` key with a short TTL
    so that ``pop`` and ``set_result`` are fully decoupled operations,
    matching the semantics of the file and memory backends.
    """

    def __init__(self, redis_client, prefix: str = "mcp:auth:") -> None:
        self._r = redis_client
        self._prefix = prefix

    def _pending_key(self, key: str) -> str:
        return f"{self._prefix}pending:{hashlib.sha256(key.encode()).hexdigest()}"

    def _done_key(self, key: str) -> str:
        return f"{self._prefix}done:{hashlib.sha256(key.encode()).hexdigest()}"

    async def create(self, key: str, metadata: dict, ttl: int) -> None:
        k = self._pending_key(key)
        logger.debug("RedisPendingStore.create key=%.8s ttl=%s redis_key=%s", key, ttl, k)
        await self._r.set(k, encrypt(metadata), ex=ttl)

    async def get(self, key: str) -> Optional[dict]:
        k = self._pending_key(key)
        logger.debug("RedisPendingStore.get key=%.8s redis_key=%s", key, k)
        raw = await self._r.get(k)
        if raw is None:
            logger.debug("RedisPendingStore.get key=%.8s → miss", key)
            return None
        try:
            result = decrypt(raw)
            logger.debug("RedisPendingStore.get key=%.8s → hit", key)
            return result
        except Exception as exc:
            logger.warning("RedisPendingStore: decrypt failed on get key=%r: %s", key[:8], exc)
            return None

    async def pop(self, key: str) -> Optional[dict]:
        pk = self._pending_key(key)
        logger.debug("RedisPendingStore.pop key=%.8s redis_key=%s", key, pk)
        pipe = self._r.pipeline()
        pipe.get(pk)
        pipe.delete(pk)
        raw, _ = await pipe.execute()
        if raw is None:
            logger.debug("RedisPendingStore.pop key=%.8s → miss", key)
            return None
        try:
            result = decrypt(raw)
            logger.debug("RedisPendingStore.pop key=%.8s → popped", key)
            return result
        except Exception as exc:
            logger.warning("RedisPendingStore: decrypt failed on pop key=%r: %s", key[:8], exc)
            return None

    async def set_result(self, key: str, result: dict, ttl: int = 120) -> None:
        dk = self._done_key(key)
        logger.debug("RedisPendingStore.set_result key=%.8s ttl=%s redis_key=%s", key, ttl, dk)
        await self._r.set(dk, encrypt(result), ex=ttl)

    async def wait_for_result(self, key: str, timeout: float) -> Optional[dict]:
        done_key = self._done_key(key)
        deadline = time.monotonic() + timeout
        logger.debug("RedisPendingStore.wait_for_result key=%.8s timeout=%s", key, timeout)
        while time.monotonic() < deadline:
            raw = await self._r.get(done_key)
            if raw is not None:
                # Consume atomically
                pipe = self._r.pipeline()
                pipe.get(done_key)
                pipe.delete(done_key)
                raw2, _ = await pipe.execute()
                if raw2 is None:
                    # Another waiter consumed it first (shouldn't happen, but be safe)
                    return None
                try:
                    result = decrypt(raw2)
                    logger.debug("RedisPendingStore.wait_for_result key=%.8s → got result", key)
                    return result
                except Exception as exc:
                    logger.warning(
                        "RedisPendingStore: decrypt failed on done key=%r: %s", key[:8], exc
                    )
                    return None
            await asyncio.sleep(_POLL_INTERVAL)
        logger.debug("RedisPendingStore.wait_for_result key=%.8s → timed out", key)
        return None
