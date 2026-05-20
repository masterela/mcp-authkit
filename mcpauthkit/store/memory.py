"""
In-memory store implementations (single-process, no persistence).

``MemoryTokenStore``   — plain dict, keyed by OIDC sub.
``MemoryPendingStore`` — dict + asyncio.Event for zero-overhead signalling.

State is lost on server restart.  No encryption — data lives only in
process memory.  Suitable for single-process deployments.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from .base import PendingStore, TokenStore

logger = logging.getLogger(__name__)


class MemoryTokenStore(TokenStore):
    """Plain in-memory token / credential store."""

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}

    async def get(self, sub: str) -> Optional[dict]:
        result = self._data.get(sub)
        logger.debug("MemoryTokenStore.get sub=%r → %s", sub, "hit" if result is not None else "miss")
        return result

    async def set(self, sub: str, value: dict) -> None:
        logger.debug("MemoryTokenStore.set sub=%r", sub)
        self._data[sub] = value

    async def delete(self, sub: str) -> None:
        existed = sub in self._data
        self._data.pop(sub, None)
        logger.debug("MemoryTokenStore.delete sub=%r existed=%s", sub, existed)


class MemoryPendingStore(PendingStore):
    """
    In-memory pending store.

    Two internal dicts keep metadata and completion results separate so
    that ``pop`` (which removes the pending entry) and ``set_result``
    (which signals the waiter) are fully decoupled:

    ``_pending``  key → {metadata, _expires}
    ``_done``     key → {asyncio.Event, result}
    """

    def __init__(self) -> None:
        self._pending: dict[str, dict] = {}
        self._done: dict[str, dict] = {}

    async def create(self, key: str, metadata: dict, ttl: int) -> None:
        logger.debug("MemoryPendingStore.create key=%.8s ttl=%s", key, ttl)
        self._pending[key] = {**metadata, "_expires": time.monotonic() + ttl}
        self._done[key] = {"event": asyncio.Event(), "result": None}

    async def get(self, key: str) -> Optional[dict]:
        entry = self._pending.get(key)
        if entry is None:
            logger.debug("MemoryPendingStore.get key=%.8s → miss", key)
            return None
        if time.monotonic() > entry["_expires"]:
            self._pending.pop(key, None)
            logger.debug("MemoryPendingStore.get key=%.8s → expired", key)
            return None
        logger.debug("MemoryPendingStore.get key=%.8s → hit", key)
        return {k: v for k, v in entry.items() if not k.startswith("_")}

    async def pop(self, key: str) -> Optional[dict]:
        entry = self._pending.pop(key, None)
        if entry is None:
            logger.debug("MemoryPendingStore.pop key=%.8s → miss", key)
            return None
        logger.debug("MemoryPendingStore.pop key=%.8s → popped", key)
        return {k: v for k, v in entry.items() if not k.startswith("_")}

    async def set_result(self, key: str, result: dict, ttl: int = 120) -> None:
        # ttl is unused for in-memory (result consumed immediately by waiter)
        done = self._done.get(key)
        logger.debug("MemoryPendingStore.set_result key=%.8s event_found=%s", key, done is not None)
        if done is not None:
            done["result"] = result
            done["event"].set()

    async def wait_for_result(self, key: str, timeout: float) -> Optional[dict]:
        done = self._done.get(key)
        if done is None:
            logger.debug("MemoryPendingStore.wait_for_result key=%.8s → no entry", key)
            return None
        logger.debug("MemoryPendingStore.wait_for_result key=%.8s waiting (timeout=%s)", key, timeout)
        try:
            await asyncio.wait_for(done["event"].wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.debug("MemoryPendingStore.wait_for_result key=%.8s → timed out", key)
            return None
        result = done.get("result")
        self._done.pop(key, None)  # consume
        logger.debug("MemoryPendingStore.wait_for_result key=%.8s → got result", key)
        return result
