"""
Abstract base classes for the two store types used by auth providers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class TokenStore(ABC):
    """
    Persistent, encrypted store for user tokens and credentials.

    Keyed by the primary OIDC ``sub`` claim.  Values are arbitrary
    JSON-serialisable dicts (``TokenData`` for OAuth, or
    ``{field: value}`` for credentials providers).
    """

    @abstractmethod
    async def get(self, sub: str) -> Optional[dict]:
        """Return the stored dict for *sub*, or ``None`` if absent."""

    @abstractmethod
    async def set(self, sub: str, value: dict) -> None:
        """Persist *value* for *sub*, overwriting any existing entry."""

    @abstractmethod
    async def delete(self, sub: str) -> None:
        """Remove the entry for *sub* (no-op if absent)."""


class PendingStore(ABC):
    """
    Ephemeral, encrypted store for in-flight elicitation state.

    Each entry has a short-lived opaque key (the OAuth ``state`` parameter
    or the credential-form entry token) and carries only
    JSON-serialisable metadata (``sub``, ``expires_at``, …).
    Non-serialisable objects (``asyncio.Event``, MCP sessions) are kept
    in the provider's local ``_sessions`` dict.

    Signal / wait semantics
    -----------------------
    The callback handler calls ``set_result`` once the token or
    credentials are ready.  The decorator that is waiting for that
    outcome calls ``wait_for_result`` to block until the result arrives
    or the timeout expires.

    * **memory** — backed by ``asyncio.Event``; zero-overhead wait.
    * **file / redis** — backed by polling at 0.5 s intervals; fully
      adequate for human-interactive flows.
    """

    @abstractmethod
    async def create(self, key: str, metadata: dict, ttl: int) -> None:
        """Create a new pending entry that expires in *ttl* seconds."""

    @abstractmethod
    async def get(self, key: str) -> Optional[dict]:
        """Return the metadata for *key*, or ``None`` if absent / expired."""

    @abstractmethod
    async def pop(self, key: str) -> Optional[dict]:
        """Return and atomically delete the metadata for *key*."""

    @abstractmethod
    async def set_result(self, key: str, result: dict, ttl: int = 120) -> None:
        """
        Store the completion result for *key* and wake any waiter.

        Called by the instance that received the OAuth callback or the
        credential form submission.  ``ttl`` controls how long the result
        is kept (important for file / redis; in-memory it is discarded
        after the waiter consumes it).
        """

    @abstractmethod
    async def wait_for_result(self, key: str, timeout: float) -> Optional[dict]:
        """
        Block until a result is available for *key*, then return it.

        Returns ``None`` on timeout.  Implementations MUST consume (delete)
        the result entry so it is not returned twice.
        """
