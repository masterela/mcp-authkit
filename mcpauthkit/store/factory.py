"""
Store factory — creates a (TokenStore, PendingStore) pair from configuration.

Reads ``TOKEN_STORAGE_MODE`` (and related env vars) unless overrides are
passed explicitly.  Call once at startup and inject the pair into every
provider that needs storage.

Example::

    from mcpauthkit.store import create_stores

    token_store, pending_store = create_stores()

    github_oauth = OAuthProvider.from_standard_oauth2(
        ...,
        token_store=token_store,
        pending_store=pending_store,
    )
"""
from __future__ import annotations

import logging
import os
from typing import Tuple

from .base import PendingStore, TokenStore
from .memory import MemoryPendingStore, MemoryTokenStore

logger = logging.getLogger(__name__)


def _require_encryption_key(mode: str) -> None:
    """
    Raise ``RuntimeError`` if neither ``STORAGE_ENCRYPTION_KEY`` nor
    ``STORAGE_ENCRYPTION_KEY_PATH`` is present in the OS environment.

    Called before creating file or redis stores, where a stable key is
    required for data to survive restarts.  The key must be exported in
    the shell environment — values only in a ``.env`` file are not
    sufficient because Pydantic Settings does not write them to ``os.environ``.
    """
    if os.environ.get("STORAGE_ENCRYPTION_KEY") or os.environ.get("STORAGE_ENCRYPTION_KEY_PATH"):
        logger.debug("encryption: key found in OS environment")
        return
    raise RuntimeError(
        f"TOKEN_STORAGE_MODE={mode!r} requires an encryption key exported in the shell environment.\n"
        "Set one of:\n"
        "  export STORAGE_ENCRYPTION_KEY=<base64-fernet-key>\n"
        "  export STORAGE_ENCRYPTION_KEY_PATH=<path-to-key-file>\n"
        "Values defined only in a .env file are not visible to the process environment."
    )


def create_stores(
    *,
    mode: str | None = None,
    file_path: str | None = None,
    redis_url: str | None = None,
    redis_prefix: str | None = None,
    namespace: str | None = None,
) -> Tuple[TokenStore, PendingStore]:
    """
    Return a ``(TokenStore, PendingStore)`` pair for the requested mode.

    Parameters (all optional — fall back to environment variables)
    -------------------------------------------------------------
    mode
        ``"memory"`` | ``"file"`` | ``"redis"``.
        Overrides ``TOKEN_STORAGE_MODE`` env var (default: ``"memory"``).
    file_path
        Root directory for file storage.
        Overrides ``FILE_STORAGE_PATH`` env var (default: ``/tmp/mcp-auth-store``).
    redis_url
        Redis connection URL.
        Overrides ``REDIS_URL`` env var (default: ``redis://localhost:6379/0``).
    redis_prefix
        Redis key prefix.
        Overrides ``REDIS_KEY_PREFIX`` env var (default: ``mcp:auth:``).
    namespace
        Optional provider namespace. For file mode, creates a subdirectory
        inside ``tokens/`` so different providers don't share filenames.
        For Redis mode, appended to the key prefix (e.g. ``mcp:auth:github:``).
    """
    resolved_mode = (mode or os.environ.get("TOKEN_STORAGE_MODE", "memory")).lower().strip()
    logger.info("Token storage mode: %s", resolved_mode)

    if resolved_mode == "memory":
        return MemoryTokenStore(), MemoryPendingStore()

    if resolved_mode == "file":
        _require_encryption_key(resolved_mode)
        from .file_store import FilePendingStore, FileTokenStore

        path = file_path or os.environ.get("FILE_STORAGE_PATH", "/tmp/mcp-auth-store")
        logger.info("File storage path: %s  namespace: %s", path, namespace or "(none)")
        return FileTokenStore(path, namespace=namespace), FilePendingStore(path)

    if resolved_mode == "redis":
        _require_encryption_key(resolved_mode)
        try:
            import redis.asyncio as aioredis
        except ImportError as exc:
            raise ImportError(
                "TOKEN_STORAGE_MODE=redis requires 'redis[asyncio]>=5'. "
                "Install it with:  pip install 'redis[asyncio]>=5'"
            ) from exc

        from .redis_store import RedisPendingStore, RedisTokenStore

        url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        prefix = redis_prefix or os.environ.get("REDIS_KEY_PREFIX", "mcp:auth:")
        if namespace:
            prefix = f"{prefix.rstrip(':')}:{namespace}:"
        logger.info("Redis URL: %s  key prefix: %s", url, prefix)
        client = aioredis.from_url(url, decode_responses=False)
        return RedisTokenStore(client, prefix), RedisPendingStore(client, prefix)

    raise ValueError(
        f"Unknown TOKEN_STORAGE_MODE {resolved_mode!r}. "
        "Valid values: memory, file, redis"
    )
