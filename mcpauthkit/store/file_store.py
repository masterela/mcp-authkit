"""
Encrypted file-based store implementations.

Suitable for multiple processes on the same host that share a filesystem
(e.g. several ``uvicorn`` workers behind a reverse proxy, or replicas
using a shared NFS / EFS volume).

Each entry is stored as a Fernet-encrypted JSON blob in its own file.
Atomic writes use the tmp-then-rename pattern (POSIX-safe).

Directory layout::

    {FILE_STORAGE_PATH}/
        tokens/
            {sha256(sub)[:16]}.enc          ← token / credential data
        pending/
            {sha256(key)[:16]}.enc          ← pending-flow metadata
            {sha256(key)[:16]}.done.enc     ← completion result (ephemeral)

Poll interval for ``wait_for_result``: 0.5 s — more than fast enough for
human-interactive OAuth / credential flows.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from pathlib import Path

from .base import PendingStore, TokenStore
from .encryption import decrypt, encrypt

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 0.5  # seconds between existence checks


def _safe_name(key: str) -> str:
    """Map an arbitrary string key to a safe, fixed-length filename."""
    return hashlib.sha256(key.encode()).hexdigest()


class FileTokenStore(TokenStore):
    """
    Encrypted file-based token / credential store.

    Each user's data is a separate ``.enc`` file named by the SHA-256 of
    their OIDC ``sub``, stored under ``{storage_path}/tokens/{namespace}/``.
    When *namespace* is omitted the subdirectory is simply ``tokens/``.
    """

    def __init__(self, storage_path: str, namespace: str | None = None) -> None:
        base = Path(storage_path) / "tokens"
        self._dir = base / namespace if namespace else base
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, sub: str) -> Path:
        return self._dir / f"{_safe_name(sub)}.enc"

    async def get(self, sub: str) -> dict | None:
        p = self._path(sub)
        logger.debug("FileTokenStore.get sub=%r file=%s", sub, p.name)
        if not p.exists():
            logger.debug("FileTokenStore.get sub=%r → miss", sub)
            return None
        try:
            result = decrypt(p.read_bytes())
            logger.debug("FileTokenStore.get sub=%r → hit", sub)
            return result
        except Exception as exc:
            logger.warning(
                "FileTokenStore: could not decrypt entry for sub=%r (%s). "
                "This usually means the encryption key changed. "
                "The stale entry will be removed — the user will be re-prompted once.",
                sub[:8], exc,
            )
            p.unlink(missing_ok=True)
            return None

    async def set(self, sub: str, value: dict) -> None:
        p = self._path(sub)
        logger.debug("FileTokenStore.set sub=%r → %s", sub, p.name)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(encrypt(value))
        tmp.replace(p)  # atomic on POSIX

    async def delete(self, sub: str) -> None:
        p = self._path(sub)
        logger.debug("FileTokenStore.delete sub=%r existed=%s", sub, p.exists())
        p.unlink(missing_ok=True)


class FilePendingStore(PendingStore):
    """
    Encrypted file-based pending store with polling-based ``wait_for_result``.

    Completion results are written to a separate ``.done.enc`` sidecar file
    so that ``pop`` (removes the pending entry) and ``set_result`` (writes the
    completion file) are fully independent operations.
    """

    def __init__(self, storage_path: str) -> None:
        self._dir = Path(storage_path) / "pending"
        self._dir.mkdir(parents=True, exist_ok=True)

    def _meta_path(self, key: str) -> Path:
        return self._dir / f"{_safe_name(key)}.enc"

    def _done_path(self, key: str) -> Path:
        return self._dir / f"{_safe_name(key)}.done.enc"

    async def create(self, key: str, metadata: dict, ttl: int) -> None:
        p = self._meta_path(key)
        logger.debug("FilePendingStore.create key=%.8s ttl=%s → %s", key, ttl, p.name)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(encrypt({**metadata, "_expires": time.time() + ttl}))
        tmp.replace(p)

    async def get(self, key: str) -> dict | None:
        p = self._meta_path(key)
        logger.debug("FilePendingStore.get key=%.8s", key)
        if not p.exists():
            logger.debug("FilePendingStore.get key=%.8s → miss", key)
            return None
        try:
            entry = decrypt(p.read_bytes())
            if time.time() > entry.get("_expires", 0):
                p.unlink(missing_ok=True)
                logger.debug("FilePendingStore.get key=%.8s → expired", key)
                return None
            logger.debug("FilePendingStore.get key=%.8s → hit", key)
            return {k: v for k, v in entry.items() if not k.startswith("_")}
        except Exception as exc:
            logger.warning("FilePendingStore: decrypt failed on get key=%r: %s", key[:8], exc)
            return None

    async def pop(self, key: str) -> dict | None:
        p = self._meta_path(key)
        if not p.exists():
            logger.debug("FilePendingStore.pop key=%.8s → miss", key)
            return None
        try:
            entry = decrypt(p.read_bytes())
            p.unlink(missing_ok=True)
            logger.debug("FilePendingStore.pop key=%.8s → popped", key)
            return {k: v for k, v in entry.items() if not k.startswith("_")}
        except Exception as exc:
            logger.warning("FilePendingStore: decrypt failed on pop key=%r: %s", key[:8], exc)
            p.unlink(missing_ok=True)
            return None

    async def set_result(self, key: str, result: dict, ttl: int = 120) -> None:
        p = self._done_path(key)
        logger.debug("FilePendingStore.set_result key=%.8s ttl=%s → %s", key, ttl, p.name)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(encrypt({**result, "_expires": time.time() + ttl}))
        tmp.replace(p)

    async def wait_for_result(self, key: str, timeout: float) -> dict | None:
        done_path = self._done_path(key)
        deadline = time.monotonic() + timeout
        logger.debug("FilePendingStore.wait_for_result key=%.8s timeout=%s", key, timeout)
        while time.monotonic() < deadline:
            if done_path.exists():
                try:
                    entry = decrypt(done_path.read_bytes())
                    done_path.unlink(missing_ok=True)
                    logger.debug("FilePendingStore.wait_for_result key=%.8s → got result", key)
                    return {k: v for k, v in entry.items() if not k.startswith("_")}
                except Exception as exc:
                    logger.warning(
                        "FilePendingStore: decrypt failed on done key=%r: %s", key[:8], exc
                    )
                    done_path.unlink(missing_ok=True)
                    return None
            await asyncio.sleep(_POLL_INTERVAL)
        logger.debug("FilePendingStore.wait_for_result key=%.8s → timed out", key)
        return None
