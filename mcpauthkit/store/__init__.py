"""
lib.store — pluggable encrypted storage for tokens and elicitation state.

Choose a backend via the ``TOKEN_STORAGE_MODE`` environment variable:

    memory      In-process dict.  Zero latency; state lost on restart.
                Suitable for a single-process server (default).

    file        Fernet-encrypted JSON files in ``FILE_STORAGE_PATH``.
                Suitable for multiple processes on the same host that
                share a filesystem (e.g. replicas with a shared volume).

    redis       Fernet-encrypted values in Redis.
                Suitable for distributed / cloud deployments.

Encryption key resolution (file and redis modes):
    1. ``STORAGE_ENCRYPTION_KEY``      — base64-encoded Fernet key in env
    2. ``STORAGE_ENCRYPTION_KEY_PATH`` — path to a file containing the key
    3. Auto-generate ephemeral key (warns; tokens lost on restart)

    Future: point ``STORAGE_ENCRYPTION_KEY_PATH`` at a path managed by
    AWS KMS, HashiCorp Vault, or another external KMS to enable key rotation
    without changing application code.
"""

from .base import PendingStore, TokenStore
from .factory import create_stores
from .memory import MemoryPendingStore, MemoryTokenStore

__all__ = [
    "MemoryPendingStore",
    "MemoryTokenStore",
    "PendingStore",
    "TokenStore",
    "create_stores",
]
