"""
Symmetric encryption for at-rest token / credential data.

Key resolution order
--------------------
1. ``STORAGE_ENCRYPTION_KEY``      env var — base64-encoded Fernet key
                                    (44-char URL-safe base64 string produced by
                                    ``Fernet.generate_key()``)
2. ``STORAGE_ENCRYPTION_KEY_PATH`` env var — filesystem path to a file whose
                                    contents are the base64 key (or raw 32 bytes)
3. Auto-generate an ephemeral key  — logs a warning; tokens and credentials are
                                    NOT portable across restarts

Future KMS / Vault integration
-------------------------------
Set ``STORAGE_ENCRYPTION_KEY_PATH`` to a path managed by an external secrets
manager (AWS Secrets Manager, AWS KMS data-key download, HashiCorp Vault
agent template, etc.).  Rotate the key by updating the path contents and
restarting the server — no code change required.

For AWS KMS envelope encryption, generate a data key with:

    aws kms generate-data-key \\
        --key-id alias/my-mcp-key \\
        --key-spec AES_256 \\
        --query Plaintext --output text | base64 -d > /run/secrets/mcp_enc_key

and set ``STORAGE_ENCRYPTION_KEY_PATH=/run/secrets/mcp_enc_key``.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, cast

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Module-level singleton — built once, reused across all store instances.
_fernet: Fernet | None = None


def _build_fernet() -> Fernet:
    raw_key = os.environ.get("STORAGE_ENCRYPTION_KEY", "").strip()
    if raw_key:
        logger.debug("encryption: key loaded from STORAGE_ENCRYPTION_KEY")
        return Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)

    key_path = os.environ.get("STORAGE_ENCRYPTION_KEY_PATH", "").strip()
    if key_path:
        key_bytes = Path(key_path).read_bytes().strip()
        logger.info("encryption: key loaded from %s", key_path)
        return Fernet(key_bytes)

    # Auto-generate — ephemeral, single-process/dev only
    generated = Fernet.generate_key()
    logger.warning(
        "No STORAGE_ENCRYPTION_KEY or STORAGE_ENCRYPTION_KEY_PATH configured. "
        "An ephemeral encryption key has been generated. "
        "Stored tokens and credentials will NOT survive a server restart and "
        "cannot be shared across replicas. "
        "Set STORAGE_ENCRYPTION_KEY (or _PATH) for persistence."
    )
    return Fernet(generated)


def get_fernet() -> Fernet:
    """Return the module-level Fernet instance, building it on first call."""
    global _fernet
    if _fernet is None:
        _fernet = _build_fernet()
    return _fernet


def encrypt(data: dict) -> bytes:
    """JSON-serialise *data* and Fernet-encrypt it."""
    logger.debug("encrypt: %d keys", len(data))
    return cast(bytes, get_fernet().encrypt(json.dumps(data).encode()))


def decrypt(ciphertext: bytes) -> dict:
    """Fernet-decrypt *ciphertext* and JSON-deserialise it."""
    logger.debug("decrypt: %d bytes ciphertext", len(ciphertext))
    return cast(dict[str, Any], json.loads(get_fernet().decrypt(ciphertext)))
