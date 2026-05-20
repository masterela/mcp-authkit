# Storage backends

Three pluggable backends share the same abstract interface.

## Key management

`file` and `redis` backends encrypt all stored data with a [Fernet](https://cryptography.io/en/latest/fernet/) symmetric key. The key is resolved in this order:

1. `STORAGE_ENCRYPTION_KEY` env var — a base64-encoded Fernet key (44-char URL-safe string)
2. `STORAGE_ENCRYPTION_KEY_PATH` env var — path to a file containing the key
3. Auto-generated ephemeral key — **tokens are lost on restart**; a warning is logged

### Generating a stable key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the output and export it before starting the server:

```bash
export STORAGE_ENCRYPTION_KEY=<paste key here>
```

### Key rotation / wrong key

If the server starts with a different key than the one used to encrypt existing entries, decryption will fail silently: the stale entry is deleted and the user is re-prompted for credentials once. No data is corrupted and no error is surfaced to the user — they just re-authenticate.

This means key rotation requires no migration: restart with the new key and users re-auth on their next tool call.

## Interfaces

::: mcpauthkit.store.base

## In-process (memory)

::: mcpauthkit.store.memory

## File (Fernet-encrypted)

::: mcpauthkit.store.file_store

## Redis (async)

::: mcpauthkit.store.redis_store

## Factory

::: mcpauthkit.store.factory
