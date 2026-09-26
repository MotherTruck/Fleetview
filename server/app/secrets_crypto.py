"""Reversible at-rest encryption for integration credentials.

Every other secret this app stores (agent tokens, user passwords) is
one-way hashed, since the server only ever needs to *compare* them, never
read them back. Integration credentials (Proxmox/OPNsense API tokens) are
different: the server has to send the plaintext to an external API on
every sync, so hashing isn't an option -- this module provides real,
symmetric encryption instead, keyed by FLEETVIEW_SECRET_KEY.

That key is a required environment variable, not something generated and
persisted automatically: the server container itself is stateless (see
docker-compose.yml -- only Postgres has a volume), so a key generated at
startup and written to local disk would be lost on every container
recreation, silently making every previously-saved credential
undecryptable. Requiring the key up front, the same way ADMIN_TOKEN
already is, fails loudly at configuration time instead of quietly at
decryption time.
"""
import os

from cryptography.fernet import Fernet, InvalidToken

_fernet_cache: Fernet | None = None
_fernet_cache_key: str | None = None


class SecretKeyNotConfigured(Exception):
    pass


class CredentialDecryptionFailed(Exception):
    pass


def _fernet() -> Fernet:
    global _fernet_cache, _fernet_cache_key
    raw_key = os.environ.get("FLEETVIEW_SECRET_KEY", "")
    if not raw_key:
        raise SecretKeyNotConfigured(
            "FLEETVIEW_SECRET_KEY is not set. Generate one with: "
            "python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
            "and set it in your .env file before configuring any integration."
        )
    if _fernet_cache is not None and _fernet_cache_key == raw_key:
        return _fernet_cache
    try:
        instance = Fernet(raw_key.encode("utf-8"))
    except (ValueError, TypeError) as error:
        raise SecretKeyNotConfigured(
            "FLEETVIEW_SECRET_KEY is set but not a valid Fernet key (expected the base64 output of "
            "Fernet.generate_key())."
        ) from error
    _fernet_cache, _fernet_cache_key = instance, raw_key
    return instance


def encrypt_text(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as error:
        raise CredentialDecryptionFailed(
            "Could not decrypt stored credentials -- FLEETVIEW_SECRET_KEY may have changed since they "
            "were saved. Re-enter this integration's credentials."
        ) from error


def secret_key_configured() -> bool:
    try:
        _fernet()
        return True
    except SecretKeyNotConfigured:
        return False


def generate_key() -> str:
    """Used only by tests and the `python -m app.secrets_crypto` helper below;
    real deployments generate their own key once and put it in .env."""
    return Fernet.generate_key().decode("ascii")


if __name__ == "__main__":
    print(generate_key())
