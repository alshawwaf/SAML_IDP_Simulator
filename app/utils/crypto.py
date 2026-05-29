"""Fernet encryption helpers for SCIM bearer tokens at rest.

The Fernet key comes from SCIM_ENCRYPTION_KEY (set in .env). Generate one with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.utils.config_manager import config_manager


_fernet_singleton: Fernet | None = None


def _get_fernet() -> Fernet:
    """Lazy-load the Fernet instance. Raises a clear error if the key is missing."""
    global _fernet_singleton
    if _fernet_singleton is not None:
        return _fernet_singleton

    key = config_manager.SCIM_ENCRYPTION_KEY
    if not key:
        raise RuntimeError(
            "SCIM_ENCRYPTION_KEY is not set. SCIM features that store tokens "
            "require an encryption key. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )

    try:
        _fernet_singleton = Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as e:
        raise RuntimeError(f"SCIM_ENCRYPTION_KEY is invalid: {e}") from e

    return _fernet_singleton


def encrypt_token(plaintext: str) -> bytes:
    """Encrypt a bearer token for storage in ScimTarget.bearer_token_encrypted."""
    return _get_fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_token(ciphertext: bytes) -> str:
    """Decrypt a token retrieved from ScimTarget.bearer_token_encrypted."""
    try:
        return _get_fernet().decrypt(ciphertext).decode("utf-8")
    except InvalidToken as e:
        raise RuntimeError(
            "Failed to decrypt SCIM bearer token. The SCIM_ENCRYPTION_KEY may have changed."
        ) from e


def hash_inbound_token(token: str) -> str:
    """SHA-256 hex digest for inbound bearer tokens. Used to store ScimInboundToken.token_hash."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_inbound_token(token: str, expected_hash: str) -> bool:
    """Constant-time comparison of a presented token against a stored hash."""
    return hmac.compare_digest(hash_inbound_token(token), expected_hash)


def generate_inbound_token() -> str:
    """Generate a high-entropy opaque bearer token for inbound SCIM clients."""
    return secrets.token_urlsafe(32)
