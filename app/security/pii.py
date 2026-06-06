"""Application-level encryption for PII at rest.

Uses AES-SIV, a *deterministic* authenticated cipher: the same plaintext always
encrypts to the same ciphertext under a given key. Determinism is what lets
encrypted columns still be used in equality lookups (login by email, allowlist
by phone, uniqueness checks) — the ORM encrypts the comparison value the same
way it encrypted the stored value. Partial/substring search (ILIKE) does NOT
work on ciphertext; those queries (only in the gate router) filter in Python
after the ORM transparently decrypts the rows.

Ciphertext is stored as `enc:1:<base64>` so we can tell encrypted values from
any legacy plaintext and migrate safely (see scripts/encrypt_pii.py).
"""
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from sqlalchemy.types import String, TypeDecorator

from app.config.config import settings

_PREFIX = "enc:1:"
# Fixed associated data — binds ciphertext to this application/domain.
_AAD = [b"twickenham-glades-pii-v1"]


def _key() -> bytes:
    """Derive a stable 256-bit AES-SIV key from the configured secret."""
    return hashlib.sha256(settings.pii_encryption_key.encode("utf-8")).digest()


def pii_encrypt(plaintext):
    """Encrypt a string to `enc:1:<b64>`. None and already-encrypted pass through."""
    if plaintext is None:
        return None
    text = str(plaintext)
    if text.startswith(_PREFIX):
        return text
    siv = AESSIV(_key())
    ct = siv.encrypt(text.encode("utf-8"), _AAD)
    return _PREFIX + base64.urlsafe_b64encode(ct).decode("ascii")


def pii_decrypt(value):
    """Decrypt `enc:1:<b64>`. Legacy plaintext (no prefix) is returned as-is."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith(_PREFIX):
        return value
    raw = base64.urlsafe_b64decode(value[len(_PREFIX):].encode("ascii"))
    siv = AESSIV(_key())
    return siv.decrypt(raw, _AAD).decode("utf-8")


class EncryptedStr(TypeDecorator):
    """A String column transparently encrypted at rest with [pii_encrypt].

    Reads return plaintext; writes and equality-comparison values are encrypted
    deterministically so `column == value` filters still work.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return pii_encrypt(value)

    def process_result_value(self, value, dialect):
        return pii_decrypt(value)
