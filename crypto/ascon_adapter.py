"""
Cryptographic Adapter for Ascon-AEAD128 (NIST SP 800-232).
Provides constant-time verification, strict input validation, and clean AEAD interfaces.
"""
import hmac
from typing import Optional, Tuple
from . import ascon_nist


class AsconCryptoError(Exception):
    """Base exception for Ascon cryptographic operations."""
    pass


class InvalidKeyOrNonceError(AsconCryptoError):
    """Key or nonce does not match required 16-byte length."""
    pass


class AuthenticationFailureError(AsconCryptoError):
    """Authentication tag mismatch or corrupted ciphertext/AAD."""
    pass


class AsconAEAD128:
    """
    Production adapter for NIST SP 800-232 Ascon-AEAD128.
    Parameters:
        Key size: 128 bits (16 bytes)
        Nonce size: 128 bits (16 bytes)
        Tag size: 128 bits (16 bytes)
        Rate: 128 bits (16 bytes)
        Rounds: a=12, b=8
    """

    VARIANT = "Ascon-AEAD128"
    KEY_LEN = 16
    NONCE_LEN = 16
    TAG_LEN = 16

    @classmethod
    def validate_params(cls, key: bytes, nonce: bytes, tag: Optional[bytes] = None):
        """Validates key, nonce, and optional tag byte lengths."""
        if not isinstance(key, (bytes, bytearray)) or len(key) != cls.KEY_LEN:
            raise InvalidKeyOrNonceError(
                f"Key must be exactly {cls.KEY_LEN} bytes, got {len(key) if hasattr(key, '__len__') else type(key)}"
            )
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != cls.NONCE_LEN:
            raise InvalidKeyOrNonceError(
                f"Nonce must be exactly {cls.NONCE_LEN} bytes, got {len(nonce) if hasattr(nonce, '__len__') else type(nonce)}"
            )
        if tag is not None:
            if not isinstance(tag, (bytes, bytearray)) or len(tag) != cls.TAG_LEN:
                raise AuthenticationFailureError(
                    f"Tag must be exactly {cls.TAG_LEN} bytes, got {len(tag) if hasattr(tag, '__len__') else type(tag)}"
                )

    @classmethod
    def encrypt(cls, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext and generates authentication tag protecting ciphertext and AAD.
        Returns:
            Tuple[bytes, bytes]: (ciphertext, 16-byte tag)
        """
        cls.validate_params(key, nonce)
        # ascon_nist returns ciphertext + 16-byte tag
        raw_result = ascon_nist.ascon_encrypt(
            key=key,
            nonce=nonce,
            associateddata=aad,
            plaintext=plaintext,
            variant=cls.VARIANT,
        )
        ciphertext = raw_result[:-cls.TAG_LEN]
        tag = raw_result[-cls.TAG_LEN:]
        return ciphertext, tag

    @classmethod
    def decrypt(cls, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> Optional[bytes]:
        """
        Verifies tag in constant time and decrypts ciphertext.
        SECURITY CRITICAL: Returns None on ANY verification failure.
        Plaintext must NEVER be accessed or returned if authentication fails.
        """
        cls.validate_params(key, nonce, tag)
        combined = ciphertext + tag
        # ascon_decrypt verifies tag internally and returns plaintext or None
        plaintext = ascon_nist.ascon_decrypt(
            key=key,
            nonce=nonce,
            associateddata=aad,
            ciphertext=combined,
            variant=cls.VARIANT,
        )

        if plaintext is None:
            return None

        # Double-check tag with constant-time comparison to prevent side channels
        recomputed_ct, recomputed_tag = cls.encrypt(key, nonce, aad, plaintext)
        if not hmac.compare_digest(recomputed_tag, tag):
            return None

        return plaintext

