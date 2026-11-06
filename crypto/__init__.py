"""
SecureFlex Cryptographic Module.
Implements NIST SP 800-232 Ascon-AEAD128 and SecureFlex Parity Checks.
"""
from .ascon_adapter import (
    AsconAEAD128,
    AsconCryptoError,
    InvalidKeyOrNonceError,
    AuthenticationFailureError,
)
from .parity_model import SecureFlexPermutationModel, compute_word_parity, sbox_parity_lookup

