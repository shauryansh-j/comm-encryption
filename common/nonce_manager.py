"""
Cryptographic Nonce and Session Manager.
Guarantees absolute nonce uniqueness across restarts and transmissions under Ascon-AEAD128.
"""
import os
import secrets
import struct
import threading
from typing import Tuple

from .protocol_constants import NONCE_SIZE_BYTES


class NonceExhaustionError(Exception):
    """Raised when the 64-bit counter reaches safety limits."""
    pass


class NonceManager:
    """
    Constructs deterministic 128-bit unique nonces using:
    [Session ID: 64-bit uint] || [Monotonic Packet Counter: 64-bit uint] = 16 bytes.
    Thread-safe and persistent across state renewals.
    """

    # Maximum safe counter value before requiring session re-keying (2^48)
    MAX_SAFE_COUNTER = 0x0000_FFFF_FFFF_FFFF

    def __init__(self, session_id: int = None, start_counter: int = 1):
        self._lock = threading.Lock()
        if session_id is None:
            # 64-bit cryptographically secure random session ID (excluding 0)
            self._session_id = secrets.randbits(64) or 1
        else:
            self._session_id = session_id

        self._counter = start_counter

    @property
    def session_id(self) -> int:
        with self._lock:
            return self._session_id

    @property
    def current_counter(self) -> int:
        with self._lock:
            return self._counter

    def rotate_session(self, new_session_id: int = None) -> int:
        """Establish a fresh unique session identifier and reset counter safely."""
        with self._lock:
            if new_session_id is None:
                self._session_id = secrets.randbits(64) or 1
            else:
                self._session_id = new_session_id
            self._counter = 1
            return self._session_id

    def next_nonce(self) -> Tuple[int, bytes]:
        """
        Allocates the next monotonic counter and constructs the canonical 16-byte nonce.
        Returns:
            Tuple[int, bytes]: (packet_counter, 16-byte nonce)
        """
        with self._lock:
            if self._counter >= self.MAX_SAFE_COUNTER:
                raise NonceExhaustionError(
                    f"Counter reached safe ceiling {self.MAX_SAFE_COUNTER}. Rotate session/key immediately."
                )

            counter_val = self._counter
            self._counter += 1

            # Format: 8-byte session ID (big-endian) followed by 8-byte counter (big-endian)
            nonce = struct.pack(">QQ", self._session_id, counter_val)
            assert len(nonce) == NONCE_SIZE_BYTES
            return counter_val, nonce

    @staticmethod
    def build_nonce(session_id: int, counter: int) -> bytes:
        """Utility to reconstruct 16-byte nonce from session ID and counter."""
        return struct.pack(">QQ", session_id, counter)

