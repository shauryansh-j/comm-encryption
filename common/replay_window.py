"""
Sliding Replay Protection Window for SecureFlex-MAVLink Transport.
Implements RFC 6479-style sliding bitmap anti-replay window with two-phase check/commit.
"""
import threading
from typing import Optional, Tuple
from .protocol_constants import REPLAY_WINDOW_SIZE


class ReplayError(Exception):
    """Base exception for anti-replay violations."""
    pass


class DuplicatePacketError(ReplayError):
    """Packet counter has already been received and committed."""
    pass


class StalePacketError(ReplayError):
    """Packet counter is older than the lower bound of the sliding window."""
    pass


class InvalidSessionError(ReplayError):
    """Session ID does not match active authenticated session."""
    pass


class ReplayProtectionWindow:
    """
    Sliding window replay protection with 2-phase verification:
    1. check(session_id, counter): Verifies window without mutating state (pre-decryption).
    2. commit(session_id, counter): Records counter into replay window (post-authentication).
    """

    def __init__(self, window_size: int = REPLAY_WINDOW_SIZE, strict_monotonic: bool = False):
        self.window_size = window_size
        self.strict_monotonic = strict_monotonic
        self._lock = threading.Lock()

        self._active_session_id: Optional[int] = None
        self._max_counter: int = 0
        self._bitmap: int = 0  # Bit 0 represents (_max_counter), bit i represents (_max_counter - i)
        self._total_accepted: int = 0
        self._total_replays: int = 0
        self._total_stale: int = 0

    @property
    def active_session_id(self) -> Optional[int]:
        with self._lock:
            return self._active_session_id

    @property
    def max_counter(self) -> int:
        with self._lock:
            return self._max_counter

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "active_session_id": self._active_session_id,
                "max_counter": self._max_counter,
                "total_accepted": self._total_accepted,
                "total_replays": self._total_replays,
                "total_stale": self._total_stale,
            }

    def reset_session(self, new_session_id: int):
        """Explicitly switch or initialize active session."""
        with self._lock:
            self._active_session_id = new_session_id
            self._max_counter = 0
            self._bitmap = 0

    def check(self, session_id: int, counter: int) -> Tuple[bool, Optional[str]]:
        """
        Pre-flight check: Returns (True, None) if packet counter is plausible and acceptable.
        Does NOT alter state. Must be followed by commit() only if authentication succeeds.
        """
        if counter <= 0:
            return False, "Counter must be positive non-zero"

        with self._lock:
            # First packet ever received
            if self._active_session_id is None:
                return True, None

            # Different session: allowed if new sender restarted with a fresh session
            if session_id != self._active_session_id:
                # Session transition policy: accept new session proposal
                return True, None

            # Same active session: evaluate against replay window
            if self.strict_monotonic:
                if counter <= self._max_counter:
                    return False, f"Strict monotonic violation: counter {counter} <= max {self._max_counter}"
                return True, None

            diff = counter - self._max_counter

            if diff > 0:
                # Ahead of max counter: valid new packet
                return True, None
            else:
                offset = -diff  # offset >= 0
                if offset >= self.window_size:
                    return False, f"Stale packet: offset {offset} >= window {self.window_size}"
                # Check if already received in bitmap
                if (self._bitmap & (1 << offset)) != 0:
                    return False, f"Duplicate packet: counter {counter} already received"
                return True, None

    def commit(self, session_id: int, counter: int):
        """
        Commits counter to replay state. MUST ONLY be called after cryptographic authentication succeeds!
        """
        with self._lock:
            if self._active_session_id is None or session_id != self._active_session_id:
                # Establish or transition to new session
                self._active_session_id = session_id
                self._max_counter = counter
                self._bitmap = 1  # bit 0 set
                self._total_accepted += 1
                return

            diff = counter - self._max_counter

            if diff > 0:
                # Advance window
                if diff >= self.window_size:
                    self._bitmap = 1
                else:
                    self._bitmap = (self._bitmap << diff) | 1
                self._max_counter = counter
                self._total_accepted += 1
            else:
                offset = -diff
                if offset >= self.window_size:
                    self._total_stale += 1
                    raise StalePacketError(f"Stale packet counter {counter} rejected during commit")
                if (self._bitmap & (1 << offset)) != 0:
                    self._total_replays += 1
                    raise DuplicatePacketError(f"Duplicate counter {counter} rejected during commit")
                self._bitmap |= (1 << offset)
                self._total_accepted += 1

