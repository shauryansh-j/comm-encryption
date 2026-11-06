"""
Recovery Finite State Machine (FSM) for SecureFlex-MAVLink Transport.
Implements the 8-state SecureFlex recovery architecture, fault isolation, and lockdown protection.
"""
from enum import Enum
import threading
import time
from typing import Callable, Optional


class FSMState(str, Enum):
    IDLE = "IDLE"              # Initial state, waiting for authenticated session
    RUN = "RUN"                # Normal authenticated operation
    SUSPECT = "SUSPECT"        # Single fault or transient anomaly trapped
    HALT = "HALT"              # Security isolation; forwarding to MAVLink stopped
    RECOVER = "RECOVER"        # Session re-synchronization initiated
    WAIT = "WAIT"              # Waiting for fresh authenticated packet/handshake
    RECOVERED = "RECOVERED"    # Communication verified and restored
    LOCK = "LOCK"              # Lockdown; communication disabled pending operator reset


class RecoveryFSM:
    """
    Finite State Machine inspired by SecureFlex hardware recovery controller.
    Controls isolation gates and manages communication restoration.
    """

    def __init__(
        self,
        max_consecutive_suspect: int = 2,
        max_recovery_attempts: int = 5,
        recovery_timeout_sec: float = 2.0,
        on_state_change: Optional[Callable[[FSMState, FSMState, str], None]] = None,
    ):
        self._lock = threading.Lock()
        self._state = FSMState.IDLE
        self.max_consecutive_suspect = max_consecutive_suspect
        self.max_recovery_attempts = max_recovery_attempts
        self.recovery_timeout_sec = recovery_timeout_sec
        self.on_state_change = on_state_change

        self._consecutive_faults = 0
        self._consecutive_recoveries = 0
        self._state_entered_time = time.monotonic()
        self._last_valid_packet_time = 0.0

    @property
    def current_state(self) -> FSMState:
        with self._lock:
            return self._state

    @property
    def is_forwarding_allowed(self) -> bool:
        """Forwarding to MAVLink decoder is ONLY permitted in RUN and RECOVERED states."""
        with self._lock:
            return self._state in (FSMState.RUN, FSMState.RECOVERED)

    def _transition(self, new_state: FSMState, reason: str):
        old_state = self._state
        if old_state == new_state:
            return

        self._state = new_state
        self._state_entered_time = time.monotonic()

        if self.on_state_change:
            try:
                self.on_state_change(old_state, new_state, reason)
            except Exception as e:
                print(f"[FSM Error] Callback exception: {e}")

    def on_valid_packet(self):
        """Called whenever a datagram is successfully authenticated and decrypted."""
        with self._lock:
            self._last_valid_packet_time = time.monotonic()
            self._consecutive_faults = 0

            if self._state == FSMState.IDLE:
                self._transition(FSMState.RUN, "Initial authenticated session established")
            elif self._state == FSMState.SUSPECT:
                self._transition(FSMState.RUN, "Transient anomaly cleared by valid packet")
            elif self._state == FSMState.WAIT:
                self._transition(FSMState.RECOVERED, "Valid authenticated packet received during WAIT")
                self._transition(FSMState.RUN, "Session restored to normal RUN state")
            elif self._state == FSMState.RECOVERED:
                self._transition(FSMState.RUN, "Resumed normal operation")
            elif self._state == FSMState.LOCK:
                # Locked down: ignore valid packets until operator reset!
                pass

    def on_fault_detected(self, reason: str):
        """Called whenever any framing, replay, or authentication fault occurs."""
        with self._lock:
            if self._state == FSMState.LOCK:
                return  # Already locked

            self._consecutive_faults += 1

            if self._consecutive_faults >= self.max_recovery_attempts:
                self._transition(
                    FSMState.LOCK,
                    f"Persistent failure limit exceeded ({self._consecutive_faults} faults): {reason}"
                )
                return

            if self._state == FSMState.RUN:
                self._transition(FSMState.SUSPECT, f"Fault trapped in RUN: {reason}")
            elif self._state == FSMState.SUSPECT:
                if self._consecutive_faults >= self.max_consecutive_suspect:
                    self._transition(FSMState.HALT, f"Suspect threshold reached: {reason}")
            elif self._state in (FSMState.RECOVER, FSMState.WAIT):
                self._consecutive_recoveries += 1
                if self._consecutive_recoveries >= self.max_recovery_attempts:
                    self._transition(FSMState.LOCK, f"Repeated recovery failures: {reason}")
                else:
                    self._transition(FSMState.HALT, f"Fault during recovery: {reason}")

    def trigger_recovery(self):
        """Triggers recovery sequence from HALT or timeout."""
        with self._lock:
            if self._state == FSMState.LOCK:
                return
            if self._state == FSMState.HALT:
                self._transition(FSMState.RECOVER, "Initiating session re-synchronization")
                self._transition(FSMState.WAIT, "Waiting for fresh authenticated heartbeat")

    def check_heartbeat_timeout(self, timeout_sec: float = 3.5):
        """Checks for communication loss / heartbeat timeouts."""
        with self._lock:
            if self._state in (FSMState.IDLE, FSMState.LOCK):
                return

            now = time.monotonic()
            if self._last_valid_packet_time > 0 and (now - self._last_valid_packet_time) > timeout_sec:
                if self._state == FSMState.RUN:
                    self._transition(FSMState.SUSPECT, f"Heartbeat timeout ({timeout_sec:.1f}s)")
                elif self._state == FSMState.SUSPECT:
                    self._transition(FSMState.HALT, "Heartbeat loss confirmed; entering HALT")

    def operator_reset(self, authorization_token: str = "SECURE_RESET") -> bool:
        """Authorized operator override to release permanent LOCK state."""
        with self._lock:
            if authorization_token != "SECURE_RESET":
                return False
            self._consecutive_faults = 0
            self._consecutive_recoveries = 0
            self._transition(FSMState.IDLE, "Authorized operator reset executed")
            return True

