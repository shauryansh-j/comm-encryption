"""
Fault Detection, Categorization, and Structured Diagnostics Monitor.
Logs security events, calculates fault rates, and preserves audit trails without silent overwrites.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import os
import threading
import time
from typing import Dict, List, Optional
import uuid


class FaultCategory:
    INVALID_FRAMING = "INVALID_FRAMING"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    UNEXPECTED_SENDER = "UNEXPECTED_SENDER"
    INVALID_MAVLINK = "INVALID_MAVLINK"
    HEARTBEAT_TIMEOUT = "HEARTBEAT_TIMEOUT"
    PARITY_MISMATCH = "PARITY_MISMATCH"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass
class FaultRecord:
    timestamp_utc: str
    monotonic_time: float
    event_id: str
    category: str
    stage: str
    action_taken: str
    recovery_state: str
    sender_id_unverified: Optional[int]
    session_id_unverified: Optional[str]
    counter_unverified: Optional[int]
    details: str

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class FaultMonitor:
    """
    Centralized security and fault diagnostics engine.
    Maintains persistent JSONL logs and thread-safe counters.
    """

    def __init__(self, log_path: str = "logs/fault_events.jsonl"):
        self.log_path = log_path
        self._lock = threading.Lock()
        self._category_counts: Dict[str, int] = {
            FaultCategory.INVALID_FRAMING: 0,
            FaultCategory.UNSUPPORTED_VERSION: 0,
            FaultCategory.AUTHENTICATION_FAILED: 0,
            FaultCategory.REPLAY_ATTACK: 0,
            FaultCategory.UNEXPECTED_SENDER: 0,
            FaultCategory.INVALID_MAVLINK: 0,
            FaultCategory.HEARTBEAT_TIMEOUT: 0,
            FaultCategory.PARITY_MISMATCH: 0,
            FaultCategory.INTERNAL_ERROR: 0,
        }
        self.total_faults = 0
        self.first_fault_record: Optional[FaultRecord] = None
        self._recent_timestamps: List[float] = []

        # Ensure log directory exists
        log_dir = os.path.dirname(self.log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def record_fault(
        self,
        category: str,
        stage: str,
        action_taken: str,
        recovery_state: str,
        details: str,
        sender_id: Optional[int] = None,
        session_id: Optional[int] = None,
        packet_counter: Optional[int] = None,
    ) -> FaultRecord:
        """
        Records a fault event. Never logs secret keys or plaintext data.
        """
        now_mono = time.monotonic()
        now_utc = datetime.now(timezone.utc).isoformat()

        session_str = f"{session_id:016x}" if session_id is not None else None

        record = FaultRecord(
            timestamp_utc=now_utc,
            monotonic_time=now_mono,
            event_id=str(uuid.uuid4())[:8],
            category=category,
            stage=stage,
            action_taken=action_taken,
            recovery_state=recovery_state,
            sender_id_unverified=sender_id,
            session_id_unverified=session_str,
            counter_unverified=packet_counter,
            details=details,
        )

        with self._lock:
            self.total_faults += 1
            if category in self._category_counts:
                self._category_counts[category] += 1
            else:
                self._category_counts[category] = 1

            # Preserve the very first fault for forensic isolation
            if self.first_fault_record is None:
                self.first_fault_record = record

            # Track timestamp for rate calculation (sliding 60s)
            self._recent_timestamps.append(now_mono)
            cutoff = now_mono - 60.0
            self._recent_timestamps = [t for t in self._recent_timestamps if t >= cutoff]

            # Append to persistent JSONL log
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(record.to_json() + "\n")
            except OSError as e:
                print(f"[FaultMonitor Warning] Could not write log to {self.log_path}: {e}")

        return record

    def get_summary(self) -> dict:
        """Returns diagnostic summary of fault occurrences."""
        with self._lock:
            return {
                "total_faults": self.total_faults,
                "counts_by_category": dict(self._category_counts),
                "fault_rate_per_min": len(self._recent_timestamps),
                "has_first_fault": self.first_fault_record is not None,
                "first_fault": asdict(self.first_fault_record) if self.first_fault_record else None,
            }

