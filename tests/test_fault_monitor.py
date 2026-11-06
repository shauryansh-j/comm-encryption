"""
Test Suite: Fault Detection and Structured Diagnostics Monitor.
"""
import os
import tempfile
from raspberry_pi.fault_monitor import FaultMonitor, FaultCategory


def test_fault_recording_and_first_fault_preservation():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "test_events.jsonl")
        monitor = FaultMonitor(log_path=log_file)

        # Record first fault
        f1 = monitor.record_fault(
            category=FaultCategory.INVALID_FRAMING,
            stage="STAGE_2_HEADER_FRAMING",
            action_taken="DISCARD_DATAGRAM",
            recovery_state="RUN",
            details="Bad magic bytes",
            sender_id=1,
            packet_counter=5,
        )

        # Record second fault
        f2 = monitor.record_fault(
            category=FaultCategory.AUTHENTICATION_FAILED,
            stage="STAGE_6_ASCON_AEAD128_AUTH",
            action_taken="DISCARD_DATAGRAM",
            recovery_state="SUSPECT",
            details="Tag mismatch",
            sender_id=1,
            packet_counter=6,
        )

        summary = monitor.get_summary()
        assert summary["total_faults"] == 2
        assert summary["counts_by_category"][FaultCategory.INVALID_FRAMING] == 1
        assert summary["counts_by_category"][FaultCategory.AUTHENTICATION_FAILED] == 1

        # First fault must NOT be overwritten!
        assert monitor.first_fault_record.details == "Bad magic bytes"
        assert monitor.first_fault_record.category == FaultCategory.INVALID_FRAMING

        # Check JSONL output on disk
        with open(log_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 2

