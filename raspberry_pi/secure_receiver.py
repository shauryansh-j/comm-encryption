"""
SecureFlex MAVLink Receiver (Raspberry Pi 5).
Listens on UDP 14550, validates framing, enforces replay protection, authenticates with Ascon-AEAD128,
monitors faults, and passes only verified plaintext to pymavlink.
"""
import argparse
import os
import socket
import sys
import time

# Ensure project root is in import path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.protocol_constants import (
    DEFAULT_LOCAL_BIND_IP,
    DEFAULT_UDP_PORT,
    SENDER_ID_GCS,
    DEFAULT_HEARTBEAT_TIMEOUT_SEC,
    REPLAY_WINDOW_SIZE,
)
from common.replay_window import ReplayProtectionWindow
from config.key_generator import load_key_from_file
from raspberry_pi.mavlink_decoder import AuthenticatedMAVLinkDecoder
from raspberry_pi.fault_monitor import FaultMonitor, FaultCategory
from raspberry_pi.fault_localizer import FaultLocalizer
from raspberry_pi.recovery_fsm import RecoveryFSM, FSMState


def on_fsm_transition(old_state: FSMState, new_state: FSMState, reason: str):
    print(f"\n>>> [RECOVERY FSM TRANSITION] {old_state.value} -> {new_state.value} | Reason: {reason}\n")


class SecureMAVLinkReceiver:
    """
    Production-grade secure transport receiver for Raspberry Pi 5.
    Guarantees that unauthenticated, forged, or replayed datagrams never reach pymavlink.
    """

    def __init__(
        self,
        bind_ip: str = DEFAULT_LOCAL_BIND_IP,
        bind_port: int = DEFAULT_UDP_PORT,
        key: bytes = None,
        expected_sender_id: int = SENDER_ID_GCS,
        timeout_sec: float = DEFAULT_HEARTBEAT_TIMEOUT_SEC,
        log_path: str = "logs/fault_events.jsonl",
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.key = key
        self.expected_sender_id = expected_sender_id
        self.timeout_sec = timeout_sec

        if self.key is None:
            raise ValueError("A valid 16-byte cryptographic key must be provided")

        self.replay_window = ReplayProtectionWindow(window_size=REPLAY_WINDOW_SIZE)
        self.fault_monitor = FaultMonitor(log_path=log_path)
        self.mavlink_decoder = AuthenticatedMAVLinkDecoder(expected_system_id=255, expected_component_id=190)
        self.fsm = RecoveryFSM(on_state_change=on_fsm_transition)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))
        # Non-blocking timeout so heartbeat monitor and recovery logic can fire
        self.sock.settimeout(1.0)

        self.total_received = 0
        self.total_authenticated = 0
        self.total_rejected = 0

    def start(self):
        print("=" * 68)
        print("  SecureFlex-MAVLink Secure Receiver (Raspberry Pi 5)")
        print("  Algorithm: NIST SP 800-232 Ascon-AEAD128")
        print(f"  Listening on: {self.bind_ip}:{self.bind_port} (UDP)")
        print(f"  Expected Sender ID: {self.expected_sender_id}")
        print(f"  Replay Window: {REPLAY_WINDOW_SIZE} packets")
        print(f"  Initial FSM State: {self.fsm.current_state.value}")
        print("=" * 68)
        print("Waiting for incoming encrypted MAVLink datagrams...\n")

        try:
            while True:
                # 1. Check for heartbeat timeouts periodically
                self.fsm.check_heartbeat_timeout(self.timeout_sec)

                # If HALT state, attempt automatic recovery trigger
                if self.fsm.current_state == FSMState.HALT:
                    self.fsm.trigger_recovery()

                try:
                    datagram, sender_addr = self.sock.recvfrom(2048)
                except socket.timeout:
                    continue

                self.total_received += 1

                # 2. Inspect, localize, and cryptographically verify
                result = FaultLocalizer.inspect_and_verify(
                    datagram=datagram,
                    key=self.key,
                    replay_window=self.replay_window,
                    expected_sender_id=self.expected_sender_id,
                )

                # 3. Handle Verification Failure
                if not result.is_valid:
                    self.total_rejected += 1
                    header = result.packet.header if result.packet else None

                    # Log structured forensic event
                    self.fault_monitor.record_fault(
                        category=result.category or FaultCategory.INTERNAL_ERROR,
                        stage=result.stage,
                        action_taken="DISCARD_DATAGRAM",
                        recovery_state=self.fsm.current_state.value,
                        details=result.reason or "Unknown rejection",
                        sender_id=header.sender_id if header else None,
                        session_id=header.session_id if header else None,
                        packet_counter=header.packet_counter if header else None,
                    )

                    # Update recovery state machine
                    self.fsm.on_fault_detected(result.reason or "Validation failure")

                    print(
                        f"[SECURITY REJECTION #{self.total_rejected}] "
                        f"From {sender_addr[0]}:{sender_addr[1]} | "
                        f"Stage: {result.stage} | "
                        f"Category: {result.category} | "
                        f"Reason: {result.reason} | "
                        f"FSM: {self.fsm.current_state.value}"
                    )
                    # INVARIANT: Plaintext is discarded. NEVER pass to pymavlink!
                    continue

                # 4. Handle Successful Authentication
                self.total_authenticated += 1
                header = result.packet.header

                # Commit counter to replay window (post-authentication)
                self.replay_window.commit(header.session_id, header.packet_counter)

                # Update FSM state
                self.fsm.on_valid_packet()

                # Check if FSM allows forwarding to MAVLink decoder
                if not self.fsm.is_forwarding_allowed:
                    print(
                        f"[GATE CLOSED] Packet authenticated but FSM in state {self.fsm.current_state.value}. "
                        "Forwarding suppressed."
                    )
                    continue

                # 5. Decode Authenticated MAVLink Frame
                messages, warnings = self.mavlink_decoder.parse_bytes(result.plaintext)

                for msg in messages:
                    print(
                        f"[AUTHENTICATED MAVLINK] {msg.msg_type} | "
                        f"System ID: {msg.src_system} | "
                        f"Component ID: {msg.src_component} | "
                        f"Session: {header.session_id:016x} | "
                        f"Counter: #{header.packet_counter:04d} | "
                        f"FSM: {self.fsm.current_state.value}"
                    )

                for warn in warnings:
                    print(f"  [POLICY WARNING] {warn}")

        except KeyboardInterrupt:
            print("\n[Receiver] Shutting down on user interrupt.")
            summary = self.fault_monitor.get_summary()
            print(
                f"[Summary] Received: {self.total_received} | "
                f"Authenticated: {self.total_authenticated} | "
                f"Rejected: {self.total_rejected} | "
                f"Total Faults Logged: {summary['total_faults']}"
            )
        finally:
            self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="SecureFlex MAVLink Receiver (Raspberry Pi 5)")
    parser.add_argument("--bind-ip", default=DEFAULT_LOCAL_BIND_IP, help="Local UDP bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP listening port")
    parser.add_argument("--key-file", default="config/secret.key", help="Path to secret key file")
    parser.add_argument("--sender-id", type=int, default=SENDER_ID_GCS, help="Expected sender ID")
    parser.add_argument("--timeout", type=float, default=DEFAULT_HEARTBEAT_TIMEOUT_SEC, help="Heartbeat timeout in seconds")
    parser.add_argument("--log-path", default="logs/fault_events.jsonl", help="Forensic JSONL log path")
    args = parser.parse_args()

    key_path = os.path.abspath(args.key_file)
    if not os.path.isfile(key_path):
        alt_path = os.path.join(PROJECT_ROOT, "config", "secret.key")
        if os.path.isfile(alt_path):
            key_path = alt_path

    try:
        key = load_key_from_file(key_path)
    except Exception as e:
        print(f"[Error] Failed to load key file '{key_path}': {e}")
        print("Run 'python config/key_generator.py -o config/secret.key' first!")
        sys.exit(1)

    receiver = SecureMAVLinkReceiver(
        bind_ip=args.bind_ip,
        bind_port=args.port,
        key=key,
        expected_sender_id=args.sender_id,
        timeout_sec=args.timeout,
        log_path=args.log_path,
    )
    receiver.start()


if __name__ == "__main__":
    main()

