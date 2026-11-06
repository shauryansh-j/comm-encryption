"""
SecureFlex MAVLink Receiver & UAV Transceiver (Raspberry Pi 5).
Full-duplex bidirectional node:
- Listens on UDP 14550, enforces replay protection, and authenticates GCS commands with Ascon-AEAD128 (Sender ID = 1)
- Automatically detects PC address from incoming packets
- Transmits authenticated UAV heartbeats and attitude telemetry back to Windows PC (Sender ID = 2)
"""
import argparse
import os
import socket
import sys
import threading
import time
from typing import Optional, Tuple
from pymavlink.dialects.v20 import common as mavlink2

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.protocol_constants import (
    DEFAULT_LOCAL_BIND_IP,
    DEFAULT_UDP_PORT,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    SENDER_ID_GCS,
    SENDER_ID_UAV,
    DEFAULT_HEARTBEAT_TIMEOUT_SEC,
    REPLAY_WINDOW_SIZE,
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from common.replay_window import ReplayProtectionWindow
from crypto.ascon_adapter import AsconAEAD128
from config.key_generator import load_key_from_file
from raspberry_pi.mavlink_decoder import AuthenticatedMAVLinkDecoder
from raspberry_pi.fault_monitor import FaultMonitor, FaultCategory
from raspberry_pi.fault_localizer import FaultLocalizer
from raspberry_pi.recovery_fsm import RecoveryFSM, FSMState


def on_fsm_transition(old_state: FSMState, new_state: FSMState, reason: str):
    print(f"\n>>> [RECOVERY FSM TRANSITION] {old_state.value} -> {new_state.value} | Reason: {reason}\n")


class SecureMAVLinkReceiver:
    """
    Production-grade secure transport receiver & UAV telemetry transmitter for Raspberry Pi 5.
    Guarantees that unauthenticated datagrams never reach pymavlink, and returns encrypted telemetry to PC.
    """

    def __init__(
        self,
        bind_ip: str = DEFAULT_LOCAL_BIND_IP,
        bind_port: int = DEFAULT_UDP_PORT,
        target_pc_ip: Optional[str] = None,
        target_pc_port: Optional[int] = None,
        key: bytes = None,
        expected_sender_id: int = SENDER_ID_GCS,
        timeout_sec: float = DEFAULT_HEARTBEAT_TIMEOUT_SEC,
        enable_two_way: bool = True,
        log_path: str = "logs/fault_events.jsonl",
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.key = key
        self.expected_sender_id = expected_sender_id
        self.timeout_sec = timeout_sec
        self.enable_two_way = enable_two_way

        if self.key is None:
            raise ValueError("A valid 16-byte cryptographic key must be provided")

        self.mav = mavlink2.MAVLink(None, srcSystem=1, srcComponent=1)
        self.nonce_mgr = NonceManager()
        self.replay_window = ReplayProtectionWindow(window_size=REPLAY_WINDOW_SIZE)
        self.fault_monitor = FaultMonitor(log_path=log_path)
        self.mavlink_decoder = AuthenticatedMAVLinkDecoder(expected_system_id=255, expected_component_id=190)
        self.fsm = RecoveryFSM(on_state_change=on_fsm_transition)

        # Dynamic return target for PC
        self.pc_address: Optional[Tuple[str, int]] = None
        if target_pc_ip and target_pc_port:
            self.pc_address = (target_pc_ip, target_pc_port)

        self.addr_lock = threading.Lock()
        self.stop_event = threading.Event()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))
        self.sock.settimeout(1.0)

        self.total_received = 0
        self.total_authenticated = 0
        self.total_rejected = 0
        self.total_transmitted = 0

        if self.enable_two_way:
            self.tx_thread = threading.Thread(target=self._telemetry_transmit_loop, daemon=True)
            self.tx_thread.start()

    def _telemetry_transmit_loop(self):
        """Periodically streams encrypted UAV heartbeats and attitude telemetry back to PC."""
        while not self.stop_event.is_set():
            time.sleep(1.0)
            with self.addr_lock:
                target = self.pc_address

            if target is None:
                continue

            try:
                # 1. Encode UAV Heartbeat
                hb = self.mav.heartbeat_encode(
                    mavlink2.MAV_TYPE_QUADROTOR,
                    mavlink2.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    0, 0,
                    mavlink2.MAV_STATE_ACTIVE
                )
                hb_bytes = hb.pack(self.mav)

                # 2. Encode Simulated Attitude Telemetry
                att = self.mav.attitude_encode(0, 0.02, -0.01, 1.57, 0.0, 0.0, 0.0)
                att_bytes = att.pack(self.mav)
                payload = hb_bytes + att_bytes

                # 3. Nonce & Header with UAV Sender ID = 2
                counter, nonce = self.nonce_mgr.next_nonce()
                header = PacketHeader(
                    magic=MAGIC_BYTES,
                    version=PROTOCOL_VERSION,
                    flags=FLAG_HEARTBEAT,
                    sender_id=SENDER_ID_UAV,
                    session_id=self.nonce_mgr.session_id,
                    packet_counter=counter,
                    nonce=nonce,
                    ciphertext_length=len(payload),
                )
                aad = header.pack()

                # 4. Encrypt with Ascon-AEAD128
                ct, tag = AsconAEAD128.encrypt(self.key, nonce, aad, payload)
                datagram = SecurePacket(header=header, ciphertext=ct, tag=tag).serialize()

                # 5. Transmit back to Windows PC
                self.sock.sendto(datagram, target)
                self.total_transmitted += 1
                print(f"[UAV -> GCS TX #{counter:04d}] Sent Telemetry to PC {target[0]}:{target[1]} | Datagram: {len(datagram)}B")
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"[TX Error] {e}")

    def start(self):
        print("=" * 68)
        print("  SecureFlex-MAVLink Secure Receiver & UAV Node (Raspberry Pi 5)")
        print("  Full-Duplex NIST SP 800-232 Ascon-AEAD128 Authenticated Encryption")
        print(f"  Listening on: {self.bind_ip}:{self.bind_port} (UDP)")
        print(f"  Expected GCS Sender ID: {self.expected_sender_id} | UAV Sender ID: {SENDER_ID_UAV}")
        print(f"  Two-Way Communication: {'ENABLED' if self.enable_two_way else 'DISABLED'}")
        if self.pc_address:
            print(f"  Static PC Return Target: {self.pc_address[0]}:{self.pc_address[1]}")
        else:
            print("  Return Route: AUTO-DETECT (learns PC IP:port from incoming packets)")
        print("=" * 68)
        print("Waiting for incoming encrypted MAVLink datagrams...\n")

        try:
            while True:
                self.fsm.check_heartbeat_timeout(self.timeout_sec)

                if self.fsm.current_state == FSMState.HALT:
                    self.fsm.trigger_recovery()

                try:
                    datagram, sender_addr = self.sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    continue

                self.total_received += 1

                # 2. Inspect, localize, and cryptographically verify
                result = FaultLocalizer.inspect_and_verify(
                    datagram=datagram,
                    key=self.key,
                    replay_window=self.replay_window,
                    expected_sender_id=self.expected_sender_id,
                )

                if not result.is_valid:
                    self.total_rejected += 1
                    header = result.packet.header if result.packet else None

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
                    self.fsm.on_fault_detected(result.reason or "Validation failure")
                    print(
                        f"[SECURITY REJECTION #{self.total_rejected}] "
                        f"From {sender_addr[0]}:{sender_addr[1]} | "
                        f"Stage: {result.stage} | "
                        f"Category: {result.category} | "
                        f"Reason: {result.reason} | "
                        f"FSM: {self.fsm.current_state.value}"
                    )
                    continue

                # 4. Handle Successful Authentication
                self.total_authenticated += 1
                header = result.packet.header
                self.replay_window.commit(header.session_id, header.packet_counter)
                self.fsm.on_valid_packet()

                # Auto-detect PC address for return telemetry stream
                with self.addr_lock:
                    if self.pc_address != sender_addr:
                        self.pc_address = sender_addr
                        print(f"\n>>> [PC Return Address Set] Streaming return telemetry to: {sender_addr[0]}:{sender_addr[1]}\n")

                if not self.fsm.is_forwarding_allowed:
                    print(f"[GATE CLOSED] Packet authenticated but FSM in state {self.fsm.current_state.value}.")
                    continue

                # 5. Decode Authenticated MAVLink Frame
                messages, warnings = self.mavlink_decoder.parse_bytes(result.plaintext)
                for msg in messages:
                    print(
                        f"[AUTHENTICATED MAVLINK] {msg.msg_type} | "
                        f"System ID: {msg.src_system} | "
                        f"Component ID: {msg.src_component} | "
                        f"Session: {header.session_id:016x} | "
                        f"Counter: #{header.packet_counter:04d}"
                    )
                for warn in warnings:
                    print(f"  [POLICY WARNING] {warn}")

        except KeyboardInterrupt:
            print("\n[Receiver] Shutting down on user interrupt.")
        finally:
            self.stop_event.set()
            self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="SecureFlex MAVLink Receiver & UAV Node (Raspberry Pi 5)")
    parser.add_argument("--bind-ip", default=DEFAULT_LOCAL_BIND_IP, help="Local UDP bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP listening port")
    parser.add_argument("--target-pc-ip", default=None, help="Optional static Windows PC IP address")
    parser.add_argument("--target-pc-port", type=int, default=DEFAULT_UDP_PORT, help="Windows PC UDP port")
    parser.add_argument("--key-file", default="config/secret.key", help="Path to secret key file")
    parser.add_argument("--sender-id", type=int, default=SENDER_ID_GCS, help="Expected GCS sender ID")
    parser.add_argument("--timeout", type=float, default=DEFAULT_HEARTBEAT_TIMEOUT_SEC, help="Heartbeat timeout")
    parser.add_argument("--no-two-way", action="store_true", help="Disable return telemetry transmission")
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
        target_pc_ip=args.target_pc_ip,
        target_pc_port=args.target_pc_port,
        key=key,
        expected_sender_id=args.sender_id,
        timeout_sec=args.timeout,
        enable_two_way=not args.no_two_way,
        log_path=args.log_path,
    )
    receiver.start()


if __name__ == "__main__":
    main()
