"""
SecureFlex Two-Way MAVLink Transceiver (Raspberry Pi 5 UAV Node).
Full-duplex bidirectional node:
- Receives and authenticates GCS heartbeats and commands from Windows PC (Sender ID = 1)
- Automatically detects PC return IP and port (NAT & firewall hole-punching)
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
from raspberry_pi.mavlink_decoder import AuthenticatedMAVLinkDecoder
from raspberry_pi.fault_localizer import FaultLocalizer
from raspberry_pi.fault_monitor import FaultMonitor, FaultCategory
from raspberry_pi.recovery_fsm import RecoveryFSM, FSMState
from config.key_generator import load_key_from_file


class SecureUAVTransceiver:
    """
    Bidirectional Secure UAV Node running on Raspberry Pi 5.
    Auto-detects PC address on first authenticated incoming packet and streams telemetry back.
    """

    def __init__(
        self,
        bind_ip: str = DEFAULT_LOCAL_BIND_IP,
        bind_port: int = DEFAULT_UDP_PORT,
        target_pc_ip: Optional[str] = None,
        target_pc_port: Optional[int] = None,
        key: bytes = None,
        source_system: int = 1,
        source_component: int = 1,
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.key = key
        self.source_system = source_system
        self.source_component = source_component

        if self.key is None:
            raise ValueError("A valid 16-byte cryptographic key must be provided")

        self.mav = mavlink2.MAVLink(None, srcSystem=self.source_system, srcComponent=self.source_component)
        self.decoder = AuthenticatedMAVLinkDecoder()
        self.nonce_mgr = NonceManager()
        # Replay window tracking incoming traffic from GCS (Sender ID = 1)
        self.replay_window = ReplayProtectionWindow(window_size=REPLAY_WINDOW_SIZE)
        self.fault_monitor = FaultMonitor(log_path="logs/uav_fault_events.jsonl")
        self.fsm = RecoveryFSM()

        # Target PC return address (auto-detected or statically configured)
        self.pc_address: Optional[Tuple[str, int]] = None
        if target_pc_ip and target_pc_port:
            self.pc_address = (target_pc_ip, target_pc_port)

        self.addr_lock = threading.Lock()
        self.stop_event = threading.Event()

        # Bind UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))

        self.rx_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.total_tx = 0
        self.total_rx_authenticated = 0
        self.total_rx_rejected = 0

    def start(self):
        self.rx_thread.start()

    def _receive_loop(self):
        """Background listener for incoming GCS commands and heartbeats."""
        print(f"[RX Thread] Listening on {self.bind_ip}:{self.bind_port} for GCS packets (Sender ID: {SENDER_ID_GCS})...")
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(1.0)
                datagram, sender_addr = self.sock.recvfrom(2048)
            except socket.timeout:
                self.fsm.check_heartbeat_timeout(timeout_sec=3.5)
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"[RX Exception] {e}")
                continue

            # Verify datagram from GCS (expected_sender_id = 1)
            result = FaultLocalizer.inspect_and_verify(
                datagram=datagram,
                key=self.key,
                replay_window=self.replay_window,
                expected_sender_id=SENDER_ID_GCS,
            )

            if not result.is_valid:
                self.total_rx_rejected += 1
                header = result.packet.header if result.packet else None
                self.fault_monitor.record_fault(
                    category=result.category or FaultCategory.INTERNAL_ERROR,
                    stage=result.stage,
                    action_taken="DISCARD_DATAGRAM",
                    recovery_state=self.fsm.current_state.value,
                    details=result.reason or "Validation failure",
                    sender_id=header.sender_id if header else None,
                    session_id=header.session_id if header else None,
                    packet_counter=header.packet_counter if header else None,
                )
                self.fsm.on_fault_detected(result.reason or "Validation failure")
                print(
                    f"\n  [UAV SECURITY REJECTION] From {sender_addr[0]}:{sender_addr[1]} | "
                    f"Stage: {result.stage} | Category: {result.category} | Reason: {result.reason}"
                )
                continue

            # Authentication succeeded
            self.total_rx_authenticated += 1
            header = result.packet.header
            self.replay_window.commit(header.session_id, header.packet_counter)
            self.fsm.on_valid_packet()

            # Auto-detect PC address for return telemetry stream
            with self.addr_lock:
                if self.pc_address != sender_addr:
                    self.pc_address = sender_addr
                    print(f"\n>>> [PC Return Address Set] Streaming return telemetry to: {sender_addr[0]}:{sender_addr[1]}\n")

            # Decode authenticated MAVLink frame
            messages, warnings = self.decoder.parse_bytes(result.plaintext)
            for msg in messages:
                print(
                    f"  [UAV <- GCS RX #{header.packet_counter:04d}] {msg.msg_type} | "
                    f"SysID: {msg.src_system} | CompID: {msg.src_component} | "
                    f"Session: {header.session_id:016x}"
                )
            for warn in warnings:
                print(f"  [UAV Policy Warning] {warn}")

    def send_telemetry(self) -> Optional[int]:
        """Encodes, encrypts, and transmits UAV heartbeat + attitude to PC (Sender ID = 2)."""
        with self.addr_lock:
            target = self.pc_address

        if target is None:
            return None

        # 1. Encode UAV Heartbeat
        hb = self.mav.heartbeat_encode(
            mavlink2.MAV_TYPE_QUADROTOR,
            mavlink2.MAV_AUTOPILOT_ARDUPILOTMEGA,
            0,
            0,
            mavlink2.MAV_STATE_ACTIVE
        )
        hb_bytes = hb.pack(self.mav)

        # 2. Encode Simulated Attitude (Roll: 0.03 rad, Pitch: -0.01 rad, Yaw: 1.57 rad)
        att = self.mav.attitude_encode(
            0,
            0.03,
            -0.01,
            1.57,
            0.0, 0.0, 0.0
        )
        att_bytes = att.pack(self.mav)

        combined_plaintext = hb_bytes + att_bytes

        # 3. Nonce allocation
        counter, nonce = self.nonce_mgr.next_nonce()

        # 4. Canonical header with UAV Sender ID (2)
        header = PacketHeader(
            magic=MAGIC_BYTES,
            version=PROTOCOL_VERSION,
            flags=FLAG_HEARTBEAT,
            sender_id=SENDER_ID_UAV,
            session_id=self.nonce_mgr.session_id,
            packet_counter=counter,
            nonce=nonce,
            ciphertext_length=len(combined_plaintext),
        )
        aad = header.pack()

        # 5. Encrypt with Ascon-AEAD128
        ct, tag = AsconAEAD128.encrypt(
            key=self.key,
            nonce=nonce,
            aad=aad,
            plaintext=combined_plaintext,
        )

        packet = SecurePacket(header=header, ciphertext=ct, tag=tag)
        datagram = packet.serialize()

        # 6. Transmit to PC
        self.sock.sendto(datagram, target)
        self.total_tx += 1

        print(
            f"[UAV -> GCS TX #{counter:04d}] Sent UAV Telemetry -> {target[0]}:{target[1]} | "
            f"Plaintext: {len(combined_plaintext)}B (HB+ATT) | Datagram: {len(datagram)}B"
        )
        return counter

    def close(self):
        self.stop_event.set()
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="SecureFlex Two-Way UAV Transceiver (Raspberry Pi 5)")
    parser.add_argument("--bind-ip", default=DEFAULT_LOCAL_BIND_IP, help="Local UDP bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP listening port")
    parser.add_argument("--target-ip", default=None, help="Optional static Windows PC IP address")
    parser.add_argument("--target-port", type=int, default=DEFAULT_UDP_PORT, help="Windows PC UDP port")
    parser.add_argument("--key-file", default="config/secret.key", help="Path to secret key file")
    parser.add_argument("--rate", type=float, default=1.0, help="Telemetry rate in Hz (default: 1.0)")
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

    print("=" * 68)
    print("  SecureFlex Two-Way MAVLink Transceiver (Raspberry Pi 5 UAV Node)")
    print("  Full-Duplex NIST SP 800-232 Ascon-AEAD128 Authenticated Encryption")
    print(f"  Listening on: {args.bind_ip}:{args.port} (UDP)")
    print(f"  UAV Sender ID: {SENDER_ID_UAV} | GCS Sender ID: {SENDER_ID_GCS}")
    if args.target_ip:
        print(f"  Static PC Target: {args.target_ip}:{args.target_port}")
    else:
        print("  Return Target: AUTO-DETECT (learns PC IP:port from incoming packets)")
    print("=" * 68)

    transceiver = SecureUAVTransceiver(
        bind_ip=args.bind_ip,
        bind_port=args.port,
        target_pc_ip=args.target_ip,
        target_pc_port=args.target_port,
        key=key,
    )
    transceiver.start()

    interval = 1.0 / max(0.1, args.rate)

    try:
        while True:
            sent = transceiver.send_telemetry()
            if sent is None:
                print("[Waiting for GCS] Waiting for initial packet from Windows PC to establish return route...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[UAV] Stopping transceiver on user interrupt...")
        print(f"[Summary] Transmitted: {transceiver.total_tx} | Received: {transceiver.total_rx_authenticated} | Rejected: {transceiver.total_rx_rejected}")
    finally:
        transceiver.close()


if __name__ == "__main__":
    main()

