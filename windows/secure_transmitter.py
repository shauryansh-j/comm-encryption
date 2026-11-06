"""
SecureFlex MAVLink Transmitter & GCS Transceiver (Windows Laptop).
Full-duplex bidirectional communication:
- Encrypts and transmits MAVLink GCS heartbeats using NIST SP 800-232 Ascon-AEAD128 (Sender ID = 1)
- Listens for and authenticates incoming telemetry sent back by Raspberry Pi 5 (Sender ID = 2)
"""
import argparse
import os
import socket
import sys
import threading
import time

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.protocol_constants import (
    DEFAULT_TARGET_IP,
    DEFAULT_UDP_PORT,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    SENDER_ID_GCS,
    SENDER_ID_UAV,
    DEFAULT_HEARTBEAT_INTERVAL_SEC,
    REPLAY_WINDOW_SIZE,
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from common.replay_window import ReplayProtectionWindow
from crypto.ascon_adapter import AsconAEAD128
from windows.mavlink_sender import MAVLinkFrameSerializer
from raspberry_pi.mavlink_decoder import AuthenticatedMAVLinkDecoder
from raspberry_pi.fault_localizer import FaultLocalizer
from raspberry_pi.fault_monitor import FaultMonitor, FaultCategory
from config.key_generator import load_key_from_file


class SecureMAVLinkTransmitter:
    """
    Handles secure serialization, AEAD encryption, framing, and bidirectional UDP communication.
    """

    def __init__(
        self,
        target_ip: str = DEFAULT_TARGET_IP,
        target_port: int = DEFAULT_UDP_PORT,
        local_port: int = DEFAULT_UDP_PORT,
        key: bytes = None,
        sender_id: int = SENDER_ID_GCS,
        source_system: int = 255,
        source_component: int = 190,
        enable_two_way: bool = True,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.local_port = local_port
        self.sender_id = sender_id
        self.key = key
        self.enable_two_way = enable_two_way

        if self.key is None:
            raise ValueError("A valid 16-byte cryptographic key must be provided")

        self.serializer = MAVLinkFrameSerializer(source_system, source_component)
        self.decoder = AuthenticatedMAVLinkDecoder()
        self.nonce_mgr = NonceManager()
        self.replay_window = ReplayProtectionWindow(window_size=REPLAY_WINDOW_SIZE)
        self.fault_monitor = FaultMonitor(log_path="logs/windows_rx_faults.jsonl")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind locally on local_port so return UDP packets from Pi arrive directly
        try:
            self.sock.bind(("0.0.0.0", self.local_port))
            print(f"[Socket] Bound locally to 0.0.0.0:{self.local_port} for two-way communication")
        except Exception as e:
            print(f"[Socket Note] Could not bind 0.0.0.0:{self.local_port}: {e}. (Will use ephemeral port)")

        self.stop_event = threading.Event()
        self.total_transmitted = 0
        self.total_received = 0

        if self.enable_two_way:
            self.rx_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.rx_thread.start()

    def _receive_loop(self):
        """Background thread listening for encrypted UAV telemetry sent back by Raspberry Pi."""
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(1.0)
                datagram, sender_addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    pass
                continue

            # Verify datagram sent from UAV (Expected Sender ID = 2)
            result = FaultLocalizer.inspect_and_verify(
                datagram=datagram,
                key=self.key,
                replay_window=self.replay_window,
                expected_sender_id=SENDER_ID_UAV,
            )

            if not result.is_valid:
                header = result.packet.header if result.packet else None
                self.fault_monitor.record_fault(
                    category=result.category or FaultCategory.INTERNAL_ERROR,
                    stage=result.stage,
                    action_taken="DISCARD_DATAGRAM",
                    recovery_state="RUN",
                    details=result.reason or "Validation failure",
                    sender_id=header.sender_id if header else None,
                    session_id=header.session_id if header else None,
                    packet_counter=header.packet_counter if header else None,
                )
                print(
                    f"\n  [GCS REJECTION from {sender_addr[0]}] Stage: {result.stage} | "
                    f"Category: {result.category} | Reason: {result.reason}"
                )
                continue

            # Authenticated telemetry received from Raspberry Pi!
            self.total_received += 1
            header = result.packet.header
            self.replay_window.commit(header.session_id, header.packet_counter)

            messages, _ = self.decoder.parse_bytes(result.plaintext)
            for msg in messages:
                print(
                    f"  [GCS <- UAV RECEIVED #{header.packet_counter:04d}] {msg.msg_type} | "
                    f"SysID: {msg.src_system} | CompID: {msg.src_component} | "
                    f"Session: {header.session_id:016x}"
                )

    def send_heartbeat(
        self,
        corrupt_ct: bool = False,
        corrupt_tag: bool = False,
        corrupt_aad: bool = False,
    ) -> int:
        """Serializes, encrypts, and transmits a single MAVLink heartbeat datagram."""
        mavlink_plaintext = self.serializer.create_heartbeat()
        counter, nonce = self.nonce_mgr.next_nonce()

        header = PacketHeader(
            magic=MAGIC_BYTES,
            version=PROTOCOL_VERSION,
            flags=FLAG_HEARTBEAT,
            sender_id=self.sender_id,
            session_id=self.nonce_mgr.session_id,
            packet_counter=counter,
            nonce=nonce,
            ciphertext_length=len(mavlink_plaintext),
        )
        aad = header.pack()

        if corrupt_aad:
            aad = bytearray(aad)
            aad[0] ^= 0xFF
            aad = bytes(aad)

        ciphertext, tag = AsconAEAD128.encrypt(
            key=self.key,
            nonce=nonce,
            aad=aad,
            plaintext=mavlink_plaintext,
        )

        if corrupt_ct:
            ct_list = bytearray(ciphertext)
            ct_list[0] ^= 0x01
            ciphertext = bytes(ct_list)

        if corrupt_tag:
            tag_list = bytearray(tag)
            tag_list[0] ^= 0x01
            tag = bytes(tag_list)

        packet = SecurePacket(header=header, ciphertext=ciphertext, tag=tag)
        datagram = packet.serialize()

        self.sock.sendto(datagram, (self.target_ip, self.target_port))
        self.total_transmitted += 1

        print(
            f"[GCS -> UAV TX #{counter:04d}] Sent to {self.target_ip}:{self.target_port} | "
            f"Plaintext: {len(mavlink_plaintext)}B | Datagram: {len(datagram)}B"
        )
        return counter

    def close(self):
        self.stop_event.set()
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="SecureFlex MAVLink Transmitter & GCS Node (Windows)")
    parser.add_argument("--target-ip", default=DEFAULT_TARGET_IP, help="Raspberry Pi IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP destination port on Pi")
    parser.add_argument("--local-port", type=int, default=DEFAULT_UDP_PORT, help="Local UDP bind port on PC")
    parser.add_argument("--key-file", default="config/secret.key", help="Path to 16-byte secret key file")
    parser.add_argument("--rate", type=float, default=1.0, help="Heartbeat rate in Hz (default: 1.0)")
    parser.add_argument("--no-two-way", action="store_true", help="Disable receiving return telemetry from Pi")
    parser.add_argument("--test-corrupt-ct", action="store_true", help="Test: Corrupt ciphertext bit")
    parser.add_argument("--test-corrupt-tag", action="store_true", help="Test: Corrupt authentication tag")
    parser.add_argument("--test-corrupt-aad", action="store_true", help="Test: Corrupt AAD header")
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
    print("  SecureFlex-MAVLink Secure GCS Node (Windows Laptop)")
    print("  Full-Duplex NIST SP 800-232 Ascon-AEAD128 Authenticated Encryption")
    print(f"  Target Pi 5: {args.target_ip}:{args.port}")
    print(f"  Local Port: {args.local_port} | Two-Way Communication: {'ENABLED' if not args.no_two_way else 'DISABLED'}")
    print(f"  GCS Sender ID: {SENDER_ID_GCS} | Expected UAV Sender ID: {SENDER_ID_UAV}")
    print(f"  Key File: {key_path}")
    print("=" * 68)

    transmitter = SecureMAVLinkTransmitter(
        target_ip=args.target_ip,
        target_port=args.port,
        local_port=args.local_port,
        key=key,
        enable_two_way=not args.no_two_way,
    )

    interval = 1.0 / max(0.1, args.rate)

    try:
        while True:
            transmitter.send_heartbeat(
                corrupt_ct=args.test_corrupt_ct,
                corrupt_tag=args.test_corrupt_tag,
                corrupt_aad=args.test_corrupt_aad,
            )
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[Transmitter] Stopped by operator. Sent: {transmitter.total_transmitted} | Received: {transmitter.total_received}")
    finally:
        transmitter.close()


if __name__ == "__main__":
    main()
