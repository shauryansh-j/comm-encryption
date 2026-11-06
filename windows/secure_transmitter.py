"""
SecureFlex MAVLink Transmitter (Windows Laptop).
Encrypts MAVLink heartbeats using NIST SP 800-232 Ascon-AEAD128 and transmits over UDP.
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
    DEFAULT_TARGET_IP,
    DEFAULT_UDP_PORT,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    SENDER_ID_GCS,
    DEFAULT_HEARTBEAT_INTERVAL_SEC,
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from crypto.ascon_adapter import AsconAEAD128
from windows.mavlink_sender import MAVLinkFrameSerializer
from config.key_generator import load_key_from_file


class SecureMAVLinkTransmitter:
    """
    Handles secure serialization, AEAD encryption, framing, and UDP transmission of MAVLink frames.
    """

    def __init__(
        self,
        target_ip: str = DEFAULT_TARGET_IP,
        target_port: int = DEFAULT_UDP_PORT,
        key: bytes = None,
        sender_id: int = SENDER_ID_GCS,
        source_system: int = 255,
        source_component: int = 190,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.sender_id = sender_id
        self.key = key

        if self.key is None:
            raise ValueError("A valid 16-byte cryptographic key must be provided")

        self.serializer = MAVLinkFrameSerializer(source_system, source_component)
        self.nonce_mgr = NonceManager()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.total_transmitted = 0

    def send_heartbeat(
        self,
        corrupt_ct: bool = False,
        corrupt_tag: bool = False,
        corrupt_aad: bool = False,
    ) -> int:
        """
        Serializes, encrypts, and transmits a single MAVLink heartbeat datagram.
        Allows controlled fault injection for demonstration/testing.
        """
        # 1. Generate complete MAVLink heartbeat frame
        mavlink_plaintext = self.serializer.create_heartbeat()

        # 2. Acquire fresh monotonic counter and 16-byte nonce
        counter, nonce = self.nonce_mgr.next_nonce()

        # 3. Construct canonical header
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

        # 4. Canonical header serves as Authenticated Associated Data (AAD)
        aad = header.pack()

        if corrupt_aad:
            # Tamper with AAD bit/byte
            aad = bytearray(aad)
            aad[0] ^= 0xFF
            aad = bytes(aad)

        # 5. Encrypt and authenticate with Ascon-AEAD128
        ciphertext, tag = AsconAEAD128.encrypt(
            key=self.key,
            nonce=nonce,
            aad=aad,
            plaintext=mavlink_plaintext,
        )

        # Fault injection hooks
        if corrupt_ct:
            ct_list = bytearray(ciphertext)
            ct_list[0] ^= 0x01  # Flip 1 bit in ciphertext
            ciphertext = bytes(ct_list)

        if corrupt_tag:
            tag_list = bytearray(tag)
            tag_list[0] ^= 0x01  # Flip 1 bit in tag
            tag = bytes(tag_list)

        # 6. Assemble complete packet
        packet = SecurePacket(header=header, ciphertext=ciphertext, tag=tag)
        datagram = packet.serialize()

        # 7. Transmit via UDP
        self.sock.sendto(datagram, (self.target_ip, self.target_port))
        self.total_transmitted += 1

        print(
            f"[TX #{counter:04d}] Sent SecureFlex packet -> {self.target_ip}:{self.target_port} | "
            f"Session: {self.nonce_mgr.session_id:016x} | "
            f"Plaintext: {len(mavlink_plaintext)}B | "
            f"Datagram: {len(datagram)}B | "
            f"Tag: {tag[:4].hex()}..."
        )
        return counter

    def close(self):
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="SecureFlex MAVLink Transmitter (Windows)")
    parser.add_argument("--target-ip", default=DEFAULT_TARGET_IP, help="Raspberry Pi IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP destination port")
    parser.add_argument("--key-file", default="config/secret.key", help="Path to 16-byte secret key file")
    parser.add_argument("--rate", type=float, default=1.0, help="Heartbeat rate in Hz (default: 1.0)")
    parser.add_argument("--test-corrupt-ct", action="store_true", help="Test: Corrupt ciphertext bit")
    parser.add_argument("--test-corrupt-tag", action="store_true", help="Test: Corrupt authentication tag")
    parser.add_argument("--test-corrupt-aad", action="store_true", help="Test: Corrupt AAD header")
    args = parser.parse_args()

    # Locate key file
    key_path = os.path.abspath(args.key_file)
    if not os.path.isfile(key_path):
        # Fallback to local config dir if called from different cwd
        alt_path = os.path.join(PROJECT_ROOT, "config", "secret.key")
        if os.path.isfile(alt_path):
            key_path = alt_path

    try:
        key = load_key_from_file(key_path)
    except Exception as e:
        print(f"[Error] Failed to load key file '{key_path}': {e}")
        print("Run 'python config/key_generator.py -o config/secret.key' first!")
        sys.exit(1)

    print("=" * 65)
    print("  SecureFlex-MAVLink Secure Transmitter (Windows Laptop)")
    print("  Algorithm: NIST SP 800-232 Ascon-AEAD128")
    print(f"  Destination: {args.target_ip}:{args.port}")
    print(f"  Key File: {key_path}")
    print(f"  Heartbeat Rate: {args.rate} Hz")
    if args.test_corrupt_ct:
        print("  [ALERT] TEST MODE: Ciphertext bit-flipping ENABLED")
    if args.test_corrupt_tag:
        print("  [ALERT] TEST MODE: Tag bit-flipping ENABLED")
    if args.test_corrupt_aad:
        print("  [ALERT] TEST MODE: AAD tampering ENABLED")
    print("=" * 65)

    transmitter = SecureMAVLinkTransmitter(
        target_ip=args.target_ip,
        target_port=args.port,
        key=key,
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
        print(f"\n[Transmitter] Stopped by operator. Total datagrams sent: {transmitter.total_transmitted}")
    finally:
        transmitter.close()


if __name__ == "__main__":
    main()

