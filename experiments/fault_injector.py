"""
Test-Only Controlled Fault Injector for SecureFlex-MAVLink.
CRITICAL: For laboratory evaluation and test campaigns only. Never deploy in production.
"""
import argparse
import socket
import struct
import sys
import os

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
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from crypto.ascon_adapter import AsconAEAD128
from windows.mavlink_sender import MAVLinkFrameSerializer
from config.key_generator import load_key_from_file


class FaultInjector:
    def __init__(self, target_ip: str, target_port: int, key: bytes):
        self.target_ip = target_ip
        self.target_port = target_port
        self.key = key
        self.serializer = MAVLinkFrameSerializer()
        self.nonce_mgr = NonceManager()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _create_valid_packet(self) -> Tuple[PacketHeader, bytes, bytes, bytes]:
        mav_bytes = self.serializer.create_heartbeat()
        counter, nonce = self.nonce_mgr.next_nonce()
        header = PacketHeader(
            magic=MAGIC_BYTES,
            version=PROTOCOL_VERSION,
            flags=FLAG_HEARTBEAT,
            sender_id=SENDER_ID_GCS,
            session_id=self.nonce_mgr.session_id,
            packet_counter=counter,
            nonce=nonce,
            ciphertext_length=len(mav_bytes),
        )
        aad = header.pack()
        ct, tag = AsconAEAD128.encrypt(self.key, nonce, aad, mav_bytes)
        datagram = SecurePacket(header=header, ciphertext=ct, tag=tag).serialize()
        return header, ct, tag, datagram

    def inject_ciphertext_bitflip(self):
        """1. Flips bit 0 of ciphertext."""
        header, ct, tag, _ = self._create_valid_packet()
        corrupted_ct = bytearray(ct)
        corrupted_ct[0] ^= 0x01
        packet = SecurePacket(header=header, ciphertext=bytes(corrupted_ct), tag=tag)
        self.sock.sendto(packet.serialize(), (self.target_ip, self.target_port))
        print("Injected: Bit-flip in ciphertext (Expected: AUTHENTICATION_FAILED)")

    def inject_tag_bitflip(self):
        """2. Flips bit 0 of authentication tag."""
        header, ct, tag, _ = self._create_valid_packet()
        corrupted_tag = bytearray(tag)
        corrupted_tag[0] ^= 0x01
        packet = SecurePacket(header=header, ciphertext=ct, tag=bytes(corrupted_tag))
        self.sock.sendto(packet.serialize(), (self.target_ip, self.target_port))
        print("Injected: Bit-flip in tag (Expected: AUTHENTICATION_FAILED)")

    def inject_aad_tamper(self):
        """3. Modifies header field without updating tag."""
        header, ct, tag, _ = self._create_valid_packet()
        tampered_header = PacketHeader(
            magic=header.magic,
            version=header.version,
            flags=0xFF,  # Tampered flags
            sender_id=header.sender_id,
            session_id=header.session_id,
            packet_counter=header.packet_counter,
            nonce=header.nonce,
            ciphertext_length=header.ciphertext_length,
        )
        packet = SecurePacket(header=tampered_header, ciphertext=ct, tag=tag)
        self.sock.sendto(packet.serialize(), (self.target_ip, self.target_port))
        print("Injected: Tampered AAD flags (Expected: AUTHENTICATION_FAILED)")

    def inject_truncation(self):
        """4. Truncates datagram length."""
        _, _, _, datagram = self._create_valid_packet()
        truncated = datagram[:-10]
        self.sock.sendto(truncated, (self.target_ip, self.target_port))
        print("Injected: Truncated datagram (Expected: INVALID_FRAMING)")

    def inject_extra_bytes(self):
        """5. Appends rogue bytes to valid datagram."""
        _, _, _, datagram = self._create_valid_packet()
        oversized = datagram + b"\xDE\xAD\xBE\xEF"
        self.sock.sendto(oversized, (self.target_ip, self.target_port))
        print("Injected: Extra trailing bytes (Expected: INVALID_FRAMING)")

    def inject_replay_attack(self):
        """6. Sends identical datagram twice."""
        _, _, _, datagram = self._create_valid_packet()
        self.sock.sendto(datagram, (self.target_ip, self.target_port))
        # Second replayed transmission
        self.sock.sendto(datagram, (self.target_ip, self.target_port))
        print("Injected: Duplicate replayed datagram (Expected: REPLAY_ATTACK)")

    def inject_unsupported_version(self):
        """7. Sends unsupported protocol version."""
        mav_bytes = self.serializer.create_heartbeat()
        counter, nonce = self.nonce_mgr.next_nonce()
        header = PacketHeader(
            magic=MAGIC_BYTES,
            version=99,  # Bad version
            flags=0,
            sender_id=SENDER_ID_GCS,
            session_id=self.nonce_mgr.session_id,
            packet_counter=counter,
            nonce=nonce,
            ciphertext_length=len(mav_bytes),
        )
        ct, tag = AsconAEAD128.encrypt(self.key, nonce, header.pack(), mav_bytes)
        packet = SecurePacket(header=header, ciphertext=ct, tag=tag)
        self.sock.sendto(packet.serialize(), (self.target_ip, self.target_port))
        print("Injected: Unsupported version 99 (Expected: UNSUPPORTED_VERSION)")

    def inject_random_noise(self):
        """8. Sends raw random noise."""
        noise = os.urandom(64)
        self.sock.sendto(noise, (self.target_ip, self.target_port))
        print("Injected: 64 bytes of random noise (Expected: INVALID_FRAMING)")

    def inject_wrong_sender(self):
        """9. Sends packet from unapproved sender ID."""
        mav_bytes = self.serializer.create_heartbeat()
        counter, nonce = self.nonce_mgr.next_nonce()
        header = PacketHeader(
            magic=MAGIC_BYTES,
            version=PROTOCOL_VERSION,
            flags=0,
            sender_id=88,  # Rogue sender ID
            session_id=self.nonce_mgr.session_id,
            packet_counter=counter,
            nonce=nonce,
            ciphertext_length=len(mav_bytes),
        )
        ct, tag = AsconAEAD128.encrypt(self.key, nonce, header.pack(), mav_bytes)
        packet = SecurePacket(header=header, ciphertext=ct, tag=tag)
        self.sock.sendto(packet.serialize(), (self.target_ip, self.target_port))
        print("Injected: Unauthorized sender ID 88 (Expected: UNEXPECTED_SENDER)")


def main():
    parser = argparse.ArgumentParser(description="SecureFlex Laboratory Fault Injector")
    parser.add_argument("--ip", default=DEFAULT_TARGET_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("--key-file", default="config/secret.key")
    parser.add_argument(
        "--fault",
        choices=["ct", "tag", "aad", "truncate", "extra", "replay", "version", "noise", "sender", "all"],
        default="all",
        help="Select fault injection type",
    )
    args = parser.parse_args()

    key = load_key_from_file(args.key_file)
    injector = FaultInjector(args.ip, args.port, key)

    dispatch = {
        "ct": injector.inject_ciphertext_bitflip,
        "tag": injector.inject_tag_bitflip,
        "aad": injector.inject_aad_tamper,
        "truncate": injector.inject_truncation,
        "extra": injector.inject_extra_bytes,
        "replay": injector.inject_replay_attack,
        "version": injector.inject_unsupported_version,
        "noise": injector.inject_random_noise,
        "sender": injector.inject_wrong_sender,
    }

    if args.fault == "all":
        for name, fn in dispatch.items():
            fn()
    else:
        dispatch[args.fault]()


if __name__ == "__main__":
    main()

