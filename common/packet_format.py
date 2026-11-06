"""
Binary Packet Framing and Parsing for SecureFlex-MAVLink Transport.
Encapsulates Ascon-AEAD128 ciphertext, canonical authenticated headers (AAD), and authentication tags.
"""
from dataclasses import dataclass
import struct
from typing import Tuple

from .protocol_constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    HEADER_STRUCT_FORMAT,
    HEADER_SIZE_BYTES,
    MIN_PACKET_SIZE_BYTES,
    MAX_PACKET_SIZE_BYTES,
    MAX_CIPHERTEXT_SIZE_BYTES,
    TAG_SIZE_BYTES,
    NONCE_SIZE_BYTES,
)


class PacketParseError(Exception):
    """Base exception for packet format errors."""
    pass


class FramingError(PacketParseError):
    """Packet size or magic bytes are invalid."""
    pass


class VersionError(PacketParseError):
    """Protocol version is unsupported."""
    pass


class LengthMismatchError(PacketParseError):
    """Ciphertext length in header does not match datagram length."""
    pass


@dataclass(frozen=True)
class PacketHeader:
    """Fixed-size canonical packet header (39 bytes)."""
    magic: bytes
    version: int
    flags: int
    sender_id: int
    session_id: int
    packet_counter: int
    nonce: bytes
    ciphertext_length: int

    def pack(self) -> bytes:
        """Serializes header into 39 canonical big-endian bytes used as AAD."""
        if len(self.nonce) != NONCE_SIZE_BYTES:
            raise ValueError(f"Nonce must be {NONCE_SIZE_BYTES} bytes, got {len(self.nonce)}")
        return struct.pack(
            HEADER_STRUCT_FORMAT,
            self.magic,
            self.version,
            self.flags,
            self.sender_id,
            self.session_id,
            self.packet_counter,
            self.nonce,
            self.ciphertext_length,
        )

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> "PacketHeader":
        """Parses canonical header from bytes without trusting field values."""
        if len(raw_bytes) < HEADER_SIZE_BYTES:
            raise FramingError(
                f"Header too short: expected {HEADER_SIZE_BYTES} bytes, got {len(raw_bytes)}"
            )

        magic, version, flags, sender_id, session_id, counter, nonce, ct_len = struct.unpack(
            HEADER_STRUCT_FORMAT, raw_bytes[:HEADER_SIZE_BYTES]
        )

        if magic != MAGIC_BYTES:
            raise FramingError(f"Invalid magic: expected {MAGIC_BYTES!r}, got {magic!r}")

        if version != PROTOCOL_VERSION:
            raise VersionError(f"Unsupported version {version}, expected {PROTOCOL_VERSION}")

        if ct_len > MAX_CIPHERTEXT_SIZE_BYTES:
            raise LengthMismatchError(
                f"Declared ciphertext length {ct_len} exceeds max {MAX_CIPHERTEXT_SIZE_BYTES}"
            )

        return cls(
            magic=magic,
            version=version,
            flags=flags,
            sender_id=sender_id,
            session_id=session_id,
            packet_counter=counter,
            nonce=nonce,
            ciphertext_length=ct_len,
        )


@dataclass
class SecurePacket:
    """Complete SecureFlex datagram containing header (AAD), ciphertext, and tag."""
    header: PacketHeader
    ciphertext: bytes
    tag: bytes

    def serialize(self) -> bytes:
        """Serializes full packet into a UDP datagram."""
        header_bytes = self.header.pack()
        if len(self.ciphertext) != self.header.ciphertext_length:
            raise ValueError(
                f"Ciphertext len {len(self.ciphertext)} does not match header length {self.header.ciphertext_length}"
            )
        if len(self.tag) != TAG_SIZE_BYTES:
            raise ValueError(f"Tag must be {TAG_SIZE_BYTES} bytes, got {len(self.tag)}")
        return header_bytes + self.ciphertext + self.tag

    def get_aad(self) -> bytes:
        """Returns the canonical header bytes used as Authenticated Associated Data."""
        return self.header.pack()

    @classmethod
    def parse(cls, datagram: bytes) -> "SecurePacket":
        """
        Parses and validates framing of received datagram.
        NOTE: This DOES NOT authenticate the payload. Cryptographic verification MUST follow.
        """
        if len(datagram) < MIN_PACKET_SIZE_BYTES:
            raise FramingError(
                f"Datagram too short: {len(datagram)} bytes (minimum {MIN_PACKET_SIZE_BYTES})"
            )

        if len(datagram) > MAX_PACKET_SIZE_BYTES:
            raise FramingError(
                f"Datagram too large: {len(datagram)} bytes (maximum {MAX_PACKET_SIZE_BYTES})"
            )

        header = PacketHeader.unpack(datagram[:HEADER_SIZE_BYTES])

        expected_total_len = HEADER_SIZE_BYTES + header.ciphertext_length + TAG_SIZE_BYTES
        if len(datagram) != expected_total_len:
            raise LengthMismatchError(
                f"Total datagram length {len(datagram)} does not match expected {expected_total_len} "
                f"(declared ciphertext: {header.ciphertext_length} bytes)"
            )

        ct_start = HEADER_SIZE_BYTES
        ct_end = ct_start + header.ciphertext_length
        ciphertext = datagram[ct_start:ct_end]
        tag = datagram[ct_end:ct_end + TAG_SIZE_BYTES]

        return cls(header=header, ciphertext=ciphertext, tag=tag)

