"""
Test Suite: SecureFlex Binary Packet Framing and Header Validation.
"""
import pytest
from common.protocol_constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    HEADER_SIZE_BYTES,
    TAG_SIZE_BYTES,
    MIN_PACKET_SIZE_BYTES,
)
from common.packet_format import (
    PacketHeader,
    SecurePacket,
    FramingError,
    VersionError,
    LengthMismatchError,
)


def test_packet_header_pack_unpack_roundtrip():
    nonce = b"\x00" * 16
    header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=FLAG_HEARTBEAT,
        sender_id=1,
        session_id=0x1122334455667788,
        packet_counter=42,
        nonce=nonce,
        ciphertext_length=21,
    )
    packed = header.pack()
    assert len(packed) == HEADER_SIZE_BYTES

    unpacked = PacketHeader.unpack(packed)
    assert unpacked.magic == MAGIC_BYTES
    assert unpacked.version == PROTOCOL_VERSION
    assert unpacked.flags == FLAG_HEARTBEAT
    assert unpacked.sender_id == 1
    assert unpacked.session_id == 0x1122334455667788
    assert unpacked.packet_counter == 42
    assert unpacked.nonce == nonce
    assert unpacked.ciphertext_length == 21


def test_packet_header_invalid_magic():
    nonce = b"\x00" * 16
    bad_bytes = b"XX" + b"\x01\x00\x01" + b"\x00" * 8 + b"\x00" * 8 + nonce + b"\x00\x05"
    with pytest.raises(FramingError):
        PacketHeader.unpack(bad_bytes)


def test_packet_header_unsupported_version():
    nonce = b"\x00" * 16
    bad_bytes = MAGIC_BYTES + b"\x02\x00\x01" + b"\x00" * 8 + b"\x00" * 8 + nonce + b"\x00\x05"
    with pytest.raises(VersionError):
        PacketHeader.unpack(bad_bytes)


def test_secure_packet_length_mismatch():
    nonce = b"\x00" * 16
    header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=0,
        sender_id=1,
        session_id=1,
        packet_counter=1,
        nonce=nonce,
        ciphertext_length=10,  # Declares 10 bytes
    )
    # But passes 5 bytes ciphertext
    with pytest.raises(ValueError):
        SecurePacket(header=header, ciphertext=b"12345", tag=b"\x00" * 16).serialize()


def test_secure_packet_parse_truncated():
    # Pass fewer bytes than minimum 55
    with pytest.raises(FramingError):
        SecurePacket.parse(b"\x00" * 30)

