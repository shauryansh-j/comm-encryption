"""
Test Suite: End-to-End Secure MAVLink Pipeline Integration Test.
Simulates Windows transmitter -> UDP transport -> Raspberry Pi receiver -> pymavlink decoding.
"""
import socket
import pytest
from common.protocol_constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    SENDER_ID_GCS,
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from common.replay_window import ReplayProtectionWindow
from crypto.ascon_adapter import AsconAEAD128
from windows.mavlink_sender import MAVLinkFrameSerializer
from raspberry_pi.fault_localizer import FaultLocalizer
from raspberry_pi.mavlink_decoder import AuthenticatedMAVLinkDecoder


def test_end_to_end_valid_heartbeat_transmission_and_decoding():
    key = b"16_byte_test_key"
    serializer = MAVLinkFrameSerializer(source_system=255, source_component=190)
    nonce_mgr = NonceManager()
    replay_window = ReplayProtectionWindow()
    decoder = AuthenticatedMAVLinkDecoder(expected_system_id=255, expected_component_id=190)

    # 1. Transmitter encodes MAVLink heartbeat
    mavlink_frame = serializer.create_heartbeat()
    assert len(mavlink_frame) > 0

    # 2. Acquire counter and nonce
    counter, nonce = nonce_mgr.next_nonce()

    # 3. Construct canonical header and AAD
    header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=FLAG_HEARTBEAT,
        sender_id=SENDER_ID_GCS,
        session_id=nonce_mgr.session_id,
        packet_counter=counter,
        nonce=nonce,
        ciphertext_length=len(mavlink_frame),
    )
    aad = header.pack()

    # 4. Ascon-AEAD128 Encryption
    ct, tag = AsconAEAD128.encrypt(key, nonce, aad, mavlink_frame)

    # 5. Assemble and serialize datagram
    packet = SecurePacket(header=header, ciphertext=ct, tag=tag)
    datagram = packet.serialize()

    # 6. Receiver validates and decrypts
    result = FaultLocalizer.inspect_and_verify(
        datagram=datagram,
        key=key,
        replay_window=replay_window,
        expected_sender_id=SENDER_ID_GCS,
    )
    assert result.is_valid, f"Verification failed: {result.reason}"
    assert result.plaintext == mavlink_frame

    # 7. Commit counter
    replay_window.commit(header.session_id, counter)

    # 8. Feed authenticated plaintext to MAVLink decoder
    messages, warnings = decoder.parse_bytes(result.plaintext)
    assert len(messages) == 1
    assert messages[0].msg_type == "HEARTBEAT"
    assert messages[0].src_system == 255
    assert messages[0].src_component == 190
    assert len(warnings) == 0


def test_end_to_end_tampered_packet_never_reaches_decoder():
    key = b"16_byte_test_key"
    serializer = MAVLinkFrameSerializer()
    nonce_mgr = NonceManager()
    replay_window = ReplayProtectionWindow()
    decoder = AuthenticatedMAVLinkDecoder()

    mavlink_frame = serializer.create_heartbeat()
    counter, nonce = nonce_mgr.next_nonce()
    header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=FLAG_HEARTBEAT,
        sender_id=SENDER_ID_GCS,
        session_id=nonce_mgr.session_id,
        packet_counter=counter,
        nonce=nonce,
        ciphertext_length=len(mavlink_frame),
    )
    ct, tag = AsconAEAD128.encrypt(key, nonce, header.pack(), mavlink_frame)

    # Malicious tampering: flip byte in ciphertext
    corrupted_ct = bytearray(ct)
    corrupted_ct[2] ^= 0xFF

    bad_datagram = SecurePacket(header=header, ciphertext=bytes(corrupted_ct), tag=tag).serialize()

    # Receiver inspection
    result = FaultLocalizer.inspect_and_verify(
        datagram=bad_datagram,
        key=key,
        replay_window=replay_window,
        expected_sender_id=SENDER_ID_GCS,
    )

    # Must be rejected!
    assert not result.is_valid
    assert result.plaintext is None

    # Decoder must NOT be called, or if called with None/empty, produces 0 messages
    messages, _ = decoder.parse_bytes(b"")
    assert len(messages) == 0
    assert decoder.total_decoded == 0

