"""
Test Suite: Bidirectional (Two-Way) Secure MAVLink Communication.
Validates:
1. GCS -> UAV encrypted transmission and authentication (Sender ID = 1)
2. UAV -> GCS encrypted transmission, dynamic return routing, and telemetry parsing (Sender ID = 2)
3. Domain separation: Cross-direction injection rejection
4. Live socket bidirectional loopback integration
"""
import time
import pytest
from common.protocol_constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    SENDER_ID_GCS,
    SENDER_ID_UAV,
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from common.replay_window import ReplayProtectionWindow
from crypto.ascon_adapter import AsconAEAD128
from windows.mavlink_sender import MAVLinkFrameSerializer
from raspberry_pi.mavlink_decoder import AuthenticatedMAVLinkDecoder
from raspberry_pi.fault_localizer import FaultLocalizer
from raspberry_pi.fault_monitor import FaultCategory
from windows.secure_transceiver import SecureGCSTransceiver
from raspberry_pi.secure_transceiver import SecureUAVTransceiver


def test_bidirectional_direction_domain_separation():
    """Confirms that packets sent by GCS cannot be accepted as UAV packets, and vice versa."""
    key = b"16_byte_test_key"
    gcs_nonce_mgr = NonceManager()
    uav_nonce_mgr = NonceManager()

    gcs_replay_window = ReplayProtectionWindow()  # GCS window tracking UAV packets (ID = 2)
    uav_replay_window = ReplayProtectionWindow()  # UAV window tracking GCS packets (ID = 1)

    serializer = MAVLinkFrameSerializer()
    mav_bytes = serializer.create_heartbeat()

    # 1. GCS creates packet with Sender ID = 1
    c1, n1 = gcs_nonce_mgr.next_nonce()
    gcs_header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=FLAG_HEARTBEAT,
        sender_id=SENDER_ID_GCS,
        session_id=gcs_nonce_mgr.session_id,
        packet_counter=c1,
        nonce=n1,
        ciphertext_length=len(mav_bytes),
    )
    ct1, tag1 = AsconAEAD128.encrypt(key, n1, gcs_header.pack(), mav_bytes)
    gcs_datagram = SecurePacket(header=gcs_header, ciphertext=ct1, tag=tag1).serialize()

    # UAV verifies GCS packet (Expected ID = 1) -> MUST SUCCEED
    res_uav = FaultLocalizer.inspect_and_verify(gcs_datagram, key, uav_replay_window, SENDER_ID_GCS)
    assert res_uav.is_valid is True
    assert res_uav.plaintext == mav_bytes

    # If GCS mistakenly (or via attacker) receives its own GCS packet expecting UAV (ID = 2) -> MUST FAIL
    res_cross = FaultLocalizer.inspect_and_verify(gcs_datagram, key, gcs_replay_window, SENDER_ID_UAV)
    assert res_cross.is_valid is False
    assert res_cross.category == FaultCategory.UNEXPECTED_SENDER

    # 2. UAV creates packet with Sender ID = 2
    c2, n2 = uav_nonce_mgr.next_nonce()
    uav_header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=FLAG_HEARTBEAT,
        sender_id=SENDER_ID_UAV,
        session_id=uav_nonce_mgr.session_id,
        packet_counter=c2,
        nonce=n2,
        ciphertext_length=len(mav_bytes),
    )
    ct2, tag2 = AsconAEAD128.encrypt(key, n2, uav_header.pack(), mav_bytes)
    uav_datagram = SecurePacket(header=uav_header, ciphertext=ct2, tag=tag2).serialize()

    # GCS verifies UAV packet (Expected ID = 2) -> MUST SUCCEED
    res_gcs = FaultLocalizer.inspect_and_verify(uav_datagram, key, gcs_replay_window, SENDER_ID_UAV)
    assert res_gcs.is_valid is True
    assert res_gcs.plaintext == mav_bytes

    # UAV receiving UAV packet (Expected ID = 1) -> MUST FAIL
    res_cross2 = FaultLocalizer.inspect_and_verify(uav_datagram, key, uav_replay_window, SENDER_ID_GCS)
    assert res_cross2.is_valid is False
    assert res_cross2.category == FaultCategory.UNEXPECTED_SENDER


def test_two_way_live_socket_loopback():
    """Full-duplex live socket test between SecureGCSTransceiver and SecureUAVTransceiver."""
    key = b"two_way_test_key"
    gcs_port = 14591
    uav_port = 14592

    # Start UAV node listening on uav_port
    uav = SecureUAVTransceiver(
        bind_ip="127.0.0.1",
        bind_port=uav_port,
        target_pc_ip="127.0.0.1",
        target_pc_port=gcs_port,
        key=key,
    )
    uav.start()

    # Start GCS node listening on gcs_port and sending to uav_port
    gcs = SecureGCSTransceiver(
        target_ip="127.0.0.1",
        target_port=uav_port,
        local_port=gcs_port,
        key=key,
    )
    gcs.start()

    time.sleep(0.3)

    try:
        # GCS transmits 3 heartbeats to UAV
        for _ in range(3):
            gcs.send_heartbeat()
            time.sleep(0.1)

        time.sleep(0.3)
        assert uav.total_rx_authenticated == 3, f"UAV received {uav.total_rx_authenticated}, expected 3"

        # UAV transmits 3 telemetry frames back to GCS
        for _ in range(3):
            uav.send_telemetry()
            time.sleep(0.1)

        time.sleep(0.3)
        assert gcs.total_rx_authenticated == 3, f"GCS received {gcs.total_rx_authenticated}, expected 3"

    finally:
        gcs.close()
        uav.close()

