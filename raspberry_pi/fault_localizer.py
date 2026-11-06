"""
Fault Localization Engine for SecureFlex-MAVLink Transport.
Pinpoints the exact verification stage and failure mode of corrupted, replayed, or forged packets.
"""
from enum import Enum
from typing import Optional, Tuple
from common.protocol_constants import (
    HEADER_SIZE_BYTES,
    MIN_PACKET_SIZE_BYTES,
    MAX_PACKET_SIZE_BYTES,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
)
from common.packet_format import PacketHeader, SecurePacket, FramingError, VersionError, LengthMismatchError
from common.replay_window import ReplayProtectionWindow
from crypto.ascon_adapter import AsconAEAD128
from raspberry_pi.fault_monitor import FaultCategory


class VerificationStage(str, Enum):
    DATAGRAM_SIZE = "STAGE_1_DATAGRAM_SIZE"
    HEADER_FRAMING = "STAGE_2_HEADER_FRAMING"
    VERSION_CHECK = "STAGE_3_VERSION_CHECK"
    SENDER_POLICY = "STAGE_4_SENDER_POLICY"
    REPLAY_CHECK = "STAGE_5_REPLAY_PRE_CHECK"
    AUTHENTICATION = "STAGE_6_ASCON_AEAD128_AUTH"
    MAVLINK_PARSING = "STAGE_7_MAVLINK_PARSING"


class LocalizationResult:
    def __init__(
        self,
        is_valid: bool,
        stage: str,
        category: Optional[str] = None,
        reason: Optional[str] = None,
        packet: Optional[SecurePacket] = None,
        plaintext: Optional[bytes] = None,
    ):
        self.is_valid = is_valid
        self.stage = stage
        self.category = category
        self.reason = reason
        self.packet = packet
        self.plaintext = plaintext

    def __repr__(self) -> str:
        if self.is_valid:
            return f"<LocalizationResult: VALID at {self.stage}>"
        return f"<LocalizationResult: REJECTED at {self.stage} [{self.category}]: {self.reason}>"


class FaultLocalizer:
    """
    Step-by-step pipeline evaluator for fault localization and forensics.
    """

    @staticmethod
    def inspect_and_verify(
        datagram: bytes,
        key: bytes,
        replay_window: ReplayProtectionWindow,
        expected_sender_id: Optional[int] = None,
    ) -> LocalizationResult:
        # Stage 1: Raw Datagram Size Checks
        if len(datagram) < MIN_PACKET_SIZE_BYTES or len(datagram) > MAX_PACKET_SIZE_BYTES:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.DATAGRAM_SIZE,
                category=FaultCategory.INVALID_FRAMING,
                reason=f"Datagram size {len(datagram)} out of bounds [{MIN_PACKET_SIZE_BYTES}, {MAX_PACKET_SIZE_BYTES}]",
            )

        # Stage 2 & 3: Header Framing and Version
        try:
            packet = SecurePacket.parse(datagram)
        except FramingError as e:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.HEADER_FRAMING,
                category=FaultCategory.INVALID_FRAMING,
                reason=str(e),
            )
        except VersionError as e:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.VERSION_CHECK,
                category=FaultCategory.UNSUPPORTED_VERSION,
                reason=str(e),
            )
        except LengthMismatchError as e:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.HEADER_FRAMING,
                category=FaultCategory.INVALID_FRAMING,
                reason=str(e),
            )
        except Exception as e:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.HEADER_FRAMING,
                category=FaultCategory.INVALID_FRAMING,
                reason=f"Unexpected framing error: {e}",
            )

        # Stage 4: Sender Identity Policy
        if expected_sender_id is not None and packet.header.sender_id != expected_sender_id:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.SENDER_POLICY,
                category=FaultCategory.UNEXPECTED_SENDER,
                reason=f"Sender ID {packet.header.sender_id} does not match expected {expected_sender_id}",
                packet=packet,
            )

        # Stage 5: Replay Window Pre-Check (Without State Mutation)
        ok, replay_reason = replay_window.check(packet.header.session_id, packet.header.packet_counter)
        if not ok:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.REPLAY_CHECK,
                category=FaultCategory.REPLAY_ATTACK,
                reason=f"Replay window check rejected: {replay_reason}",
                packet=packet,
            )

        # Stage 6: Ascon-AEAD128 Verification & Decryption
        aad = packet.get_aad()
        plaintext = AsconAEAD128.decrypt(
            key=key,
            nonce=packet.header.nonce,
            aad=aad,
            ciphertext=packet.ciphertext,
            tag=packet.tag,
        )

        if plaintext is None:
            return LocalizationResult(
                is_valid=False,
                stage=VerificationStage.AUTHENTICATION,
                category=FaultCategory.AUTHENTICATION_FAILED,
                reason="Ascon-AEAD128 authentication tag mismatch or corrupted ciphertext/AAD",
                packet=packet,
            )

        # All transport security checks passed!
        return LocalizationResult(
            is_valid=True,
            stage=VerificationStage.AUTHENTICATION,
            packet=packet,
            plaintext=plaintext,
        )

