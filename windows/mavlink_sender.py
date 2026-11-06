"""
MAVLink Message Serializer for Windows Transmitter.
Uses pymavlink dialect to encode and serialize complete MAVLink 2.0 frames into byte arrays.
"""
from typing import Optional
from pymavlink.dialects.v20 import common as mavlink2


class MAVLinkFrameSerializer:
    """
    Constructs and serializes complete MAVLink protocol frames into binary payloads.
    Decoupled from network transport to facilitate AEAD encryption.
    """

    def __init__(self, source_system: int = 255, source_component: int = 190):
        self.source_system = source_system
        self.source_component = source_component
        self.mav = mavlink2.MAVLink(
            None,
            srcSystem=self.source_system,
            srcComponent=self.source_component
        )

    def create_heartbeat(
        self,
        mav_type: int = mavlink2.MAV_TYPE_GCS,
        autopilot: int = mavlink2.MAV_AUTOPILOT_INVALID,
        base_mode: int = 0,
        custom_mode: int = 0,
        system_status: int = mavlink2.MAV_STATE_ACTIVE
    ) -> bytes:
        """
        Encodes a standard MAVLink heartbeat and returns serialized bytes.
        """
        msg = self.mav.heartbeat_encode(
            mav_type,
            autopilot,
            base_mode,
            custom_mode,
            system_status
        )
        return msg.pack(self.mav)

    def create_status_text(self, text: str, severity: int = mavlink2.MAV_SEVERITY_INFO) -> bytes:
        """
        Encodes a MAVLink STATUSTEXT message and returns serialized bytes.
        """
        msg = self.mav.statustext_encode(
            severity,
            text.encode("utf-8")[:50]
        )
        return msg.pack(self.mav)

