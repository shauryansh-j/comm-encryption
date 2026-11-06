"""
MAVLink Message Decoder for Raspberry Pi 5.
Parses authenticated byte streams using pymavlink and validates source identity policies.
"""
from typing import List, Optional, Tuple
from pymavlink.dialects.v20 import common as mavlink2


class DecodedMAVLinkMessage:
    """Wrapper for parsed MAVLink message with metadata."""
    def __init__(self, msg):
        self.raw_msg = msg
        self.msg_type = msg.get_type()
        self.src_system = msg.get_srcSystem()
        self.src_component = msg.get_srcComponent()

    def __repr__(self) -> str:
        return f"MAVLink[{self.msg_type} | SysID:{self.src_system} | CompID:{self.src_component}]"


class AuthenticatedMAVLinkDecoder:
    """
    Parses authenticated plaintext bytes into MAVLink frames.
    SECURITY RULE: Only call this class with bytes verified by Ascon-AEAD128!
    """

    def __init__(self, expected_system_id: Optional[int] = 255, expected_component_id: Optional[int] = 190):
        self.expected_system_id = expected_system_id
        self.expected_component_id = expected_component_id
        self.mav = mavlink2.MAVLink(None)
        self.total_decoded = 0

    def parse_bytes(self, authenticated_payload: bytes) -> Tuple[List[DecodedMAVLinkMessage], List[str]]:
        """
        Feeds authenticated plaintext bytes to MAVLink stream parser.
        Returns:
            Tuple[List[DecodedMAVLinkMessage], List[str]]: (valid_messages, policy_warnings)
        """
        valid_msgs = []
        warnings = []

        parsed_objects = self.mav.parse_buffer(authenticated_payload)
        if not parsed_objects:
            return valid_msgs, warnings

        for msg in parsed_objects:
            decoded = DecodedMAVLinkMessage(msg)
            self.total_decoded += 1

            # Validate against configured sender policy if specified
            if self.expected_system_id is not None and decoded.src_system != self.expected_system_id:
                warnings.append(
                    f"Unexpected MAVLink SysID {decoded.src_system} (expected {self.expected_system_id})"
                )

            if self.expected_component_id is not None and decoded.src_component != self.expected_component_id:
                warnings.append(
                    f"Unexpected MAVLink CompID {decoded.src_component} (expected {self.expected_component_id})"
                )

            valid_msgs.append(decoded)

        return valid_msgs, warnings

