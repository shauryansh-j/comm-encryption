"""
Protocol Constants for SecureFlex-MAVLink Secure Transport Layer.
Conforms to NIST SP 800-232 Ascon-AEAD128 and SecureFlex architectural specifications.
"""

# Binary Framing Identifiers
MAGIC_BYTES = b"SF"              # 0x53, 0x46 ("SecureFlex")
PROTOCOL_VERSION = 1             # Version 1

# Cryptographic Sizes (bytes) - Ascon-AEAD128 (NIST SP 800-232)
KEY_SIZE_BYTES = 16              # 128-bit symmetric key
NONCE_SIZE_BYTES = 16            # 128-bit unique nonce
TAG_SIZE_BYTES = 16              # 128-bit authentication tag
SESSION_ID_SIZE_BYTES = 8        # 64-bit session identifier
COUNTER_SIZE_BYTES = 8           # 64-bit monotonic packet counter

# Packet Header Definition
# Layout: [Magic: 2B] [Version: 1B] [Flags: 1B] [SenderID: 1B] [SessionID: 8B] [Counter: 8B] [Nonce: 16B] [CiphertextLen: 2B]
HEADER_STRUCT_FORMAT = ">2sBBBQQ16sH"
HEADER_SIZE_BYTES = 39           # 2 + 1 + 1 + 1 + 8 + 8 + 16 + 2
MIN_PACKET_SIZE_BYTES = HEADER_SIZE_BYTES + TAG_SIZE_BYTES  # 55 bytes (0 length ciphertext)
MAX_CIPHERTEXT_SIZE_BYTES = 1400 # Fits safely within standard 1500-byte MTU
MAX_PACKET_SIZE_BYTES = HEADER_SIZE_BYTES + MAX_CIPHERTEXT_SIZE_BYTES + TAG_SIZE_BYTES

# Protocol Flags (Bitmask)
FLAG_STANDARD = 0x00
FLAG_HEARTBEAT = 0x01
FLAG_KEY_ROTATION_REQUEST = 0x02
FLAG_DIAGNOSTIC_REPORT = 0x04
FLAG_RECOVERY_SYNC = 0x08

# Sender Identity Policy
SENDER_ID_GCS = 1                # Ground Control Station (Windows Laptop)
SENDER_ID_UAV = 2                # Vehicle Companion Computer (Raspberry Pi 5)
SENDER_ID_AUTOPILOT = 3          # Flight Controller / Pixhawk (Future FPGA)

# Default Network Configuration
DEFAULT_TARGET_IP = "10.41.237.148"
DEFAULT_UDP_PORT = 14550
DEFAULT_LOCAL_BIND_IP = "0.0.0.0"

# Timing Parameters (Seconds)
DEFAULT_HEARTBEAT_INTERVAL_SEC = 1.0
DEFAULT_HEARTBEAT_TIMEOUT_SEC = 3.5
RECOVERY_TIMEOUT_SEC = 2.0
MAX_PERSISTENT_FAULTS_BEFORE_LOCK = 5

# Replay Window Configuration
REPLAY_WINDOW_SIZE = 64

