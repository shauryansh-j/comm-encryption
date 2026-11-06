"""
Baseline MAVLink Transmitter (Unencrypted / Legacy).
SIVIA MAVLink Transmitter sending heartbeats over UDP to Raspberry Pi 5.
"""
import time
from pymavlink import mavutil

PI_IP = "10.41.237.148"
PI_PORT = 14550

print("SIVIA MAVLink Transmitter Started")

connection = mavutil.mavlink_connection(
    f"udpout:{PI_IP}:{PI_PORT}",
    source_system=255,
    source_component=190
)

print(f"Sending MAVLink heartbeat to {PI_IP}:{PI_PORT}")

try:
    while True:
        connection.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS,
            mavutil.mavlink.MAV_AUTOPILOT_INVALID,
            0,
            0,
            mavutil.mavlink.MAV_STATE_ACTIVE
        )
        print("Heartbeat transmitted")
        time.sleep(1)
except KeyboardInterrupt:
    print("\nTransmitter stopped by user.")

