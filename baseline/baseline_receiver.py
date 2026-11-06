"""
Baseline MAVLink Receiver (Unencrypted / Legacy).
SIVIA MAVLink Receiver listening on UDP 14550.
"""
from pymavlink import mavutil

connection = mavutil.mavlink_connection(
    'udpin:0.0.0.0:14550'
)

print("SIVIA MAVLink Receiver Started")
print("Listening on UDP port 14550...")
print("Waiting for incoming MAVLink messages...")

try:
    while True:
        message = connection.recv_match(blocking=True)

        if message is None:
            continue

        print(
            f"Received: {message.get_type()} | "
            f"System ID: {message.get_srcSystem()} | "
            f"Component ID: {message.get_srcComponent()}"
        )
except KeyboardInterrupt:
    print("\nReceiver stopped by user.")

