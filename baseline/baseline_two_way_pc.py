"""
Baseline Two-Way MAVLink GCS Node (Windows PC - Unencrypted).
Transmits GCS heartbeats to Raspberry Pi and receives UAV telemetry back.
"""
import socket
import time
import threading
from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mavlink2

PI_IP = "10.41.237.148"
PORT = 14550

print("=" * 60)
print("  Baseline Unencrypted Two-Way MAVLink Node (Windows PC)")
print(f"  Target Pi: {PI_IP}:{PORT} | Local Bind: 0.0.0.0:{PORT}")
print("=" * 60)

# Create single UDP socket bound to local port 14550 for two-way send & receive
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind(("0.0.0.0", PORT))
except Exception as e:
    print(f"[Warning] Could not bind 0.0.0.0:{PORT} ({e}). Falling back to ephemeral port.")

mav = mavlink2.MAVLink(None, srcSystem=255, srcComponent=190)
stop_event = threading.Event()


def receive_loop():
    print("[RX Thread] Listening for incoming telemetry from Raspberry Pi...")
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(2048)
            messages = mav.parse_buffer(data)
            if messages:
                for msg in messages:
                    print(
                        f"  [PC Received from {addr[0]}] {msg.get_type()} | "
                        f"SysID: {msg.get_srcSystem()} | CompID: {msg.get_srcComponent()}"
                    )
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[RX Error] {e}")


rx_thread = threading.Thread(target=receive_loop, daemon=True)
rx_thread.start()

try:
    counter = 1
    while True:
        # Send GCS Heartbeat
        hb_msg = mav.heartbeat_encode(
            mavlink2.MAV_TYPE_GCS,
            mavlink2.MAV_AUTOPILOT_INVALID,
            0,
            0,
            mavlink2.MAV_STATE_ACTIVE
        )
        data = hb_msg.pack(mav)
        sock.sendto(data, (PI_IP, PORT))
        print(f"[TX #{counter:04d}] Transmitted GCS Heartbeat to {PI_IP}:{PORT}")
        counter += 1
        time.sleep(1.0)
except KeyboardInterrupt:
    print("\nStopping PC node...")
    stop_event.set()
finally:
    sock.close()

