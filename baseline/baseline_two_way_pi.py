"""
Baseline Two-Way MAVLink UAV Node (Raspberry Pi 5 - Unencrypted).
Listens on UDP 14550, auto-detects PC address, and transmits vehicle telemetry back.
"""
import socket
import time
import threading
from pymavlink.dialects.v20 import common as mavlink2

BIND_PORT = 14550
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", BIND_PORT))

print("=" * 60)
print("  Baseline Unencrypted Two-Way MAVLink Node (Raspberry Pi 5)")
print(f"  Listening on UDP 0.0.0.0:{BIND_PORT}")
print("=" * 60)

mav = mavlink2.MAVLink(None, srcSystem=1, srcComponent=1)
pc_client_addr = None
stop_event = threading.Event()
addr_lock = threading.Lock()


def receive_loop():
    global pc_client_addr
    print("[RX Thread] Waiting for incoming MAVLink packets from Windows PC...")
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(2048)
            with addr_lock:
                if pc_client_addr != addr:
                    pc_client_addr = addr
                    print(f"\n>>> [Auto-Detected PC Address] Telemetry return target set to: {addr[0]}:{addr[1]}\n")

            messages = mav.parse_buffer(data)
            if messages:
                for msg in messages:
                    print(
                        f"  [Pi Received from {addr[0]}] {msg.get_type()} | "
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
        with addr_lock:
            target = pc_client_addr

        if target is not None:
            # Send UAV Heartbeat (SysID: 1, CompID: 1)
            hb = mav.heartbeat_encode(
                mavlink2.MAV_TYPE_QUADROTOR,
                mavlink2.MAV_AUTOPILOT_ARDUPILOTMEGA,
                0,
                0,
                mavlink2.MAV_STATE_ACTIVE
            )
            sock.sendto(hb.pack(mav), target)

            # Send Simulated Attitude Telemetry
            att = mav.attitude_encode(
                0,
                0.02,   # roll
                -0.01,  # pitch
                1.57,   # yaw
                0.0, 0.0, 0.0
            )
            sock.sendto(att.pack(mav), target)

            print(f"[TX #{counter:04d}] Sent UAV Heartbeat + Attitude telemetry -> {target[0]}:{target[1]}")
            counter += 1
        else:
            print("[Waiting for PC] Awaiting initial packet from Windows PC to detect return IP...")

        time.sleep(1.0)
except KeyboardInterrupt:
    print("\nStopping Pi node...")
    stop_event.set()
finally:
    sock.close()

