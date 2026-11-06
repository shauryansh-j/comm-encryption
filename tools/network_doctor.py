"""
Network Connectivity & Port Diagnostic Doctor for SecureFlex-MAVLink.
Diagnoses IP reachability, UDP 14550 socket connectivity, Windows Firewall status,
and Wi-Fi client isolation issues between Windows PC and Raspberry Pi 5.
"""
import argparse
import os
import platform
import socket
import subprocess
import sys
import time

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DEFAULT_PORT = 14550


def get_local_ip_addresses() -> list:
    """Finds all non-loopback local IPv4 addresses."""
    ip_list = []
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ip_list.append(ip)
    except Exception:
        pass

    # Fallback using dummy UDP connect
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip not in ip_list:
            ip_list.append(ip)
    except Exception:
        pass
    return ip_list


def ping_host(host: str, timeout_sec: float = 1.5) -> bool:
    """Sends ICMP ping to verify basic layer 3 network reachability."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val = str(int(timeout_sec * 1000)) if platform.system().lower() == "windows" else str(int(timeout_sec))

    cmd = ["ping", param, "1", timeout_param, timeout_val, host]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def test_udp_bind(port: int) -> bool:
    """Checks whether local UDP port can be bound."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        s.close()
        return True
    except OSError:
        return False


def run_udp_echo_server(port: int = DEFAULT_PORT):
    """Runs a temporary UDP echo server to verify packet reception from remote peer."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    print(f"\n[Echo Server] Listening on UDP 0.0.0.0:{port}...")
    print("Waiting for probe packets from remote node (Press Ctrl+C to stop)...")
    try:
        while True:
            data, addr = s.recvfrom(2048)
            print(f"[Echo Server] Received {len(data)} bytes from {addr[0]}:{addr[1]} -> '{data.decode('utf-8', errors='ignore')}'")
            s.sendto(b"ECHO_ACK:" + data, addr)
            print(f"[Echo Server] Sent ACK back to {addr[0]}:{addr[1]}")
    except KeyboardInterrupt:
        print("\nStopping Echo Server.")
    finally:
        s.close()


def run_udp_probe(target_ip: str, port: int = DEFAULT_PORT, timeout_sec: float = 2.0) -> bool:
    """Sends a test probe datagram and waits for echo ACK."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout_sec)
    msg = f"SECUREFLEX_PROBE_{int(time.time())}".encode("utf-8")
    print(f"[Probe] Sending UDP probe to {target_ip}:{port}...")
    try:
        s.sendto(msg, (target_ip, port))
        ack, addr = s.recvfrom(2048)
        print(f"[Probe SUCCESS] Received reply from {addr[0]}:{addr[1]} -> '{ack.decode('utf-8', errors='ignore')}'")
        s.close()
        return True
    except socket.timeout:
        print(f"[Probe TIMEOUT] No reply received from {target_ip}:{port} within {timeout_sec}s.")
        s.close()
        return False
    except Exception as e:
        print(f"[Probe ERROR] {e}")
        s.close()
        return False


def check_windows_firewall_rule():
    """Checks if Windows Defender Firewall has an inbound rule for UDP 14550."""
    if platform.system().lower() != "windows":
        return None
    try:
        cmd = [
            "powershell",
            "-Command",
            "Get-NetFirewallRule -DisplayName '*MAVLink*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return len(res.stdout.strip()) > 0
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="SecureFlex Network Connectivity & Firewall Doctor")
    parser.add_argument("--remote-ip", default="10.41.237.148", help="Remote host IP to test (e.g. Raspberry Pi IP)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="MAVLink UDP port (default: 14550)")
    parser.add_argument("--listen-server", action="store_true", help="Run UDP echo server on this node to test inbound traffic")
    parser.add_argument("--probe-remote", action="store_true", help="Send UDP echo probe to remote node")
    args = parser.parse_args()

    print("=" * 68)
    print("  SecureFlex-MAVLink Network Connectivity Doctor")
    print("=" * 68)

    local_ips = get_local_ip_addresses()
    print(f"[*] Local Hostname: {socket.gethostname()}")
    print(f"[*] Local IP Address(es): {', '.join(local_ips) if local_ips else '127.0.0.1'}")
    print(f"[*] Operating System: {platform.system()} {platform.release()}")

    # 1. Check local port binding
    port_available = test_udp_bind(args.port)
    if port_available:
        print(f"[+] UDP Port {args.port}: AVAILABLE for local binding")
    else:
        print(f"[-] UDP Port {args.port}: OCCUPIED by another process (e.g. QGroundControl or existing instance)")

    # 2. Check Windows Firewall
    if platform.system().lower() == "windows":
        has_rule = check_windows_firewall_rule()
        if has_rule:
            print("[+] Windows Firewall: MAVLink inbound UDP rule is CONFIGURED")
        else:
            print("[!] Windows Firewall Warning: No inbound rule found for MAVLink UDP 14550.")
            print("    Run this in PowerShell as Administrator:")
            print("    New-NetFirewallRule -DisplayName 'MAVLink UDP 14550' -Direction Inbound -Protocol UDP -LocalPort 14550 -Action Allow")

    # 3. Echo Server Mode
    if args.listen_server:
        run_udp_echo_server(args.port)
        return

    # 4. Probe Remote Mode
    if args.probe_remote:
        run_udp_probe(args.remote_ip, args.port)
        return

    # 5. Default Reachability Diagnostics
    print(f"\n[*] Testing Reachability to Remote Target: {args.remote_ip}...")
    ping_ok = ping_host(args.remote_ip)
    if ping_ok:
        print(f"[+] ICMP Ping to {args.remote_ip}: SUCCESSFUL (Layer 3 connected)")
    else:
        print(f"[-] ICMP Ping to {args.remote_ip}: FAILED (Host unreachable or ICMP blocked)")
        print("    Troubleshooting steps:")
        print("    1. Confirm both devices are connected to the SAME Wi-Fi network/hotspot.")
        print(f"    2. On Raspberry Pi, run 'hostname -I' to check its current IP.")
        print(f"    3. On Windows, run 'ipconfig' to check Wi-Fi subnet.")
        print("    4. If using a college/corporate network, Wi-Fi client isolation may block peer-to-peer packets.")
        print("       Solution: Connect both devices to a mobile phone hotspot or direct Ethernet cable.")

    print("\n" + "=" * 68)
    print("  Diagnostic Recommendations:")
    print(f"  - To test incoming packet reception on this node: python tools/network_doctor.py --listen-server")
    print(f"  - To send a probe to the other node: python tools/network_doctor.py --remote-ip {args.remote_ip} --probe-remote")
    print("=" * 68)


if __name__ == "__main__":
    main()
