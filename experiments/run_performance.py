"""
Performance Evaluation and Benchmark Suite for SecureFlex-MAVLink.
Measures encryption latency, verification latency, throughput, and packet framing overhead.
"""
import json
import os
import statistics
import sys
import time

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.protocol_constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    FLAG_HEARTBEAT,
    SENDER_ID_GCS,
)
from common.packet_format import PacketHeader, SecurePacket
from common.nonce_manager import NonceManager
from common.replay_window import ReplayProtectionWindow
from crypto.ascon_adapter import AsconAEAD128
from windows.mavlink_sender import MAVLinkFrameSerializer
from raspberry_pi.fault_localizer import FaultLocalizer


def run_benchmark(num_iterations: int = 1000) -> dict:
    key = b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00"
    serializer = MAVLinkFrameSerializer()
    nonce_mgr = NonceManager()
    replay_window = ReplayProtectionWindow(window_size=2048)

    # Pre-generate MAVLink heartbeat frame
    mav_bytes = serializer.create_heartbeat()
    mav_len = len(mav_bytes)

    enc_latencies_us = []
    dec_latencies_us = []
    total_pipeline_us = []

    for _ in range(num_iterations):
        # 1. Measure Encryption Phase
        c, n = nonce_mgr.next_nonce()
        header = PacketHeader(
            magic=MAGIC_BYTES,
            version=PROTOCOL_VERSION,
            flags=FLAG_HEARTBEAT,
            sender_id=SENDER_ID_GCS,
            session_id=nonce_mgr.session_id,
            packet_counter=c,
            nonce=n,
            ciphertext_length=mav_len,
        )
        aad = header.pack()

        t0 = time.perf_counter_ns()
        ct, tag = AsconAEAD128.encrypt(key, n, aad, mav_bytes)
        t1 = time.perf_counter_ns()

        packet = SecurePacket(header=header, ciphertext=ct, tag=tag)
        datagram = packet.serialize()
        t2 = time.perf_counter_ns()

        # 2. Measure Decryption and Verification Phase
        res = FaultLocalizer.inspect_and_verify(datagram, key, replay_window, SENDER_ID_GCS)
        t3 = time.perf_counter_ns()

        assert res.is_valid and res.plaintext == mav_bytes
        replay_window.commit(header.session_id, c)

        enc_latencies_us.append((t1 - t0) / 1000.0)
        dec_latencies_us.append((t3 - t2) / 1000.0)
        total_pipeline_us.append((t3 - t0) / 1000.0)

    datagram_len = len(datagram)
    overhead_bytes = datagram_len - mav_len
    overhead_pct = (overhead_bytes / mav_len) * 100.0

    avg_enc_us = statistics.mean(enc_latencies_us)
    p50_enc_us = statistics.median(enc_latencies_us)
    p95_enc_us = statistics.quantiles(enc_latencies_us, n=20)[18]

    avg_dec_us = statistics.mean(dec_latencies_us)
    p50_dec_us = statistics.median(dec_latencies_us)
    p95_dec_us = statistics.quantiles(dec_latencies_us, n=20)[18]

    avg_total_us = statistics.mean(total_pipeline_us)
    throughput_msgs_per_sec = 1_000_000.0 / avg_total_us

    results = {
        "benchmark_iterations": num_iterations,
        "payload_size_bytes": mav_len,
        "datagram_size_bytes": datagram_len,
        "framing_overhead_bytes": overhead_bytes,
        "overhead_percent": overhead_pct,
        "encryption_latency_us": {
            "mean": round(avg_enc_us, 2),
            "median": round(p50_enc_us, 2),
            "p95": round(p95_enc_us, 2),
            "min": round(min(enc_latencies_us), 2),
            "max": round(max(enc_latencies_us), 2),
        },
        "decryption_verification_latency_us": {
            "mean": round(avg_dec_us, 2),
            "median": round(p50_dec_us, 2),
            "p95": round(p95_dec_us, 2),
            "min": round(min(dec_latencies_us), 2),
            "max": round(max(dec_latencies_us), 2),
        },
        "total_cryptographic_pipeline_us": {
            "mean": round(avg_total_us, 2),
            "throughput_messages_per_second": round(throughput_msgs_per_sec, 1),
        },
    }

    out_dir = os.path.join(CURRENT_DIR, "results")
    os.makedirs(out_dir, exist_ok=True)
    report_file = os.path.join(out_dir, "performance_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


def main():
    print("=" * 65)
    print("  Running SecureFlex-MAVLink Performance Benchmark")
    print("  Measuring Ascon-AEAD128 (NIST SP 800-232) Latency & Overhead")
    print("=" * 65)

    res = run_benchmark(num_iterations=1000)

    print(f"[*] Payload Size: {res['payload_size_bytes']} bytes (MAVLink Heartbeat)")
    print(f"[*] Datagram Size: {res['datagram_size_bytes']} bytes")
    print(f"[*] Secure Overhead: {res['framing_overhead_bytes']} bytes ({res['overhead_percent']:.1f}%)")
    print(f"[*] Encryption Latency (Mean): {res['encryption_latency_us']['mean']} us (p95: {res['encryption_latency_us']['p95']} us)")
    print(f"[*] Decryption & Verify Latency (Mean): {res['decryption_verification_latency_us']['mean']} us (p95: {res['decryption_verification_latency_us']['p95']} us)")
    print(f"[*] Total Crypto Overhead: {res['total_cryptographic_pipeline_us']['mean']} us per frame")
    print(f"[*] Cryptographic Processing Rate: {res['total_cryptographic_pipeline_us']['throughput_messages_per_second']} messages/sec")
    print("=" * 65)


if __name__ == "__main__":
    main()

