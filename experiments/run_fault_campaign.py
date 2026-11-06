"""
Automated Security Fault Campaign and Parity Simulation Suite.
Executes comprehensive fault injection across network, framing, replay, crypto, and S-box parity models.
"""
import json
import os
import sys

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
from crypto.parity_model import SecureFlexPermutationModel
from raspberry_pi.fault_localizer import FaultLocalizer, VerificationStage
from raspberry_pi.fault_monitor import FaultCategory
from windows.mavlink_sender import MAVLinkFrameSerializer


def run_sbox_parity_campaign() -> dict:
    """
    Simulates SecureFlex 5-bit S-box fault injection across all 64 slices x 5 bits = 320 single-bit faults.
    """
    total_tests = 0
    detected_faults = 0

    for col in range(64):
        for bit_pos in range(5):
            mask = 1 << bit_pos
            model = SecureFlexPermutationModel(state=[0x1234567890ABCDEF] * 5)
            # Inject single-bit fault into slice col
            result = model.step_round(round_idx=0, inject_sbox_fault={col: mask})
            total_tests += 1
            if not result["sbox_parity_match"]:
                detected_faults += 1

    detection_rate = (detected_faults / total_tests) * 100.0
    return {
        "campaign": "S-Box Parity Prediction Single-Bit Campaign",
        "total_faults_injected": total_tests,
        "detected_faults": detected_faults,
        "detection_rate_pct": detection_rate,
        "expected_detection_rate_pct": 100.0,
    }


def run_linear_invariant_campaign() -> dict:
    """
    Simulates linear-layer word parity invariant checks across all 5 words with single-bit faults.
    """
    total_tests = 0
    detected_faults = 0

    for word_idx in range(5):
        for bit_pos in range(64):
            mask = 1 << bit_pos
            model = SecureFlexPermutationModel(state=[0x0FEDCBA987654321] * 5)
            result = model.step_round(round_idx=0, inject_linear_fault={word_idx: mask})
            total_tests += 1
            if not result["linear_invariant_match"]:
                detected_faults += 1

    detection_rate = (detected_faults / total_tests) * 100.0
    return {
        "campaign": "Linear Layer Word-Parity Invariant Single-Bit Campaign",
        "total_faults_injected": total_tests,
        "detected_faults": detected_faults,
        "detection_rate_pct": detection_rate,
        "expected_detection_rate_pct": 100.0,
    }


def run_network_fault_campaign() -> dict:
    """
    Tests network-layer fault localization and rejection rules.
    """
    key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    serializer = MAVLinkFrameSerializer()
    nonce_mgr = NonceManager()
    replay_window = ReplayProtectionWindow()

    # Create baseline valid datagram
    mav_bytes = serializer.create_heartbeat()
    counter, nonce = nonce_mgr.next_nonce()
    header = PacketHeader(
        magic=MAGIC_BYTES,
        version=PROTOCOL_VERSION,
        flags=FLAG_HEARTBEAT,
        sender_id=SENDER_ID_GCS,
        session_id=nonce_mgr.session_id,
        packet_counter=counter,
        nonce=nonce,
        ciphertext_length=len(mav_bytes),
    )
    aad = header.pack()
    ct, tag = AsconAEAD128.encrypt(key, nonce, aad, mav_bytes)
    valid_datagram = SecurePacket(header=header, ciphertext=ct, tag=tag).serialize()

    test_cases = []

    # Case 1: Valid Packet
    res = FaultLocalizer.inspect_and_verify(valid_datagram, key, replay_window, SENDER_ID_GCS)
    test_cases.append({"name": "Valid Packet", "passed": res.is_valid, "stage": res.stage})
    # Commit counter so subsequent identical packets become replays
    replay_window.commit(header.session_id, counter)

    # Case 2: Replay Packet (identical counter)
    res = FaultLocalizer.inspect_and_verify(valid_datagram, key, replay_window, SENDER_ID_GCS)
    test_cases.append({
        "name": "Replay Duplicate Counter",
        "passed": (not res.is_valid and res.category == FaultCategory.REPLAY_ATTACK),
        "stage": res.stage,
        "category": res.category,
    })

    # Helper to generate fresh datagram for independent crypto tests
    def make_fresh_datagram():
        c, n = nonce_mgr.next_nonce()
        hdr = PacketHeader(
            magic=MAGIC_BYTES,
            version=PROTOCOL_VERSION,
            flags=FLAG_HEARTBEAT,
            sender_id=SENDER_ID_GCS,
            session_id=nonce_mgr.session_id,
            packet_counter=c,
            nonce=n,
            ciphertext_length=len(mav_bytes),
        )
        c_text, t = AsconAEAD128.encrypt(key, n, hdr.pack(), mav_bytes)
        return hdr, SecurePacket(header=hdr, ciphertext=c_text, tag=t).serialize()

    # Case 3: Corrupted Ciphertext Bit (with fresh counter)
    hdr3, fresh_dg3 = make_fresh_datagram()
    corrupted_ct = bytearray(fresh_dg3)
    corrupted_ct[len(hdr3.pack())] ^= 0x01
    res = FaultLocalizer.inspect_and_verify(bytes(corrupted_ct), key, replay_window, SENDER_ID_GCS)
    test_cases.append({
        "name": "Ciphertext Bit Flip",
        "passed": (not res.is_valid and res.category == FaultCategory.AUTHENTICATION_FAILED),
        "stage": res.stage,
        "category": res.category,
    })

    # Case 4: Corrupted Tag Bit (with fresh counter)
    hdr4, fresh_dg4 = make_fresh_datagram()
    corrupted_tag = bytearray(fresh_dg4)
    corrupted_tag[-1] ^= 0x01
    res = FaultLocalizer.inspect_and_verify(bytes(corrupted_tag), key, replay_window, SENDER_ID_GCS)
    test_cases.append({
        "name": "Tag Bit Flip",
        "passed": (not res.is_valid and res.category == FaultCategory.AUTHENTICATION_FAILED),
        "stage": res.stage,
        "category": res.category,
    })

    # Case 5: Truncated Datagram
    res = FaultLocalizer.inspect_and_verify(valid_datagram[:-10], key, replay_window, SENDER_ID_GCS)
    test_cases.append({
        "name": "Truncated Datagram",
        "passed": (not res.is_valid and res.category == FaultCategory.INVALID_FRAMING),
        "stage": res.stage,
        "category": res.category,
    })

    # Case 6: Bad Protocol Version
    bad_ver = bytearray(valid_datagram)
    bad_ver[2] = 99
    res = FaultLocalizer.inspect_and_verify(bytes(bad_ver), key, replay_window, SENDER_ID_GCS)
    test_cases.append({
        "name": "Unsupported Version",
        "passed": (not res.is_valid and res.category == FaultCategory.UNSUPPORTED_VERSION),
        "stage": res.stage,
        "category": res.category,
    })

    # Case 7: Bad Magic Bytes
    bad_magic = bytearray(valid_datagram)
    bad_magic[0] = 0x00
    res = FaultLocalizer.inspect_and_verify(bytes(bad_magic), key, replay_window, SENDER_ID_GCS)
    test_cases.append({
        "name": "Invalid Magic Framing",
        "passed": (not res.is_valid and res.category == FaultCategory.INVALID_FRAMING),
        "stage": res.stage,
        "category": res.category,
    })

    all_passed = all(t["passed"] for t in test_cases)
    return {
        "campaign": "Network Transport Security Validation",
        "all_passed": all_passed,
        "total_test_cases": len(test_cases),
        "passed_cases": sum(1 for t in test_cases if t["passed"]),
        "cases": test_cases,
    }


def main():
    print("=" * 65)
    print("  Running SecureFlex-MAVLink Full Fault Campaign Suite")
    print("=" * 65)

    sbox_res = run_sbox_parity_campaign()
    print(f"[*] S-Box Parity Test: Injected {sbox_res['total_faults_injected']} single-bit faults | Detected: {sbox_res['detected_faults']} ({sbox_res['detection_rate_pct']:.1f}%)")

    linear_res = run_linear_invariant_campaign()
    print(f"[*] Linear Invariant Test: Injected {linear_res['total_faults_injected']} single-bit faults | Detected: {linear_res['detected_faults']} ({linear_res['detection_rate_pct']:.1f}%)")

    net_res = run_network_fault_campaign()
    print(f"[*] Network Transport Test: {net_res['passed_cases']}/{net_res['total_test_cases']} attack scenarios successfully trapped and rejected!")

    out_dir = os.path.join(CURRENT_DIR, "results")
    os.makedirs(out_dir, exist_ok=True)
    report_file = os.path.join(out_dir, "fault_campaign_report.json")

    full_report = {
        "sbox_parity": sbox_res,
        "linear_invariant": linear_res,
        "network_faults": net_res,
    }

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"\n[+] Full campaign report written to: {report_file}")
    print("=" * 65)


if __name__ == "__main__":
    main()
