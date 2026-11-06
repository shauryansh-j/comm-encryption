# SecureFlex-MAVLink: Authenticated Lightweight Encryption for Unmanned Systems

A production-grade implementation of secure MAVLink telemetry transport inspired by the **SecureFlex-ASCON** hardware architecture, standardized using **NIST SP 800-232 Ascon-AEAD128**.

Designed for pairing between a **Windows Laptop (Ground Control Station)** and a **Raspberry Pi 5 (Companion Computer / Autopilot Gateway)** over Wi-Fi/UDP.

---

## 1. System Architecture

```text
+-------------------------------------------------------------------------+
|                        WINDOWS GCS TRANSMITTER                          |
|                                                                         |
|  [pymavlink Frame] -> [Nonce Manager] -> [Header (AAD)]                 |
|                                                  |                      |
|                                      [Ascon-AEAD128 Encrypt]            |
|                                                  |                      |
|                                      [Secure Binary Datagram]           |
+--------------------------------------------------+----------------------+
                                                   |
                                                   | UDP Datagram (Port 14550)
                                                   v
+--------------------------------------------------+----------------------+
|                       RASPBERRY PI 5 RECEIVER                           |
|                                                                         |
|  [UDP Socket Ingest]                                                    |
|           |                                                             |
|  [Stage 1-4: Header & Length Check] ---- (Failure) ---> [Fault Monitor] |
|           |                                                    |        |
|  [Stage 5: Anti-Replay Pre-Check] ------ (Failure) ---> [Recovery FSM]  |
|           |                                                    |        |
|  [Stage 6: Ascon-AEAD128 Verify] ------- (Failure) ---> [ISOLATION GATE]|
|           |                                                             |
|       (Success)                                                         |
|           |                                                             |
|  [Post-Auth Replay Commit]                                              |
|           |                                                             |
|  [Feed Plaintext to pymavlink Decoder] -> Decoded Telemetry / Downstream|
+-------------------------------------------------------------------------+
```

---

## 2. Key Features

- **NIST SP 800-232 Ascon-AEAD128 Authenticated Encryption**: Evaluated against 36 official NIST Known-Answer Test (KAT) vectors.
- **Strict Invariant Isolation**: Plaintext is **never** provided to `pymavlink` unless Ascon authentication succeeds with 100% integrity.
- **Defense-in-Depth Framing**: Header authenticated as Associated Data (AAD), sealing sender identity, session ID, counter, and length.
- **Sliding-Window Replay Protection**: RFC 6479-style 64-packet bitmap window with two-phase check/commit.
- **Monotonic Nonce Management**: $2^{64}$ unique session space combined with 64-bit monotonic packet counters.
- **Fault Detection & Localization**: Stage-by-stage trapping of framing, version, sender policy, replay, and crypto tag violations.
- **8-State Recovery FSM**: `IDLE` -> `RUN` -> `SUSPECT` -> `HALT` -> `RECOVER` -> `WAIT` -> `RECOVERED` -> `LOCK`.
- **Software Parity Model**: Simulates SecureFlex S-box parity predictors (320/320 single-bit faults trapped) and linear layer rotation invariants.

---

## 3. Directory Layout

```text
comm encrypt/
├── baseline/                  # Original working unencrypted transmitter & receiver
│   ├── baseline_transmitter.py
│   └── baseline_receiver.py
├── common/                    # Protocol framing, nonce manager, replay window
│   ├── protocol_constants.py
│   ├── packet_format.py
│   ├── nonce_manager.py
│   └── replay_window.py
├── crypto/                    # NIST SP 800-232 Ascon-AEAD128 & Parity Model
│   ├── ascon_nist.py
│   ├── ascon_adapter.py
│   ├── parity_model.py
│   └── known_answer_tests/
├── windows/                   # Windows GCS MAVLink serializer & secure transmitter
│   ├── mavlink_sender.py
│   └── secure_transmitter.py
├── raspberry_pi/              # Raspberry Pi 5 secure receiver, monitor, FSM
│   ├── secure_receiver.py
│   ├── mavlink_decoder.py
│   ├── fault_monitor.py
│   ├── fault_localizer.py
│   ├── recovery_fsm.py
│   └── service/
├── tests/                     # Automated pytest test suite (54 tests)
├── experiments/               # Fault injection & performance evaluation tools
│   ├── fault_injector.py
│   ├── run_fault_campaign.py
│   └── run_performance.py
├── config/                    # Configuration and key provisioning
│   ├── config.toml
│   └── key_generator.py
└── SecureFlex_MAVLink_Plan_Guide.pdf  # Comprehensive technical plan guide PDF
```

---

## 4. Quick Start Guide

### Step 1: Provision Symmetric Key
```bash
python config/key_generator.py -o config/secret.key
```
Copy `config/secret.key` to Raspberry Pi 5 (`~/SecureFlex-MAVLink/config/secret.key`) via SCP and run `chmod 600 config/secret.key`.

### Step 2: Start Secure Receiver on Raspberry Pi 5
```bash
python raspberry_pi/secure_receiver.py --bind-ip 0.0.0.0 --port 14550 --key-file config/secret.key
```

### Step 3: Start Secure Transmitter on Windows Laptop
```powershell
python windows/secure_transmitter.py --target-ip 10.41.237.148 --port 14550 --key-file config/secret.key --rate 1.0
```

### Step 4: Run Automated Tests & Fault Campaign
```powershell
# Run full test suite
pytest tests

# Run security fault campaign (S-box parity, replay, network tampering)
python experiments/run_fault_campaign.py

# Run cryptographic performance benchmark
python experiments/run_performance.py
```

