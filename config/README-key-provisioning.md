# SecureFlex-MAVLink: Key Provisioning & Management Guide

## 1. Overview
SecureFlex utilizes **NIST SP 800-232 Ascon-AEAD128** authenticated encryption. The cipher requires a **128-bit (16-byte)** symmetric secret key shared between the Ground Control Station (Windows laptop) and the companion computer (Raspberry Pi 5).

## 2. Key Generation (Out-of-Band)
Keys must **never** be transmitted over unencrypted Wi-Fi or UDP. Generate the key securely on the host using the provided Python CSPRNG tool:

```powershell
python config/key_generator.py -o config/secret.key
```

This generates a 32-character hexadecimal key (16 raw bytes) using Python's `secrets` module (Cryptographically Secure Pseudo-Random Number Generator).

## 3. Secure Out-of-Band Provisioning to Raspberry Pi 5
Transfer the key file directly to the Raspberry Pi 5 over an encrypted channel such as `scp` or via an offline USB drive:

```bash
# From Windows laptop (via SCP)
scp config/secret.key pi@10.41.237.148:~/SecureFlex-MAVLink/config/secret.key
```

On the Raspberry Pi 5, enforce POSIX file permission restriction so only the current user/service can read the key:

```bash
chmod 600 ~/SecureFlex-MAVLink/config/secret.key
```

## 4. Key Rotation Procedure
1. Generate a new key: `python config/key_generator.py -o config/secret_v2.key`
2. Coordinate maintenance window or update key config on both sender and receiver.
3. Restart both services with the new key path.
4. If a key compromise is suspected, immediately initiate the **LOCK** state and re-provision out-of-band.

