"""
Secure Cryptographic Key Generator for SecureFlex-MAVLink.
Generates 128-bit (16-byte) CSPRNG keys for NIST SP 800-232 Ascon-AEAD128.
"""
import argparse
import os
import secrets


def generate_key_file(output_path: str = "secret.key") -> str:
    """Generates a random 16-byte key and writes hex representation to a secure file."""
    key = secrets.token_bytes(16)
    key_hex = key.hex()

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(key_hex + "\n")

    # On POSIX systems, set strict permissions 0600 (readable only by owner)
    if os.name != "nt":
        try:
            os.chmod(output_path, 0o600)
        except OSError:
            pass

    print(f"[KeyGenerator] Generated 128-bit Ascon key: {key_hex}")
    print(f"[KeyGenerator] Saved to: {os.path.abspath(output_path)}")
    return key_hex


def load_key_from_file(path: str) -> bytes:
    """Loads 16-byte key from a text file containing 32 hex characters or raw bytes."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Key file not found at: {path}")

    with open(path, "rb") as f:
        content = f.read().strip()

    if len(content) == 16:
        return content
    elif len(content) == 32:
        return bytes.fromhex(content.decode("ascii"))
    else:
        # Try decoding string
        text = content.decode("utf-8").strip()
        return bytes.fromhex(text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureFlex Key Provisioning Utility")
    parser.add_argument("-o", "--output", default="secret.key", help="Output key file path")
    args = parser.parse_args()
    generate_key_file(args.output)

