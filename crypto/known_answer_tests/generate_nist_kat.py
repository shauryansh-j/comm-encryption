"""
NIST SP 800-232 Known-Answer Test (KAT) Generator and Validator.
Produces reproducible test vectors according to NIST Cryptographic Algorithm Validation Program formats.
"""
import json
import os
import sys

# Ensure project root is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from crypto.ascon_adapter import AsconAEAD128


def generate_kat_bytes(length: int) -> bytes:
    """Standard NIST deterministic pattern: byte[i] = i % 256."""
    return bytes([i % 256 for i in range(length)])


def generate_and_save_kat_vectors(filepath: str = None) -> list:
    """Generates standard NIST KAT vectors for Ascon-AEAD128."""
    if filepath is None:
        filepath = os.path.join(CURRENT_DIR, "test_vectors.json")

    key = generate_kat_bytes(16)
    nonce = generate_kat_bytes(16)

    # Standard lengths: 0, 1, 8, 16, 21, 32 bytes
    lengths = [0, 1, 8, 16, 21, 32]
    vectors = []
    count = 1

    for mlen in lengths:
        for adlen in lengths:
            pt = generate_kat_bytes(mlen)
            ad = generate_kat_bytes(adlen)

            ct, tag = AsconAEAD128.encrypt(key, nonce, ad, pt)
            decrypted = AsconAEAD128.decrypt(key, nonce, ad, ct, tag)
            assert decrypted == pt, f"Decryption failure in vector {count}"

            vectors.append({
                "count": count,
                "key_hex": key.hex(),
                "nonce_hex": nonce.hex(),
                "pt_len": mlen,
                "pt_hex": pt.hex(),
                "ad_len": adlen,
                "ad_hex": ad.hex(),
                "ct_hex": ct.hex(),
                "tag_hex": tag.hex(),
            })
            count += 1

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2)

    print(f"Generated {len(vectors)} NIST SP 800-232 KAT vectors to {filepath}")
    return vectors


if __name__ == "__main__":
    generate_and_save_kat_vectors()

