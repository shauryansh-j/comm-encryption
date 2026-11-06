"""
Test Suite: Cryptographic Tampering and Negative Authentication Tests.
Confirms that Ascon-AEAD128 rejects all corrupted ciphertext, tag, AAD, and wrong keys.
"""
from crypto.ascon_adapter import AsconAEAD128


def test_tampered_ciphertext_bit_fails():
    key = b"\x00" * 16
    nonce = b"\x01" * 16
    aad = b"authenticated_header"
    pt = b"MAVLink Heartbeat Plaintext"

    ct, tag = AsconAEAD128.encrypt(key, nonce, aad, pt)

    # Flip bit 0 of ciphertext
    corrupted_ct = bytearray(ct)
    corrupted_ct[0] ^= 0x01

    recovered = AsconAEAD128.decrypt(key, nonce, aad, bytes(corrupted_ct), tag)
    assert recovered is None, "Tampered ciphertext MUST fail verification and return None!"


def test_tampered_tag_bit_fails():
    key = b"\x00" * 16
    nonce = b"\x01" * 16
    aad = b"authenticated_header"
    pt = b"MAVLink Heartbeat Plaintext"

    ct, tag = AsconAEAD128.encrypt(key, nonce, aad, pt)

    # Flip bit 0 of authentication tag
    corrupted_tag = bytearray(tag)
    corrupted_tag[0] ^= 0x01

    recovered = AsconAEAD128.decrypt(key, nonce, aad, ct, bytes(corrupted_tag))
    assert recovered is None, "Tampered tag MUST fail verification and return None!"


def test_tampered_aad_fails():
    key = b"\x00" * 16
    nonce = b"\x01" * 16
    aad = b"authenticated_header"
    pt = b"MAVLink Heartbeat Plaintext"

    ct, tag = AsconAEAD128.encrypt(key, nonce, aad, pt)

    # Modify AAD
    tampered_aad = b"tampered_header____"

    recovered = AsconAEAD128.decrypt(key, nonce, tampered_aad, ct, tag)
    assert recovered is None, "Tampered AAD MUST fail verification and return None!"


def test_wrong_key_fails():
    key_alice = b"\x00" * 16
    key_bob = b"\x01" * 16
    nonce = b"\x02" * 16
    aad = b"header"
    pt = b"secret message"

    ct, tag = AsconAEAD128.encrypt(key_alice, nonce, aad, pt)

    recovered = AsconAEAD128.decrypt(key_bob, nonce, aad, ct, tag)
    assert recovered is None, "Wrong key MUST fail verification and return None!"

