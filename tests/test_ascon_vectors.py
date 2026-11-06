"""
Test Suite: NIST SP 800-232 Known-Answer Tests (KAT) for Ascon-AEAD128.
"""
import json
import os
import pytest
from crypto.ascon_adapter import AsconAEAD128

KAT_FILE = os.path.join(os.path.dirname(__file__), "..", "crypto", "known_answer_tests", "test_vectors.json")


def load_vectors():
    with open(KAT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("vec", load_vectors())
def test_nist_sp800_232_known_answer(vec):
    key = bytes.fromhex(vec["key_hex"])
    nonce = bytes.fromhex(vec["nonce_hex"])
    pt = bytes.fromhex(vec["pt_hex"])
    ad = bytes.fromhex(vec["ad_hex"])
    expected_ct = bytes.fromhex(vec["ct_hex"])
    expected_tag = bytes.fromhex(vec["tag_hex"])

    # Test Encryption
    computed_ct, computed_tag = AsconAEAD128.encrypt(key, nonce, ad, pt)
    assert computed_ct == expected_ct, f"Ciphertext mismatch in KAT #{vec['count']}"
    assert computed_tag == expected_tag, f"Tag mismatch in KAT #{vec['count']}"

    # Test Decryption
    decrypted_pt = AsconAEAD128.decrypt(key, nonce, ad, computed_ct, computed_tag)
    assert decrypted_pt == pt, f"Decryption plaintext mismatch in KAT #{vec['count']}"

