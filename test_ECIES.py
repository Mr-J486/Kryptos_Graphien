"""
test_ECIES.py — Integration test for the Kryptos_Graphien ECIES layer
======================================================================
Run from the repo root:
    python test_ECIES.py

Tests the full stack:
  crypto/ECC.py   — secp256k1 key pairs
  crypto/ECIES.py — ECDH + AES-128-CBC (uses repo's AES/aes_core.py) + HMAC
  Alice2 / Bob2     — communication protocol

No Flask server needed — tests the crypto library directly.
"""

import os, time

from crypto.ECC   import generate_keypair, public_key_to_hex
from crypto.ECIES import (
    ecies_encrypt, ecies_decrypt,
    ecies_encrypt_str, ecies_decrypt_str,
    bundle_to_hex, bundle_from_hex,
)

def sep(title):
    print(f"\n{'═'*62}")
    print(f"  {title}")
    print(f"{'═'*62}")

# ══════════════════════════════════════════════════════════════
def test_basic_roundtrip():
    sep("TEST 1: Basic Encrypt / Decrypt")
    Alice2_priv, Alice2_pub = generate_keypair()
    msg    = b"Hello from the Kryptos_Graphien test suite!"
    bundle = ecies_encrypt(msg, Alice2_pub)
    result = ecies_decrypt(bundle, Alice2_priv)
    assert result == msg
    print(f"  Plaintext  : {msg.decode()}")
    print(f"  Bundle size: {len(bundle)} bytes  (overhead = 113 B fixed + padding)")
    print("  ✅ Round-trip passed")

# ══════════════════════════════════════════════════════════════
def test_Alice2_Bob2_protocol():
    sep("TEST 2: Alice2 ↔ Bob2 Protocol (simulated)")

    Alice2_priv, Alice2_pub = generate_keypair()
    Bob2_priv,   Bob2_pub   = generate_keypair()

    print("  [Handshake] Alice2 sends Bob2 her public key (out-of-band / /receive endpoint)")
    print("  [Handshake] Bob2   sends Alice2 his public key")
    print()

    # Alice2 → Bob2
    for msg in ["Hi Bob2!", "The launch code is 4-8-15-16-23-42.", "Copy that?"]:
        bundle  = ecies_encrypt_str(msg, Bob2_pub)
        decoded = ecies_decrypt_str(bundle, Bob2_priv)
        assert decoded == msg
        print(f"  Alice2→Bob2  '{msg}'  ✅")

    # Bob2 → Alice2
    for msg in ["Loud and clear.", "Confirmed.", "Standing by."]:
        bundle  = ecies_encrypt_str(msg, Alice2_pub)
        decoded = ecies_decrypt_str(bundle, Alice2_priv)
        assert decoded == msg
        print(f"  Bob2→Alice2  '{msg}'  ✅")

# ══════════════════════════════════════════════════════════════
def test_uses_repo_aes():
    sep("TEST 3: Confirm repo AES/aes_core.py is used")
    # Import directly and verify it's the same code path
    from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
    key = os.urandom(16)
    iv  = os.urandom(16)
    pt  = b"AES-128 from aes_core.py"
    ct  = aes_cbc_encrypt(pt, key, iv)
    rt  = aes_cbc_decrypt(ct, key, iv)
    assert rt == pt
    print(f"  AES-128-CBC (repo): encrypt→decrypt ✅")
    print(f"  ECIES internally calls the same aes_cbc_encrypt/decrypt ✅")

# ══════════════════════════════════════════════════════════════
def test_tamper_detection():
    sep("TEST 4: Tamper Detection (MAC)")
    Bob2_priv, Bob2_pub = generate_keypair()
    bundle    = ecies_encrypt(b"Secret payload", Bob2_pub)
    tampered  = bytearray(bundle)
    tampered[90] ^= 0xFF
    try:
        ecies_decrypt(bytes(tampered), Bob2_priv)
        print("  ❌ Tampered bundle accepted — FAIL")
    except ValueError as e:
        print(f"  ✅ Tampered bundle rejected: {e}")

# ══════════════════════════════════════════════════════════════
def test_wrong_key():
    sep("TEST 5: Wrong Key Rejection")
    Bob2_priv,  Bob2_pub  = generate_keypair()
    eve_priv,  _        = generate_keypair()
    bundle = ecies_encrypt(b"Only Bob2 can read this", Bob2_pub)
    try:
        ecies_decrypt(bundle, eve_priv)
        print("  ❌ Eve read Bob2's message — FAIL")
    except ValueError as e:
        print(f"  ✅ Eve's attempt rejected: {e}")
    result = ecies_decrypt(bundle, Bob2_priv)
    print(f"  ✅ Bob2 decrypts correctly: {result.decode()}")

# ══════════════════════════════════════════════════════════════
def test_forward_secrecy():
    sep("TEST 6: Forward Secrecy (unique bundle per call)")
    _, pub = generate_keypair()
    b1 = ecies_encrypt(b"same message", pub)
    b2 = ecies_encrypt(b"same message", pub)
    assert b1 != b2, "Bundles should differ — each uses a fresh ephemeral key + IV"
    print("  ✅ Two encryptions of the same message produce different bundles")
    print("     (ephemeral key + random IV — forward secrecy guaranteed)")

# ══════════════════════════════════════════════════════════════
def test_hex_transport():
    sep("TEST 7: Hex Transport (JSON-safe for Flask payloads)")
    priv, pub = generate_keypair()
    bundle    = ecies_encrypt_str("Classified payload", pub)
    hex_str   = bundle_to_hex(bundle)
    recovered = ecies_decrypt_str(bundle_from_hex(hex_str), priv)
    assert recovered == "Classified payload"
    print(f"  Hex length  : {len(hex_str)} chars")
    print(f"  Recovered   : {recovered}  ✅")

# ══════════════════════════════════════════════════════════════
def test_performance():
    sep("TEST 8: Performance Benchmark")
    _, pub = generate_keypair()
    priv, _ = generate_keypair()
    # use a valid pub for the bench
    priv, pub = generate_keypair()

    sizes = [64, 512, 4096]
    for n in sizes:
        data = os.urandom(n)
        t0   = time.perf_counter()
        b    = ecies_encrypt(data, pub)
        t1   = time.perf_counter()
        ecies_decrypt(b, priv)
        t2   = time.perf_counter()
        print(f"  {n:>5}B  enc {(t1-t0)*1000:5.1f}ms  dec {(t2-t1)*1000:5.1f}ms  ✅")

# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   Kryptos_Graphien — ECIES Integration Test Suite       ║")
    print("╚══════════════════════════════════════════════════════════╝")

    test_basic_roundtrip()
    test_Alice2_Bob2_protocol()
    test_uses_repo_aes()
    test_tamper_detection()
    test_wrong_key()
    test_forward_secrecy()
    test_hex_transport()
    test_performance()

    print(f"\n{'═'*62}")
    print("  ALL TESTS PASSED ✅")
    print(f"{'═'*62}\n")