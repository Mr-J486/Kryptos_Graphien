import sys, os
import sympy
import random
from binascii import hexlify, unhexlify
from utils.EuclideanAlgorithm import GCD, EEA  # your GCD and EEA

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from Hashing.SHA256 import generate_hash 

def _hash_to_int(message: str) -> int:
    """Hash a message with your SHA-256 and return it as an integer."""
    hex_digest = generate_hash(message)   # uses utf-8 encoding
    return int(hex_digest, 16)

# ─────────────────────────────────────────────
#  Encryption / Decryption  (unchanged logic)
# ─────────────────────────────────────────────


def shared_secret(A,Xa,q): # Done by Alice
  # Shared Secret (Ya)
  Ya = pow(A,Xa,q)
  return Ya

def encrypt(m,Xb,A,q,Ya): # Done by Bob
  K = pow(Ya, Xb, q)
  c1 = pow(A,Xb,q) # c1 = Yb //Bob publlic key
  c2 = (m * K) % q # c2 = encrypted message
  return c1,c2

def decrypt(Xa,c1,c2,q): # Done by Alice
  K = pow(c1,Xa,q)
  dm = (c2 * EEA(K,q)) % q
  return dm
# ─────────────────────────────────────────────
#  ElGamal Digital Signature
# ─────────────────────────────────────────────
#
#  Parameters reuse the same (A, q, Xa, Ya) as encryption:
#    A   – generator  (g in standard notation)
#    q   – prime modulus
#    Xa  – Alice's private key  (signer)
#    Ya  – Alice's public key   (verifier)
#
#  Sign:
#    1. Pick random k  with  1 < k < q-1  and  gcd(k, q-1) = 1
#    2. r = A^k mod q
#    3. s = (H(m) - Xa * r) * k^-1  mod (q-1)
#    Signature = (r, s)
#
#  Verify:
#    Check:  A^H(m) ≡ Ya^r · r^s  (mod q)
# ─────────────────────────────────────────────

def _pick_k(q):
    """Pick a random k coprime to q-1."""
    phi = q - 1
    while True:
        k = random.randint(2, phi - 1)
        if GCD(k, phi) == 1:
            return k

def sign(message: str, Xa: int, A: int, q: int) -> tuple[int, int]:
    """
    Sign a message with Alice's private key.

    Parameters
    ----------
    message : plaintext string (unicode-safe)
    Xa      : Alice's private key
    A       : generator
    q       : prime modulus

    Returns
    -------
    (r, s)  : ElGamal signature pair
    """
    h   = _hash_to_int(message)
    phi = q - 1

    while True:
        k   = _pick_k(q)
        r   = pow(A, k, q)
        k_inv = EEA(k, phi)
        s   = (k_inv * (h - Xa * r)) % phi
        if s != 0:
            return r, s

def verify(message: str, signature: tuple[int, int], Ya: int, A: int, q: int) -> bool:
    """
    Verify an ElGamal signature.

    Parameters
    ----------
    message   : plaintext string (must match what was signed)
    signature : (r, s) pair returned by sign()
    Ya        : Alice's public key
    A         : generator
    q         : prime modulus

    Returns
    -------
    True if the signature is valid, False otherwise.
    """
    r, s = signature

    # Basic range checks – invalid signatures fail immediately
    if not (0 < r < q):
        return False
    if not (0 < s < q - 1):
        return False

    h = _hash_to_int(message)

    # A^H(m) mod q  ==  (Ya^r * r^s) mod q
    lhs = pow(A,  h, q)
    rhs = (pow(Ya, r, q) * pow(r, s, q)) % q
    return lhs == rhs

# ─────────────────────────────────────────────
#  Demo
# ─────────────────────────────────────────────

if __name__ == "__main__":
    input_message = "Hello, مرحبا 🔐"   # unicode-safe with your sha256 fix

    # ── Key / parameter setup ──────────────────
    input_bytes = input_message.encode("utf-8")
    m = int(input_bytes.hex(), 16)

    q  = sympy.randprime(m * 2, m * 4)
    A  = sympy.randprime(int(m / 2), m)
    Xa = random.randint(int(m / 2), m)   # Alice private key
    Xb = random.randint(int(m / 2), m)   # Bob   private key

    Ya = shared_secret(A, Xa, q)         # Alice public key

    print("=" * 60)
    print("  KEY SETUP")
    print("=" * 60)
    print(f"  Message         : {input_message}")
    print(f"  Message (int)   : {m}")
    print(f"  Prime q         : {q}")
    print(f"  Generator A     : {A}")
    print(f"  Alice priv  Xa  : {Xa}")
    print(f"  Bob   priv  Xb  : {Xb}")
    print(f"  Alice pub   Ya  : {Ya}")

    # ── Encryption / Decryption ────────────────
    print("\n" + "=" * 60)
    print("  ENCRYPTION")
    print("=" * 60)
    c1, c2 = encrypt(m, Xb, A, q, Ya)
    print(f"  c1 (Yb)         : {c1}")
    print(f"  c2              : {c2}")

    dm = decrypt(Xa, c1, c2, q)
    decoded_hex = format(dm, "x")
    # pad to even length before unhexlify
    if len(decoded_hex) % 2:
        decoded_hex = "0" + decoded_hex
    decoded_message = unhexlify(decoded_hex).decode("utf-8")

    print(f"\n  Decrypted int   : {dm}")
    print(f"  Decrypted msg   : {decoded_message}")
    print(f"  Match           : {decoded_message == input_message}")

    # ── Signing / Verification ─────────────────
    print("\n" + "=" * 60)
    print("  SIGNING  (Alice signs with Xa)")
    print("=" * 60)
    r, s = sign(input_message, Xa, A, q)
    print(f"  Signature r     : {r}")
    print(f"  Signature s     : {s}")

    print("\n" + "=" * 60)
    print("  VERIFICATION  (anyone verifies with Ya)")
    print("=" * 60)

    valid = verify(input_message, (r, s), Ya, A, q)
    print(f"  Original message  → valid={valid}")

    tampered = input_message + " [TAMPERED]"
    valid_tampered = verify(tampered, (r, s), Ya, A, q)
    print(f"  Tampered message  → valid={valid_tampered}")

    bad_sig = (r, (s + 1) % (q - 1))
    valid_bad_sig = verify(input_message, bad_sig, Ya, A, q)
    print(f"  Corrupted sig     → valid={valid_bad_sig}")
