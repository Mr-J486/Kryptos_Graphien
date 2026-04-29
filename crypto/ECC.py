"""
Elliptic Curve Cryptography (secp256k1)
=================================================
Implementation:
  - Point arithmetic on secp256k1 (y² = x³ + 7 mod p)
  - Key pair generation
  - ECDH key exchange
  - ECDSA signing and verification
"""

import secrets
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from Hashing.SHA256 import generate_hash as _sha256_hex


def _sha256_bytes(data: bytes) -> bytes:
    """Return the SHA-256 digest as raw bytes using the custom implementation."""
    return bytes.fromhex(_sha256_hex(data))

# ---------------------------------------------------------
#  secp256k1 Parameters
#------------------------
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A  = 0
_B  = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_G   = (_GX, _GY)  
_INF = None          


# -------------------------------------------------------
#  Internal Curve Arithmetics
# -------------------------------------
def _mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_add(P1, P2):
    if P1 is _INF:
        return P2
    if P2 is _INF:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % _P == 0:
        return _INF

    if P1 == P2:
        lam = (3 * x1 * x1 + _A) * _mod_inv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _mod_inv(x2 - x1, _P) % _P

    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k: int, point) -> tuple:
    result = _INF
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _hash_message(message: bytes) -> int:
    return int.from_bytes(_sha256_bytes(message), 'big') % _N


# -------------------------------------------------------------------------
#  generate_keypair, ecdsa_sign, ecdsa_verify, ecdh_shared_secret
# ----------------------------------------------------------------

def generate_keypair() -> tuple:
    private_key = secrets.randbelow(_N - 1) + 1
    public_key  = _scalar_mult(private_key, _G)
    return private_key, public_key


def is_valid_public_key(public_key: tuple) -> bool:
    if public_key is _INF:
        return False
    x, y = public_key
    if not (0 <= x < _P and 0 <= y < _P):
        return False
    if (y * y - x * x * x - _B) % _P != 0:
        return False
    if _scalar_mult(_N, public_key) is not _INF:
        return False
    return True


def ecdh_shared_secret(private_key: int, peer_public_key: tuple) -> bytes:
    shared_point = _scalar_mult(private_key, peer_public_key)
    if shared_point is _INF:
        raise ValueError("Shared point is the point at infinity - invalid key pair.")
    return _sha256_bytes(shared_point[0].to_bytes(32, 'big'))


def ecdsa_sign(message: bytes, private_key: int) -> tuple:
    z = _hash_message(message)
    while True:
        k = secrets.randbelow(_N - 1) + 1            # we can change randbelow for more secure
        point = _scalar_mult(k, _G)
        r = point[0] % _N
        if r == 0:
            continue
        s = _mod_inv(k, _N) * (z + r * private_key) % _N
        if s == 0:
            continue
        return (r, s)


def ecdsa_verify(message: bytes, signature: tuple, public_key: tuple) -> bool:
    r, s = signature
    if not (1 <= r < _N and 1 <= s < _N):
        return False

    z  = _hash_message(message)
    w  = _mod_inv(s, _N)
    u1 = z * w % _N
    u2 = r * w % _N

    point = _point_add(
        _scalar_mult(u1, _G),
        _scalar_mult(u2, public_key)
    )

    if point is _INF:
        return False

    return point[0] % _N == r


def private_key_to_hex(private_key: int) -> str:
    return hex(private_key)[2:].zfill(64)


def public_key_to_hex(public_key: tuple) -> str:
    x, y = public_key
    return f"04{hex(x)[2:].zfill(64)}{hex(y)[2:].zfill(64)}"


def public_key_to_compressed_hex(public_key: tuple) -> str:
    x, y = public_key
    prefix = "02" if y % 2 == 0 else "03"
    return f"{prefix}{hex(x)[2:].zfill(64)}"